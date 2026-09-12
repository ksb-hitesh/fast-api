#!/usr/bin/env python3
"""Find the datacenter that actually serves the video, not the CDN in front of it.

    python origin.py urls.txt        # diagnostic: real host + abuse desk per URL

File-host player pages (luluvdo.com/e/<id>) sit behind Cloudflare, so takedown.py's
RDAP lookup only ever reaches the CDN's abuse form. But the stream itself - the
.m3u8/.mp4 the player loads - is served from a SEPARATE delivery host that usually
runs on a bare datacenter IP (Hetzner, OVH, M247...). That host can pull the file in
minutes. This module reads the stream URL out of the player, resolves the delivery
host, and hands takedown.py a real hosting abuse contact.

Needs the tunnel (README Step 0): it fetches player pages. RDAP and DNS use DoH and
are not blocked, so those work either way. If --evidence already saved the player
page, that copy is reused and no tunnel is needed.
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from takedown import (DOH_ENDPOINTS, UA, Contact, hosting_contacts, is_cdn,
                      preflight, print_preflight, rdap, read_urls, resolve, slug)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().removeprefix("www.")


def _domain_of(host: str) -> str:
    # ponytail: last two labels. Wrong for multi-part TLDs (foo.int.in), but the
    # crt.sh %.<query> still returns the deeper subdomains, so it only over-broadens.
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ---------------------------------------------------------------- extraction

# The p,a,c,k,e,d tail: }('payload', radix, count, 'a|b|c'.split('|'), 0, {})
_PACKED_RE = re.compile(
    r"\}\s*\(\s*'(?P<payload>(?:\\.|[^'\\])*)'\s*,\s*(?P<radix>\d+)\s*,\s*"
    r"(?P<count>\d+)\s*,\s*'(?P<syms>(?:\\.|[^'\\])*)'\.split\('\|'\)", re.S)

_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _unbase(token: str, radix: int) -> int:
    """Decode a base-<radix> token the packer's encoder produced (radix up to 62)."""
    if radix <= 36:
        return int(token, radix)          # lowercase base-N, exactly toString(radix)
    alpha = _B62[:radix]
    n = 0
    for ch in token:
        n = n * radix + alpha.index(ch)   # ValueError if not a real token -> caller keeps word
    return n


def _unescape(s: str) -> str:
    # Only what matters for reading a URL out of a JS string literal.
    return (s.replace("\\/", "/").replace("\\'", "'")
             .replace('\\"', '"').replace("\\\\", "\\"))


def unpack(js: str, _depth: int = 0) -> str:
    """Decode Dean-Edwards p,a,c,k,e,d packed JS. "" if it is not packed.

    ponytail: standard single packer, unpacked at most twice for double-packing.
    Anything else returns "" and the caller falls back to crt.sh - never a wrong host.
    """
    m = _PACKED_RE.search(js)
    if not m:
        return ""
    payload = _unescape(m.group("payload"))
    radix = int(m.group("radix"))
    syms = _unescape(m.group("syms")).split("|")

    def sub(word: re.Match) -> str:
        tok = word.group(0)
        try:
            i = _unbase(tok, radix)
        except ValueError:
            return tok
        return syms[i] if i < len(syms) and syms[i] else tok

    out = re.sub(r"\b\w+\b", sub, payload)
    if _depth < 1 and _PACKED_RE.search(out):
        return unpack(out, _depth + 1) or out
    return out


_MEDIA_RE = re.compile(r"""https?://[^\s"'<>\\]+\.(?:m3u8|mp4)(?:[^\s"'<>\\]*)""", re.I)
_FILE_RE = re.compile(
    r"""["']?(?:file|src|source)["']?\s*[:=]\s*["']([^"']+\.(?:m3u8|mp4)[^"']*)["']""",
    re.I)


def stream_urls(text: str, page_url: str) -> list[str]:
    """Absolute .m3u8/.mp4 URLs the player will load, from raw markup and packed JS."""
    hay = _unescape(text + "\n" + (unpack(text) or ""))
    found = [m.group(0) for m in _MEDIA_RE.finditer(hay)]
    found += [m.group(1) for m in _FILE_RE.finditer(hay)]
    out, seen = [], set()
    for u in found:
        u = urljoin(page_url, u.strip())
        if u not in seen and host_of(u):
            seen.add(u)
            out.append(u)
    return out


# ---------------------------------------------------------------- resolution

async def ptr(client: httpx.AsyncClient, ip: str) -> str:
    """Reverse-DNS name for an IP over DoH. Readable provider hint, never load-bearing."""
    if not ip or ":" in ip:
        return ""
    name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    for _, endpoint in DOH_ENDPOINTS:
        try:
            r = await client.get(endpoint, params={"name": name, "type": "PTR"},
                                 headers={"accept": "application/dns-json"}, timeout=10)
            if r.status_code != 200:
                continue
            data = r.json()
        except (httpx.HTTPError, ValueError):
            continue
        for ans in data.get("Answer") or []:
            if ans.get("type") == 12 and ans.get("data"):
                return ans["data"].rstrip(".")
    return ""


def _evidence_html(page_url: str, out) -> str:
    """The saved --evidence copy of this page, if there is one. No tunnel needed then."""
    name = slug((urlsplit(page_url).hostname or "") + "-" + (urlsplit(page_url).path or "/"))
    p = Path(out) / "evidence" / f"{name}.html"
    try:
        return p.read_text(errors="replace") if p.exists() else ""
    except OSError:
        return ""


async def _fetch_player(client: httpx.AsyncClient, page_url: str, out) -> str:
    if out:
        cached = _evidence_html(page_url, out)
        if cached:
            return cached
    try:
        r = await client.get(page_url, timeout=25)
        return r.text if r.status_code == 200 else ""
    except httpx.HTTPError:
        return ""


async def origin_contacts(client: httpx.AsyncClient, page_url: str,
                          out=None) -> tuple[dict, list[Contact]]:
    """(diag, hosting Contacts) for the host actually serving page_url's video.

    Empty contacts on any failure - a wrong host is worse than no host, so this
    never guesses. Delivery hosts that are themselves CDN-masked are recorded in
    diag["masked"] for a crt.sh pass, not turned into a contact.
    """
    diag = {"page": page_url, "page_host": host_of(page_url),
            "delivery": [], "masked": []}
    text = await _fetch_player(client, page_url, out)
    if not text:
        return diag, []

    hosts = [h for h in dict.fromkeys(host_of(u) for u in stream_urls(text, page_url))
             if h and h != diag["page_host"]]
    contacts: list[Contact] = []
    for h in hosts:
        ip, _ = await resolve(client, h)
        entry = {"host": h, "ip": ip, "ptr": "", "provider": "", "contacts": []}
        diag["delivery"].append(entry)
        if not ip:
            continue
        entry["ptr"] = await ptr(client, ip)
        cs = await hosting_contacts(client, ip)
        emails = [c for c in cs if c.type == "email"]
        if emails:
            entry["provider"] = emails[0].provider
            entry["contacts"] = emails
            contacts.extend(emails)
        else:
            # Delivery host is ALSO behind a CDN - unmask via crt.sh, don't mail the CDN.
            diag["masked"].append(h)
            entry["provider"] = cs[0].provider if cs else ""
    return diag, contacts


async def crt_candidates(client: httpx.AsyncClient, domain: str,
                         cap: int = 25) -> list[tuple[str, str, str]]:
    """Non-CDN IPs holding a cert for a subdomain of `domain`, from crt.sh. UNVERIFIED.

    A cert match is a lead, not proof: one of these MAY be the origin behind the CDN.
    Returns [(subdomain, ip, rdap_provider)] - surfaced for the user to confirm.
    """
    try:
        r = await client.get("https://crt.sh/",
                             params={"q": f"%.{domain}", "output": "json"}, timeout=30)
        rows = r.json() if r.status_code == 200 else []
    except (httpx.HTTPError, ValueError):
        return []
    names = set()
    for row in rows:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and "@" not in n and "*" not in n:
                names.add(n)
    out: list[tuple[str, str, str]] = []
    seen_ip = set()
    for name in sorted(names)[:cap]:            # ponytail: cap the resolve fan-out
        ip, _ = await resolve(client, name)
        if not ip or ip in seen_ip:
            continue
        seen_ip.add(ip)
        data = await rdap(client, f"ip/{ip}")
        net = (data.get("name") or "") + " " + str(data.get("remarks") or "")
        if is_cdn(net):
            continue
        out.append((name, ip, data.get("name") or ""))
    return out


# ---------------------------------------------------------------- diagnostic CLI

def _print_diag(diag: dict) -> None:
    print(f"\n{diag['page']}")
    print(f"  page host : {diag['page_host']} (what takedown.py sees)")
    if not diag["delivery"]:
        print("  delivery  : no stream URL could be read from the player")
        return
    for e in diag["delivery"]:
        ptr = f"  [{e['ptr']}]" if e["ptr"] else ""
        print(f"  delivery  : {e['host']} -> {e['ip'] or 'unresolved'}{ptr}")
        print(f"              provider: {e['provider'] or 'unknown'}")
        for c in e["contacts"]:
            print(f"              abuse   : {c.address}  <- report HERE, acts fastest")
        if e["host"] in diag["masked"]:
            print("              still behind a CDN - see candidate origins below")


def _print_candidates(host: str, cands: list[tuple[str, str, str]]) -> None:
    print(f"\n  candidate origins for {host} (crt.sh - UNVERIFIED, confirm first):")
    if not cands:
        print("    none found off a CDN")
    for name, ip, prov in cands:
        print(f"    {name} -> {ip}  ({prov or 'unknown network'})")


async def _run(urls: list[str], out=None) -> int:
    hosts = list(dict.fromkeys(urlsplit(u).hostname for u in urls if urlsplit(u).hostname))
    async with httpx.AsyncClient(timeout=25, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        pf = await preflight(client, hosts)
        print_preflight(pf)
        if not pf["tunnel_ok"]:
            print("\nCannot fetch player pages from here. Bring the tunnel up "
                  "(README Step 0) and re-run, or run --evidence first so the pages "
                  "are cached.")
            return 1
        for u in urls:
            diag, _ = await origin_contacts(client, u, out)
            _print_diag(diag)
            for h in diag["masked"]:
                _print_candidates(h, await crt_candidates(client, _domain_of(h)))
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit("usage: python origin.py urls.txt [out-dir]")
    urls = read_urls(sys.argv[1])
    out = sys.argv[2] if len(sys.argv) > 2 else "out"
    return asyncio.run(_run(urls, out))


if __name__ == "__main__":
    raise SystemExit(main())
