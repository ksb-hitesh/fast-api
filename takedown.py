#!/usr/bin/env python3
"""Group NCII takedown URLs by abuse desk and write ready-to-send .eml drafts.

    python takedown.py urls.txt --name "Full Name" --email me@example.com

NEVER attach the video to these mails. URLs only.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import re
import socket
import ssl
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from urllib.parse import quote_plus, urlsplit

import dns.asyncresolver
import dns.exception
import httpx
from jinja2 import Environment, FileSystemLoader

UA = "Mozilla/5.0 (compatible; NCII-takedown-reporter/1.0)"

# Abuse desks that take a web form instead of mail. Matched against the RDAP
# network name, so a site hiding behind a CDN gets routed to the CDN's form
# rather than to a mailbox that will bounce.
CDN_FORMS = {
    "cloudflare": ("Cloudflare", "https://abuse.cloudflare.com/"),
    "fastly": ("Fastly", "https://www.fastly.com/about/abuse/"),
    "akamai": ("Akamai", "https://www.akamai.com/legal/compliance/report-abuse"),
    "sucuri": ("Sucuri", "https://sucuri.net/abuse/"),
    "ddos-guard": ("DDoS-Guard", "https://ddos-guard.net/en/report"),
    "stackpath": ("StackPath", "https://www.stackpath.com/legal/abuse/"),
}

SITE_SCRAPE_BUDGET = 25.0  # seconds, total, for the whole optional site scrape
SITE_PATHS = ["/dmca", "/abuse", "/legal", "/contact", "/takedown",
              "/content-removal", "/2257", "/terms", "/"]
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]*\w")
# Only mailboxes that plausibly reach a human who can remove content.
GOOD_LOCAL = re.compile(r"dmca|abuse|legal|support|admin|takedown|removal|compliance|contact", re.I)

SEARCH_ENGINES = """\
# De-index the URLs (do this first — it kills most of the real-world harm)

Google removes non-consensual explicit imagery from Search and, since 2026, accepts
many URLs in one submission:
  https://support.google.com/websearch/answer/16854698

Bing content removal:
  https://www.bing.com/webmasters/tools/contentremoval

Also file with StopNCII.org — it hashes the video ON YOUR DEVICE (the file never
leaves it) and partner platforms block re-uploads. This tool only kills the URLs you
already know about; StopNCII is what stops new ones appearing:
  https://stopncii.org/

## Paste this list into the bulk form

{urls}
"""


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
OG_IMAGE_RE = re.compile(
    r"""<meta[^>]+(?:property|name)=["']og:image["'][^>]+content=["']([^"']+)""", re.I)
OG_IMAGE_ALT_RE = re.compile(
    r"""<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']og:image["']""", re.I)


EVIDENCE_README = """\
# Evidence

Captured BEFORE the takedown notices went out, because a successful takedown
destroys the proof that the material was ever there. Police, a lawyer or a civil
claim will all ask for this.

  MANIFEST.csv    one row per URL: when it was captured, the page title, the
                  SHA-256 of the page, and its trusted timestamp
  evidence.json   the same plus full HTTP response headers
  *.html          the page markup exactly as served
  *.tsq / *.tsr   RFC-3161 timestamp request and signed response
  VERIFY.md       how to verify those, years from now

The timestamps are what make this hold up. A file on your own disk is easy to
dismiss; a third party's signature saying that exact file existed at that exact
time is not - and unlike a public archive, it publishes nothing.

The video itself is deliberately NOT downloaded here. You do not need more copies
of it, and no abuse desk will ask you for one.

Do not edit these files. If this ever goes to court, their being untouched is the
point. Keep a second copy somewhere else.
"""

DISCOVERY_HEADER = """\
# Finding copies you haven't found yet

A first pass usually finds well under half of what is out there. These links are
built from the page titles and thumbnails already on the pages you reported.

Work through them by hand. That is deliberate - these sites block automated
searching fast, and a banned IP costs you more than the clicking saves.

Yandex is consistently the best of the three at reverse image search on this kind
of content. Try it first even though the interface is awkward.

Add anything new you find to urls.txt and run the reporter again. Set up a Google
Alert on your own name and on any distinctive title text while you are at it.
"""

ESCALATE_INDIA = """\
# Escalation - the {deadline} deadline passed

Work down this list IN ORDER. File the portal complaint before you send the second
notices - those notices say a report is being made, and it should be true when they
land.

## 1. National Cyber Crime Reporting Portal (do this first)

  https://cybercrime.gov.in/

File under "Report Women/Child Related Crime" - it accepts anonymous reports and
does not require you to go to a police station first. Attach evidence/MANIFEST.csv
and the Wayback links. Keep the acknowledgement number.

## 2. Send the second notices in this folder

## 3. The platform's Grievance Officer

Every intermediary serving India must publish one under Rule 3(2) of the IT Rules
2021. It is usually at /grievance, /grievance-officer or in the privacy policy.
They are bound to acknowledge within 7 days and, for this category, to have acted
within two hours. Cite the missed deadline.

## 4. MeitY

Non-compliance with Rule 3(2)(b) costs the intermediary its Section 79 safe
harbour. Say so plainly, and copy MeitY on the correspondence.

## 5. Upstream and registry

If the host itself is unresponsive, go above it: the upstream network operator
shown in LOG.csv, then the domain registry above the registrar. Ask each to act on
their own AUP.

## 6. Get a lawyer involved

A notice on law-firm letterhead moves hosts that ignore individuals. If the
material is still up after the steps above, this is the step that works.

## URLs still live

{urls}
"""

ESCALATE_US = """\
# Escalation - the {deadline} deadline passed

Work down this list IN ORDER. File the FTC complaint before you send the second
notices - those notices say a complaint is being filed, and it should be true when
they land.

## 1. FTC complaint (do this first)

  https://reportfraud.ftc.gov/

Section 3 of the TAKE IT DOWN Act is FTC-enforceable and has been since 19 May
2026. Failure to remove within 48 hours of a valid request is exactly what the
complaint portal is for. Attach evidence/MANIFEST.csv.

## 2. Upstream and registry

Go above the host: the upstream network operator in LOG.csv, then the domain
registry above the registrar.

## 4. Cyber Civil Rights Initiative

  https://cybercivilrights.org/ - crisis helpline and direct platform contacts
  that individuals do not have.

## 5. Get a lawyer involved

A notice on law-firm letterhead moves hosts that ignore individuals.

## URLs still live

{urls}
"""


def jinja_env() -> Environment:
    return Environment(loader=FileSystemLoader(Path(__file__).parent),
                       autoescape=False, trim_blocks=True, lstrip_blocks=True)


@dataclass(frozen=True)
class Contact:
    kind: str      # hosting | registrar | site
    provider: str
    address: str   # email address, or form URL
    type: str      # "email" | "form"


# ---------------------------------------------------------------- lookups

async def abusix_emails(ip: str) -> list[str]:
    """Hosting abuse contact for an IP, via Abusix's free DNS ContactDB."""
    # ponytail: IPv4 only. Abusix keys IPv6 in nibble format; add if a site turns
    # out to be v6-only, which is vanishingly rare for tube sites.
    if ":" in ip:
        return []
    name = ".".join(reversed(ip.split("."))) + ".abuse-contacts.abusix.zone"
    try:
        answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=10)
    except (dns.exception.DNSException, ValueError):
        return []
    out = []
    for rr in answer:
        for part in b"".join(rr.strings).decode(errors="ignore").split(","):
            part = part.strip().lower()
            if "@" in part:
                out.append(part)
    return out


def _vcard(entity: dict, key: str) -> list[str]:
    values = []
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == key:
            v = item[3]
            values.extend(v if isinstance(v, list) else [v])
    return [v for v in values if isinstance(v, str) and v]


def _walk(entities) -> list[dict]:
    """RDAP nests entities inside entities; abuse contacts hide at any depth."""
    found = []
    for e in entities or []:
        if isinstance(e, dict):
            found.append(e)
            found.extend(_walk(e.get("entities")))
    return found


def _abuse_emails(data: dict) -> list[str]:
    out = []
    for e in _walk(data.get("entities")):
        if "abuse" in [r.lower() for r in e.get("roles") or []]:
            out.extend(a.lower() for a in _vcard(e, "email") if "@" in a)
    return out


async def rdap(client: httpx.AsyncClient, path: str) -> dict:
    try:
        r = await client.get(f"https://rdap.org/{path}")
        if r.status_code == 200:
            return r.json()
    except (httpx.HTTPError, ValueError):
        pass
    return {}


def is_cdn(net: str) -> tuple[str, str] | None:
    """(label, abuse-form URL) if this RDAP network name is a known CDN, else None.

    Single source of the CDN list, so hosting_contacts and origin.crt_candidates
    agree on what counts as "masked".
    """
    low = net.lower()
    for needle, (label, form) in CDN_FORMS.items():
        if needle in low:
            return label, form
    return None


async def hosting_contacts(client: httpx.AsyncClient, ip: str) -> list[Contact]:
    data = await rdap(client, f"ip/{ip}")
    net = (data.get("name") or "") + " " + str(data.get("remarks") or "")
    provider = data.get("name") or f"network holding {ip}"

    cdn = is_cdn(net)
    if cdn:
        # Behind a CDN: the real host is masked, so report to the CDN's form.
        return [Contact("hosting", f"{cdn[0]} (CDN — origin host is masked)", cdn[1], "form")]

    addrs = dict.fromkeys(_abuse_emails(data) + await abusix_emails(ip))
    return [Contact("hosting", provider, a, "email") for a in addrs]


async def registrar_contacts(client: httpx.AsyncClient, hostname: str) -> list[Contact]:
    """Walk up the labels until RDAP recognises a registered domain."""
    labels = hostname.removeprefix("www.").split(".")
    for i in range(len(labels) - 1):
        data = await rdap(client, "domain/" + ".".join(labels[i:]))
        if not data:
            continue
        provider = next(
            (n for e in _walk(data.get("entities"))
             if "registrar" in [r.lower() for r in e.get("roles") or []]
             for n in _vcard(e, "fn")),
            "the registrar",
        )
        return [Contact("registrar", provider, a, "email")
                for a in dict.fromkeys(_abuse_emails(data))]
    return []


async def site_contacts(client: httpx.AsyncClient, hostname: str) -> list[Contact]:
    """The site's own DMCA desk — usually the fastest route on tube sites."""
    found: dict[str, None] = {}
    for path in SITE_PATHS:
        try:
            r = await client.get(f"https://{hostname}{path}")
        except httpx.HTTPError:
            continue
        if r.status_code != 200:
            continue
        for addr in EMAIL_RE.findall(r.text):
            local, _, domain = addr.lower().partition("@")
            if GOOD_LOCAL.search(local) and hostname.removeprefix("www.") in domain:
                found[addr.lower()] = None
    return [Contact("site", f"{hostname} (site operator)", a, "email") for a in found]


async def bounded(coro, seconds: float) -> list:
    """Run an optional lookup under a hard time budget; give up quietly."""
    try:
        return await asyncio.wait_for(coro, timeout=seconds)
    except (asyncio.TimeoutError, httpx.HTTPError):
        return []


async def lookup_host(client: httpx.AsyncClient, hostname: str) -> tuple[str, list[Contact]]:
    # DoH, never the system resolver: a poisoned answer would point every abuse
    # lookup at the ISP's block server and address the notices to its host.
    ip, _ = await resolve(client, hostname)
    if not ip:
        return "", []
    host, reg, site = await asyncio.gather(
        hosting_contacts(client, ip),
        registrar_contacts(client, hostname),
        # Scraping the site's own /dmca page is nine requests, and against a blocked
        # host each one hangs to timeout - minutes per site. It is a bonus contact,
        # never a dependency, so it gets a hard cap. RDAP and Abusix are not blocked
        # and always run.
        bounded(site_contacts(client, hostname), SITE_SCRAPE_BUDGET),
    )
    return ip, host + reg + site


# ---------------------------------------------------------------- resolution

DOH_ENDPOINTS = [("Cloudflare", "https://cloudflare-dns.com/dns-query"),
                 ("Google", "https://dns.google/resolve")]

# Indian ISPs answer blocked domains with one shared block-server address, so the
# system resolver cannot be trusted to say who hosts anything. Every lookup that
# feeds an abuse contact goes through DoH; the system answer is kept only so the
# two can be compared and the poisoning reported.
_dns_cache: dict[str, tuple[str, str]] = {}


async def doh_resolve(client: httpx.AsyncClient, hostname: str) -> str:
    """First A record for hostname, resolved over DNS-over-HTTPS."""
    for _, endpoint in DOH_ENDPOINTS:
        try:
            r = await client.get(endpoint, params={"name": hostname, "type": "A"},
                                 headers={"accept": "application/dns-json"}, timeout=15)
            if r.status_code != 200:
                continue
            data = r.json()
        except (httpx.HTTPError, ValueError):
            continue
        if data.get("Status") not in (0, None):
            continue
        for ans in data.get("Answer") or []:
            if ans.get("type") == 1 and ans.get("data"):
                return ans["data"]
    return ""


def system_resolve(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return ""


async def resolve(client: httpx.AsyncClient, hostname: str) -> tuple[str, str]:
    """(real_ip, system_ip). Only the first is ever acted on."""
    if hostname not in _dns_cache:
        real, sys_ip = await asyncio.gather(
            doh_resolve(client, hostname),
            asyncio.to_thread(system_resolve, hostname))
        _dns_cache[hostname] = (real, sys_ip)
    return _dns_cache[hostname]


def poisoned_hosts(resolved: dict[str, tuple[str, str]]) -> dict[str, str]:
    """{hostname: block_server_ip} for hosts the local resolver lied about.

    Two signals, either is enough: the system answer disagrees with DoH, or several
    unrelated hostnames share one system answer (the block server's signature).
    """
    # Only the shared-address signal is used. "System answer differs from DoH" on its
    # own is far too noisy: any CDN or geo-balanced site legitimately hands different
    # resolvers different IPs, and flagging those would cry wolf on half the internet.
    shared: dict[str, list[str]] = {}
    for host, (_, sys_ip) in resolved.items():
        if sys_ip:
            shared.setdefault(sys_ip, []).append(host)
    return {host: sys_ip
            for host, (_, sys_ip) in resolved.items()
            if sys_ip and len(shared.get(sys_ip, [])) > 1}


def tls_reachable(ip: str, hostname: str, timeout: float = 8.0) -> str:
    """"" if the TLS handshake completes, else why it failed.

    A reset during the handshake - after TCP connected - is SNI-based blocking:
    the packet inspector saw the hostname in the ClientHello and killed it.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
    except OSError as e:
        return f"TCP failed ({type(e).__name__})"
    try:
        with ctx.wrap_socket(sock, server_hostname=hostname):
            return ""
    except ConnectionResetError:
        return "TLS reset - SNI blocked"
    except OSError as e:
        return f"TLS failed ({type(e).__name__})"
    finally:
        sock.close()


async def exit_ip(client: httpx.AsyncClient) -> tuple[str, str]:
    """(ip, country) of whatever this process actually goes out through."""
    try:
        r = await client.get("https://www.cloudflare.com/cdn-cgi/trace", timeout=15)
        fields = dict(ln.split("=", 1) for ln in r.text.splitlines() if "=" in ln)
        return fields.get("ip", ""), fields.get("loc", "")
    except (httpx.HTTPError, ValueError):
        return "", ""


async def preflight(client: httpx.AsyncClient, hosts: list[str]) -> dict:
    """Can this process actually reach these sites, and is DNS being lied to?"""
    ip, loc = await exit_ip(client)
    resolved = {}
    for h in hosts:
        resolved[h] = await resolve(client, h)
    poisoned = poisoned_hosts(resolved)

    blocked = {}
    for h, (real, _) in resolved.items():
        if not real:
            blocked[h] = "could not resolve"
            continue
        why = await asyncio.to_thread(tls_reachable, real, h)
        if why:
            blocked[h] = why
    # Poisoning is a warning, not a blocker: every lookup already uses the DoH answer,
    # so the abuse contacts are right either way. Only reachability decides whether
    # pages can be fetched and a removal check can be believed.
    return {"exit_ip": ip, "country": loc, "resolved": resolved,
            "poisoned": poisoned, "blocked": blocked, "tunnel_ok": not blocked}


def print_preflight(pf: dict) -> None:
    print(f"\nexit IP {pf['exit_ip'] or '?'} ({pf['country'] or '?'})")
    if pf["country"] == "IN":
        print("  -> going out through an Indian connection; expect ISP blocking")
    print()
    for host, (real, sys_ip) in sorted(pf["resolved"].items()):
        bits = [f"DoH={real or 'FAILED'}"]
        if host in pf["poisoned"]:
            bits.append(f"system={sys_ip} POISONED")
        elif sys_ip and sys_ip != real:
            bits.append(f"system={sys_ip}")
        blocked = pf["blocked"].get(host)
        bits.append(blocked or "reachable")
        print(f"  {host:38} {'  '.join(bits)}")

    if pf["poisoned"]:
        servers = sorted(set(pf["poisoned"].values()))
        print(f"\n  Your resolver is answering with {', '.join(servers)} for "
              f"{len(pf['poisoned'])} host(s).")
        print("  That is a block server, not the real host. Lookups use DoH instead,")
        print("  so the abuse contacts stay correct - this is a warning, not a failure.")

    if pf["tunnel_ok"]:
        print("\n  TUNNEL OK - pages can be fetched and checks can be trusted.")
    else:
        print("\n  NOT TUNNELLED - pages cannot be fetched from here, and a removal")
        print("  check would be meaningless: everything would look gone when it isn't.")
        print("\n  Bring the tunnel up inside WSL (a VPN running in Windows very likely")
        print("  does NOT cover this shell - WSL2 is on NAT networking here):")
        print("      sudo apt install wireguard")
        print("      sudo cp your.conf /etc/wireguard/wg0.conf")
        print("      sudo chmod 600 /etc/wireguard/wg0.conf")
        print("      sudo wg-quick up wg0")
        print("  then re-run this preflight.")


async def run_preflight(args) -> int:
    hosts = list(dict.fromkeys(urlsplit(u).hostname for u in read_urls(args.urls)
                               if urlsplit(u).hostname))
    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        pf = await preflight(client, hosts)
    print_preflight(pf)
    return 0 if pf["tunnel_ok"] else 1


# ---------------------------------------------------------------- status table

STATUS_FIELDS = ["url", "hostname", "first_seen_utc", "evidence_utc", "page_sha256",
                 "timestamp", "wayback", "reported_utc", "deadline_utc", "contacts",
                 "manual_contacts", "followup_utc",
                 "last_checked_utc", "http_status", "check_note", "removed_utc"]

# Phrases sites put up in place of a removed video. Deliberately conservative:
# a false "REMOVED" is worse than an unknown, because you stop chasing.
GONE_MARKERS = re.compile(
    r"video (?:has been |was )?(?:removed|deleted|taken down)|no longer available|"
    r"content (?:is )?(?:unavailable|removed)|page not found|this video does not exist|"
    r"has been removed|404 not found", re.I)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_status(out: Path) -> dict[str, dict]:
    f = out / "STATUS.csv"
    if not f.exists():
        return {}
    with f.open(newline="") as fh:
        return {r["url"]: {k: r.get(k, "") for k in STATUS_FIELDS}
                for r in csv.DictReader(fh)}


def update_status(out: Path, updates: dict[str, dict]) -> dict[str, dict]:
    """Merge this step's facts into the one table that survives between runs."""
    out.mkdir(parents=True, exist_ok=True)
    rows = load_status(out)
    for url, fields in updates.items():
        row = rows.setdefault(url, dict.fromkeys(STATUS_FIELDS, ""))
        if not row["url"]:
            row.update(url=url, hostname=urlsplit(url).hostname or "",
                       first_seen_utc=now_utc())
        row.update({k: v for k, v in fields.items() if v != ""})
    _write_status_csv(out, rows)
    return rows


def _write_status_csv(out: Path, rows: dict[str, dict]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "STATUS.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, STATUS_FIELDS)
        w.writeheader()
        w.writerows(rows[u] for u in sorted(rows))


def clear_status_fields(out: Path, urls, fields) -> dict[str, dict]:
    """Blank named columns on named rows.

    update_status() skips empty values on purpose, so it can only ever add facts.
    Undoing one - deleting a notice puts its URLs back to un-reported - needs this.
    """
    rows = load_status(out)
    for url in urls:
        if url in rows:
            rows[url].update(dict.fromkeys(fields, ""))
    _write_status_csv(out, rows)
    return rows


def drop_status_rows(out: Path, urls) -> dict[str, dict]:
    """Forget these URLs entirely - used when they leave the URL list."""
    rows = load_status(out)
    for url in urls:
        rows.pop(url, None)
    _write_status_csv(out, rows)
    return rows


def state_of(row: dict, now: datetime) -> str:
    """Derived, never stored - so it can't go stale against the facts."""
    if row.get("removed_utc"):
        return "REMOVED"
    # startswith, not ==: a note may carry who said so ("unclear (checked by hand)")
    # and the state must not quietly fall through to something milder.
    note = row.get("check_note") or ""
    if note.startswith("blocked"):
        return "BLOCKED"
    if note.startswith("unclear"):
        return "UNCLEAR"
    if row.get("followup_utc"):
        return "CHASED"
    if row.get("reported_utc"):
        due = row.get("deadline_utc")
        if due and now > datetime.fromisoformat(due):
            return "OVERDUE"
        return "REPORTED"
    if row.get("evidence_utc"):
        return "EVIDENCE"
    return "NEW"


def write_status_table(out: Path, rows: dict[str, dict]) -> None:
    now = datetime.now(timezone.utc)
    order = {"REMOVED": 0, "OVERDUE": 1, "CHASED": 2, "BLOCKED": 3, "UNCLEAR": 4,
             "REPORTED": 5, "EVIDENCE": 6, "NEW": 7}
    items = sorted(rows.values(), key=lambda r: (order.get(state_of(r, now), 9), r["url"]))

    counts: dict[str, int] = {}
    for r in items:
        counts[state_of(r, now)] = counts.get(state_of(r, now), 0) + 1

    md = ["# Progress\n",
          f"\nUpdated {now.isoformat(timespec='seconds')}\n",
          "\n" + "  ".join(f"**{k}** {v}" for k, v in sorted(counts.items())) + "\n",
          "\n| URL | State | Evidence | Reported | Deadline | Last check | Result |\n",
          "|---|---|---|---|---|---|---|\n"]
    for r in items:
        short = r["url"] if len(r["url"]) <= 58 else r["url"][:55] + "..."
        note = r["check_note"] or "-"
        if r["http_status"]:
            note = f"{note} ({r['http_status']})"
        md.append("| [{u}]({full}) | {st} | {ev} | {rp} | {dl} | {lc} | {note} |\n".format(
            u=short.replace("|", "%7C"), full=r["url"].replace("|", "%7C"),
            st=state_of(r, now),
            ev="yes" if r["evidence_utc"] else "-",
            rp=r["reported_utc"][:16].replace("T", " ") or "-",
            dl=r["deadline_utc"][:16].replace("T", " ") or "-",
            lc=r["last_checked_utc"][:16].replace("T", " ") or "-",
            note=note))
    md.append("\n## What the states mean\n\n"
              "- **NEW** - in the list, nothing done yet\n"
              "- **EVIDENCE** - snapshot and Wayback copy taken, not yet reported\n"
              "- **REPORTED** - notices sent, still inside the deadline\n"
              "- **OVERDUE** - deadline passed, no removal. Run --followup\n"
              "- **CHASED** - second notice sent. Work through followup/ESCALATE.md\n"
              "- **UNCLEAR** - the check could not tell. Open it yourself and look\n"
              "- **REMOVED** - confirmed gone by a check\n")
    (out / "STATUS.md").write_text("".join(md))


def print_status(rows: dict[str, dict]) -> None:
    now = datetime.now(timezone.utc)
    for r in sorted(rows.values(), key=lambda r: (state_of(r, now), r["url"])):
        short = r["url"] if len(r["url"]) <= 52 else r["url"][:49] + "..."
        print(f"  {state_of(r, now):9} {short:52} {r['check_note'] or ''}")


# ---------------------------------------------------------------- checking

async def check_one(client: httpx.AsyncClient, url: str, expect_sha: str) -> tuple[str, str]:
    """Is it actually gone? Returns (http_status, verdict).

    Anything genuinely ambiguous comes back "unclear" rather than "gone" - a false
    all-clear is the one error that makes you stop chasing something still online.
    """
    try:
        r = await client.get(url)
    except (httpx.ConnectError, httpx.ReadError) as e:
        if isinstance(e.__cause__, ConnectionResetError) or "reset" in str(e).lower():
            return "", "blocked"
        return "", f"unclear ({type(e).__name__})"
    except httpx.HTTPError as e:
        return "", f"unclear ({type(e).__name__})"

    code = r.status_code
    if code in (404, 410, 451):
        return str(code), "gone"
    if code in (401, 403, 429):
        # Could be the takedown, could be anti-bot or geo-blocking. Don't guess.
        return str(code), "unclear"
    if code != 200:
        return str(code), "unclear"

    body = r.content
    if expect_sha and hashlib.sha256(body).hexdigest() == expect_sha:
        # Byte-identical to what we captured: definitively still up.
        return "200", "still up (unchanged)"
    text = body.decode(r.encoding or "utf-8", errors="replace")
    if GONE_MARKERS.search(text):
        return "200", "gone"
    return "200", "still up (page changed)"


async def run_check(args) -> int:
    out = Path(args.out)
    rows = load_status(out)
    if not rows:
        sys.exit(f"no {out}/STATUS.csv yet - run --evidence or a reporting pass first")
    rows = {u: rows[u] for u in subset(rows, args)}

    sem = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        # A check from inside the block is worthless: every site looks gone. Establish
        # first whether this process can reach anything at all, and if it cannot,
        # record that fact instead of a removal.
        hosts = list(dict.fromkeys(r["hostname"] for r in rows.values() if r["hostname"]))
        pf = await preflight(client, hosts)
        if not pf["tunnel_ok"]:
            print_preflight(pf)
            blocked_hosts = set(pf["blocked"])
            update_status(out, {
                u: {"last_checked_utc": now_utc(), "check_note": "blocked", "http_status": ""}
                for u, r in rows.items() if r["hostname"] in blocked_hosts})
            write_status_table(out, load_status(out))
            skipped = sum(1 for r in rows.values() if r["hostname"] not in blocked_hosts)
            print(f"\nRecorded {len(blocked_hosts)} host(s) as BLOCKED. The check was "
                  f"aborted, so the other {skipped} URL(s) were not checked at all - "
                  f"their last result is stale, not current.")
            print("Nothing was marked removed: from here that cannot be established.")
            print("Blocking is intermittent, so a preflight that passed earlier may fail "
                  "now. Bring the tunnel up and run --check again.")
            return 1

        async def one(url, row):
            async with sem:
                code, verdict = await check_one(client, url, row.get("page_sha256", ""))
                return url, code, verdict
        checked = await asyncio.gather(*(one(u, r) for u, r in rows.items()))

    updates = {}
    for url, code, verdict in checked:
        note = "unclear" if verdict.startswith("unclear") else verdict
        fields = {"last_checked_utc": now_utc(), "http_status": code, "check_note": note}
        if verdict == "gone" and not rows[url].get("removed_utc"):
            fields["removed_utc"] = now_utc()
        updates[url] = fields

    rows = update_status(out, updates)
    write_status_table(out, rows)

    gone = sum(1 for _, _, v in checked if v == "gone")
    unclear = sum(1 for _, _, v in checked if v.startswith("unclear"))
    print(f"\nchecked {len(checked)} URL(s): {gone} gone, "
          f"{len(checked) - gone - unclear} still up, {unclear} unclear\n")
    print_status(rows)
    print(f"\nFull table: {out}/STATUS.md and {out}/STATUS.csv")
    if unclear:
        print("Open the 'unclear' ones yourself - the check could not tell, and it "
              "will not guess.")
    return 0


# ---------------------------------------------------------------- evidence

TSA_URL = "https://freetsa.org/tsr"
TSA_CERTS = {"tsa.crt": "https://freetsa.org/files/tsa.crt",
             "cacert.pem": "https://freetsa.org/files/cacert.pem"}


async def timestamp_file(client: httpx.AsyncClient, path: Path) -> str:
    """RFC-3161 trusted timestamp over the saved page. Returns the TSA name or "".

    Proves this exact file existed at this exact time, to a third party's signature,
    WITHOUT publishing anything. That matters here: pushing the page to a public
    archive would create another reachable copy of the material.
    """
    tsq, tsr = path.with_suffix(".tsq"), path.with_suffix(".tsr")
    try:
        proc = await asyncio.create_subprocess_exec(
            "openssl", "ts", "-query", "-data", str(path), "-sha512", "-cert",
            "-no_nonce", "-out", str(tsq),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await proc.communicate()
        if proc.returncode != 0:
            return ""
        r = await client.post(TSA_URL, content=tsq.read_bytes(),
                              headers={"Content-Type": "application/timestamp-query"},
                              timeout=60)
        if r.status_code != 200 or not r.content:
            return ""
        tsr.write_bytes(r.content)
        return "freetsa.org"
    except (OSError, httpx.HTTPError):
        return ""


async def fetch_tsa_certs(client: httpx.AsyncClient, ev: Path) -> None:
    """Keep the verification certs alongside the proof, so it stays checkable
    years from now without depending on freetsa.org still being up."""
    for name, url in TSA_CERTS.items():
        dest = ev / name
        if dest.exists():
            continue
        try:
            r = await client.get(url, timeout=30)
            if r.status_code == 200:
                dest.write_bytes(r.content)
        except httpx.HTTPError:
            pass


VERIFY_MD = """\
# Verifying the timestamps

Each captured page has a matching `.tsq` (the request) and `.tsr` (the signed
response from freetsa.org). Together they prove that exact file existed at that
exact time. Nothing about the page was published to produce this proof.

To verify any one of them:

    openssl ts -verify -in PAGE.tsr -queryfile PAGE.tsq \\
        -CAfile cacert.pem -untrusted tsa.crt

`Verification: OK` means the file is unmodified since the timestamp.

To read the timestamp itself:

    openssl ts -reply -in PAGE.tsr -text

Keep this whole folder together, unmodified, and keep a second copy elsewhere.
"""


async def capture_one(client: httpx.AsyncClient, url: str, ev: Path) -> dict:
    """Snapshot a page so proof survives the takedown that destroys it.

    Saves the page markup, headers and a hash. Never downloads the video itself -
    abuse desks don't need it and you should not be making more copies.
    """
    rec = {"url": url,
           "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    try:
        r = await client.get(url)
    except httpx.HTTPError as e:
        rec["error"] = f"{type(e).__name__}: {e}"
        return rec

    body = r.content
    name = slug(urlsplit(url).hostname + "-" + (urlsplit(url).path or "/"))
    (ev / f"{name}.html").write_bytes(body)

    text = body.decode(r.encoding or "utf-8", errors="replace")
    title = TITLE_RE.search(text)
    og = OG_IMAGE_RE.search(text) or OG_IMAGE_ALT_RE.search(text)
    rec.update(
        final_url=str(r.url), http_status=r.status_code, bytes=len(body),
        sha256_of_page=hashlib.sha256(body).hexdigest(),
        page_title=" ".join(title.group(1).split()) if title else "",
        thumbnail=og.group(1) if og else "",
        server=r.headers.get("server", ""), saved_as=f"{name}.html",
        response_headers=dict(r.headers),
    )
    return rec


async def archive_one(client: httpx.AsyncClient, url: str) -> str:
    """Ask the Wayback Machine to keep a dated third-party copy.

    A snapshot on your own disk is easy to dismiss; one held by an independent
    archive with a timestamp is much harder to argue with.
    """
    try:
        r = await client.get(f"https://web.archive.org/save/{url}", timeout=120)
    except httpx.HTTPError:
        return ""
    loc = r.headers.get("content-location", "")
    return f"https://web.archive.org{loc}" if loc else str(r.url)


async def capture_evidence(client, urls: list[str], out: Path,
                           archive: bool = False) -> list[dict]:
    ev = out / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(4)

    await fetch_tsa_certs(client, ev)

    async def one(u):
        async with sem:
            print(f"  capturing {u} ...", file=sys.stderr)
            rec = await capture_one(client, u, ev)
            if rec.get("saved_as"):
                rec["timestamp"] = await timestamp_file(client, ev / rec["saved_as"])
            # Public archiving is opt-in: it would put another reachable copy of the
            # material online, which is the opposite of what we are trying to achieve.
            if archive:
                rec["wayback"] = await archive_one(client, u)
            return rec

    records = list(await asyncio.gather(*(one(u) for u in urls)))
    (ev / "evidence.json").write_text(json.dumps(records, indent=2, sort_keys=True))

    with (ev / "MANIFEST.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["captured_at_utc", "url", "http_status", "page_title",
                    "sha256_of_page", "saved_as", "timestamp", "wayback", "error"])
        for r in records:
            w.writerow([r.get("captured_at_utc", ""), r["url"], r.get("http_status", ""),
                        r.get("page_title", ""), r.get("sha256_of_page", ""),
                        r.get("saved_as", ""), r.get("timestamp", ""),
                        r.get("wayback", ""), r.get("error", "")])

    (ev / "README.md").write_text(EVIDENCE_README)
    (ev / "VERIFY.md").write_text(VERIFY_MD)
    return records


# ---------------------------------------------------------------- discovery

def write_discovery(records: list[dict], out: Path) -> None:
    """Links to hunt for copies you have not found yet.

    Deliberately manual: these sites block automated scraping quickly, and getting
    your IP banned mid-search costs more than the clicking saves.
    """
    lines = [DISCOVERY_HEADER]
    for rec in records:
        title, thumb = rec.get("page_title", ""), rec.get("thumbnail", "")
        lines.append(f"\n## {rec['url']}\n")
        if title:
            q = quote_plus(f'"{title}"')
            lines.append(f"Page title: {title}\n")
            lines.append(f"- Search the exact title: https://www.google.com/search?q={q}\n")
            lines.append(f"- Same, on Bing: https://www.bing.com/search?q={q}\n")
            lines.append(f"- Same, on Yandex (indexes these sites more deeply): "
                         f"https://yandex.com/search/?text={q}\n")
        if thumb:
            t = quote_plus(thumb)
            lines.append(f"\nThumbnail found on the page: {thumb}\n")
            lines.append(f"- Reverse image search (Google Lens): "
                         f"https://lens.google.com/uploadbyurl?url={t}\n")
            lines.append(f"- Reverse image search (Yandex, best of the three for this): "
                         f"https://yandex.com/images/search?rpt=imageview&url={t}\n")
            lines.append(f"- Reverse image search (Bing): "
                         f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{t}\n")
        if not title and not thumb:
            lines.append("Nothing extractable from this page - search manually.\n")
    (out / "DISCOVERY.md").write_text("".join(lines))


# ---------------------------------------------------------------- follow-up

def overdue_rows(out: Path, hours: float) -> dict[str, dict]:
    """Contacts from a previous run whose deadline has passed."""
    log = out / "LOG.csv"
    if not log.exists():
        sys.exit(f"no {log} - run a reporting pass first, then follow up on it")
    now = datetime.now(timezone.utc)
    # Anything a check already confirmed gone must not be chased again - sending a
    # second notice about content that is already down destroys your credibility
    # with the one desk that actually acted.
    # A URL whose notice was deleted has had reported_utc cleared: it is no longer
    # reported, so there is nothing to follow up on either.
    done = {u for u, r in load_status(out).items()
            if r.get("removed_utc") or not r.get("reported_utc")}
    groups: dict[str, dict] = {}
    with log.open(newline="") as fh:
        for row in csv.DictReader(fh):
            if row["contact_type"] != "email" or not row["contact"]:
                continue
            if row["url"] in done:
                continue
            sent = datetime.fromisoformat(row["logged_at_utc"])
            age = (now - sent).total_seconds() / 3600
            if age < hours:
                continue
            g = groups.setdefault(row["contact"], {
                "provider": row["provider"] or row["contact"],
                "urls": [], "first_sent": sent, "age": age})
            g["first_sent"] = min(g["first_sent"], sent)
            g["age"] = max(g["age"], age)
            if row["url"] not in g["urls"]:
                g["urls"].append(row["url"])
    return groups


def apply_manual_contacts(results: list, rows: dict) -> list:
    """A hand-entered abuse address wins over whatever the lookups found.

    RDAP gives you the registrar and the network owner. Neither is reliably the desk
    that actually acts - a host's published abuse@ can bounce while a support address
    on their site answers in an hour. Only the person who got a reply knows that, so
    they get to say so, and what they say replaces the guess for that URL.
    """
    merged = []
    for url, contacts in results:
        manual = (rows.get(url) or {}).get("manual_contacts", "")
        picked = [a.strip() for a in manual.split(";") if a.strip()]
        if picked:
            contacts = [Contact("hosting", "entered by hand", a,
                                "form" if a.startswith("http") else "email")
                        for a in dict.fromkeys(picked)]
        merged.append((url, contacts))
    return merged


def write_followup(args, groups: dict, out: Path, hours: float) -> None:
    env = jinja_env()
    fu = out / "followup"
    fu.mkdir(parents=True, exist_ok=True)
    for n, (addr, g) in enumerate(sorted(groups.items()), 1):
        body = env.get_template("escalation.j2").render(
            provider=g["provider"], urls=g["urls"], name=args.name, email=args.email,
            india=args.india, elapsed=f"{g['age']:.0f} hours",
            first_sent=g["first_sent"].strftime("%d %B %Y %H:%M UTC"),
            date=datetime.now(timezone.utc).strftime("%d %B %Y"))
        msg = EmailMessage()
        msg["Subject"] = (f"SECOND NOTICE - NCII removal deadline missed - "
                          f"{len(g['urls'])} URL(s) still live")
        msg["To"] = addr
        msg["From"] = args.send_from or args.email
        msg["Date"] = formatdate(localtime=True)
        msg.set_content(body)
        (fu / f"{n:02d}-{slug(addr)}.eml").write_bytes(msg.as_bytes())

    (fu / "ESCALATE.md").write_text(
        (ESCALATE_INDIA if args.india else ESCALATE_US).format(
            deadline=f"{hours:g} hours",
            urls="\n".join(f"  {u}" for g in groups.values() for u in g["urls"])))


# ---------------------------------------------------------------- grouping

def group_contacts(results: list[tuple[str, list[Contact]]]) -> dict[str, dict]:
    """{address: {provider, type, kinds, urls}} — one entry per abuse desk.

    This is the whole point of the tool: one mail to a provider listing every URL
    it hosts, instead of one mail per URL.
    """
    groups: dict[str, dict] = {}
    for url, contacts in results:
        for c in contacts:
            g = groups.setdefault(
                c.address.lower(),
                {"provider": c.provider, "type": c.type, "kinds": set(), "urls": []},
            )
            g["kinds"].add(c.kind)
            if url not in g["urls"]:
                g["urls"].append(url)
    return groups


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", text.lower()).strip("-")[:60]


# ---------------------------------------------------------------- output

def deadline_text(args) -> str:
    # India's Rule 3(2)(b) window is two hours; the US TAKE IT DOWN duty is 48.
    return "2 hours" if args.india else "48 hours"


def render(env, args, provider: str, urls: list[str], role: str = "hosting") -> str:
    return env.get_template("notice.j2").render(
        provider=provider, urls=urls, role=role, name=args.name, email=args.email,
        postal=args.postal, self_recorded=args.self_recorded, eu=args.eu,
        india=args.india, deadline=deadline_text(args),
        date=datetime.now(timezone.utc).strftime("%d %B %Y"),
    )


def write_outputs(args, results, groups, ips: dict, out: Path) -> None:
    env = jinja_env()
    out.mkdir(parents=True, exist_ok=True)
    forms = []

    n = 0
    for addr, g in sorted(groups.items()):
        # A desk reached through several routes is addressed by the narrowest one
        # that fits: a registrar can only suspend a domain, not delete a file.
        role = ("registrar" if g["kinds"] == {"registrar"}
                else "site" if g["kinds"] == {"site"} else "hosting")
        body = render(env, args, g["provider"], g["urls"], role)
        subject = (f"URGENT - Non-consensual intimate imagery (NCII) takedown request "
                   f"- removal required within {deadline_text(args)} "
                   f"- {len(g['urls'])} URL(s)")
        if g["type"] == "form":
            forms.append((g["provider"], addr, g["urls"], subject, body))
            continue
        n += 1
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["To"] = addr
        msg["From"] = args.send_from or args.email
        msg["Date"] = formatdate(localtime=True)
        msg.set_content(body)
        (out / f"{n:02d}-{slug(addr)}.eml").write_bytes(msg.as_bytes())

    if forms:
        text = ["# Abuse desks that only take a web form\n",
                "No email possible — open each link, paste the body below.\n"]
        for provider, url, urls, subject, body in forms:
            text.append(f"\n## {provider}\n\nForm: {url}\n\nCovers {len(urls)} URL(s).\n"
                        f"\nSubject:\n\n    {subject}\n\nBody:\n\n```\n{body}\n```\n")
        (out / "FORMS.md").write_text("".join(text))

    all_urls = [u for u, _ in results]
    (out / "SEARCH-ENGINES.md").write_text(
        SEARCH_ENGINES.format(urls="\n".join(all_urls)))

    # Append, never truncate. --followup reads this file to find who missed a
    # deadline; a second reporting pass that wiped it would leave the escalation
    # chasing nobody. overdue_rows() takes min(first_sent)/max(age) per desk, so
    # older rows surviving makes it cite the true first contact date.
    log = out / "LOG.csv"
    fresh = not log.exists()
    with log.open("a", newline="") as fh:
        w = csv.writer(fh)
        if fresh:
            w.writerow(["logged_at_utc", "url", "hostname", "ip", "kind", "provider",
                        "contact", "contact_type"])
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for url, contacts in results:
            host = urlsplit(url).hostname or ""
            if not contacts:
                w.writerow([stamp, url, host, "", "NONE FOUND", "", "", ""])
            for c in contacts:
                w.writerow([stamp, url, host, ips.get(host, ""), c.kind,
                            c.provider, c.address, c.type])



# ---------------------------------------------------------------- main

def subset(urls, args) -> list:
    """Narrow a run to --only, when given. Anything not on the list is untouched."""
    only = getattr(args, "only", None)
    if not only:
        return list(urls)
    picked = [u for u in urls if u in set(only)]
    if not picked:
        sys.exit("none of the selected URLs are in the list")
    return picked


def read_urls(path: str) -> list[str]:
    lines = [ln.strip() for ln in Path(path).read_text().splitlines()]
    urls = list(dict.fromkeys(u for u in lines if u and not u.startswith("#")))
    if not urls:
        sys.exit(f"no URLs in {path} - add the page URLs, one per line")
    return urls


async def run_followup(args) -> int:
    out = Path(args.out)
    hours = 2.0 if args.india else 48.0
    groups = overdue_rows(out, hours)
    if not groups:
        print(f"nothing past the {hours:g}-hour deadline yet. Check again later.")
        return 0
    write_followup(args, groups, out, hours)
    chased = now_utc()
    rows = update_status(out, {u: {"followup_utc": chased}
                               for g in groups.values() for u in g["urls"]})
    write_status_table(out, rows)
    print(f"\n{len(groups)} desk(s) past the {hours:g}-hour deadline "
          f"-> second notices in {out}/followup/")
    for addr, g in sorted(groups.items()):
        print(f"  {addr:45} {len(g['urls'])} URL(s)  {g['age']:.0f}h ago")
    print(f"\nSend those, then work through {out}/followup/ESCALATE.md.")
    print(f"Progress table: {out}/STATUS.md")
    return 0


async def run_evidence(args) -> int:
    urls = read_urls(args.urls)
    out = Path(args.out)
    async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        hosts = list(dict.fromkeys(urlsplit(u).hostname for u in urls if urlsplit(u).hostname))
        pf = await preflight(client, hosts)
        if not pf["tunnel_ok"]:
            print_preflight(pf)
            print("\nNot capturing anything: the pages cannot be reached from here, so "
                  "the evidence would be empty or a block page.")
            return 1
        records = await capture_evidence(client, urls, out, archive=args.archive)
    write_discovery(records, out)
    rows = update_status(out, {
        r["url"]: {"evidence_utc": r.get("captured_at_utc", ""),
                   "page_sha256": r.get("sha256_of_page", ""),
                   "timestamp": r.get("timestamp", ""),
                   "wayback": r.get("wayback", "")}
        for r in records if not r.get("error")})
    write_status_table(out, rows)
    ok = [r for r in records if not r.get("error")]
    stamped = [r for r in ok if r.get("timestamp")]
    print(f"\ncaptured {len(ok)}/{len(urls)} page(s) -> {out}/evidence/")
    print(f"timestamped {len(stamped)}/{len(urls)} with freetsa.org (private proof)")
    if args.archive:
        print(f"archived {sum(1 for r in ok if r.get('wayback'))}/{len(urls)} publicly "
              f"to the Wayback Machine")
    for r in records:
        if r.get("error"):
            print(f"  !! could not capture {r['url']}: {r['error']}")
        elif not r.get("timestamp"):
            print(f"  !  no timestamp for {r['url']} - the page is still saved and "
                  f"hashed, but unsigned")
    print(f"\nLeads for finding more copies: {out}/DISCOVERY.md")
    print(f"Progress table: {out}/STATUS.md")
    print("Keep a second copy of the evidence folder somewhere else.")
    return 0


async def enrich_origins(results: list, out: Path, use_ytdlp: bool = False) -> list:
    """Find the file host behind each page and give it a notice of its own.

    The pages are shells; the video lives on a file host they embed, and several
    pages usually share one file. That host is the highest-leverage target - killing
    one file kills every page carrying it - and it is a different company from the
    site, so it needs its own notice.

    Returns `results` with one extra row per discovered embed: (embed URL, its abuse
    desk). The embed URL, not the page URL - a file host cannot remove a page on
    someone else's site, and a notice citing one it does not control gets binned.

    Reads the saved --evidence copy when there is one, so after step 1 this costs no
    fetch at all. With use_ytdlp, yt-dlp reads gated/anti-bot players the regex path
    cannot. Also collects crt.sh candidate origins into HOSTS.md - surfaced, never
    auto-mailed.
    """
    import origin  # lazy: origin imports from takedown, so this avoids an import cycle

    diags, found = [], {}
    async with httpx.AsyncClient(timeout=25, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        for url, contacts in list(results):
            diag, _ = await origin.origin_contacts(client, url, out, use_ytdlp)
            for h in diag["masked"]:
                diag.setdefault("candidates", {})[h] = \
                    await origin.crt_candidates(client, origin._domain_of(h))
            diags.append(diag)
            for entry in diag["delivery"]:
                for u in entry["urls"]:
                    if entry["contacts"]:
                        found.setdefault(u, list(entry["contacts"]))

    known = {u for u, _ in results}
    extra = [(u, cs) for u, cs in found.items() if u not in known]
    for u, cs in extra:
        print(f"  embed: {u} -> {', '.join(c.address for c in cs)}", file=sys.stderr)
    if diags:
        write_hosts(diags, out)
    return results + extra


def write_hosts(diags: list, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    lines = ["# Real delivery hosts and candidate origins\n",
             "\nWho actually serves each video, found by reading the stream URL out of "
             "the player. The delivery-host abuse desks below are already in your .eml "
             "drafts. The CANDIDATE ORIGINS are unverified leads - confirm before using.\n",
             "\n## Real delivery hosts\n"]
    for d in diags:
        lines.append(f"\n### {d['page']}\n")
        if not d["delivery"]:
            lines.append("\n(no stream URL could be read from the player)\n")
        for e in d["delivery"]:
            ptr = f" [{e['ptr']}]" if e["ptr"] else ""
            lines.append(f"\n- **{e['host']}** -> {e['ip'] or 'unresolved'}{ptr}"
                         f" — {e['provider'] or 'unknown network'}\n")
            for c in e["contacts"]:
                lines.append(f"    - abuse: {c.address}\n")
            if not e["contacts"] and e["host"] in d["masked"]:
                lines.append("    - still behind a CDN — see candidate origins below\n")

    cand = [(h, cs) for d in diags for h, cs in (d.get("candidates") or {}).items()]
    if cand:
        lines.append("\n## CANDIDATE ORIGINS (crt.sh — UNVERIFIED, confirm before using)\n")
        lines.append("\nEach IP holds a TLS certificate for a subdomain of the file host "
                     "and is NOT on a CDN, so one of them may be the origin. A cert match "
                     "is not proof: verify the IP actually serves the video before sending "
                     "a notice — a wrong host costs you credibility with the desks that act.\n")
        for h, cs in cand:
            lines.append(f"\n### {h}\n")
            if not cs:
                lines.append("\n(no non-CDN certificate hosts found)\n")
            for name, ip, prov in cs:
                lines.append(f"- {name} -> {ip}  ({prov or 'unknown network'})\n")
    (out / "HOSTS.md").write_text("".join(lines))


async def run(args) -> int:
    urls = subset(read_urls(args.urls), args)

    bad = [u for u in urls if not urlsplit(u).hostname]
    if bad:
        sys.exit("these lines have no hostname — full https://... URLs are required:\n  "
                 + "\n  ".join(bad))
    hosts = list(dict.fromkeys(urlsplit(u).hostname for u in urls))

    sem = asyncio.Semaphore(5)  # be polite to RDAP servers
    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        async def one(h):
            async with sem:
                print(f"  looking up {h} ...", file=sys.stderr)
                return h, await lookup_host(client, h)
        per_host = dict(await asyncio.gather(*(one(h) for h in hosts)))

    ips = {h: ip for h, (ip, _) in per_host.items()}
    # Own list per URL: origin enrichment appends to it without touching the shared
    # per-host list (many URLs can share one host).
    results = [(u, list(per_host[urlsplit(u).hostname][1])) for u in urls]

    out = Path(args.out)
    if getattr(args, "origin", True):
        results = await enrich_origins(results, out, getattr(args, "use_ytdlp", False))

    # After enrichment, before grouping: the notices are written from `groups`, not
    # from STATUS.csv, so an override that lands any later would never reach a draft.
    results = apply_manual_contacts(results, load_status(out))

    groups = group_contacts(results)
    write_outputs(args, results, groups, ips, out)

    sent = datetime.now(timezone.utc)
    due = sent + timedelta(hours=2 if args.india else 48)
    rows = update_status(out, {
        url: {"reported_utc": sent.isoformat(timespec="seconds"),
              "deadline_utc": due.isoformat(timespec="seconds"),
              "contacts": "; ".join(dict.fromkeys(c.address for c in contacts))
                          or "NONE FOUND"}
        for url, contacts in results})
    write_status_table(out, rows)

    emails = sum(1 for g in groups.values() if g["type"] == "email")
    print(f"\n{len(urls)} URL(s) across {len(hosts)} host(s) -> {emails} email draft(s) in {out}/")
    for addr, g in sorted(groups.items()):
        print(f"  [{g['type']:5}] {addr:45} {len(g['urls'])} URL(s)  ({', '.join(sorted(g['kinds']))})")

    orphans = [u for u, c in results if not c]
    if orphans:
        print("\n!! NO CONTACT FOUND — these need manual work, do not lose them:")
        for u in orphans:
            print(f"   {u}")
    print(f"\nProgress table: {out}/STATUS.md  (deadline {due.strftime('%H:%M UTC')})")
    print("\nRead every draft before sending. Never attach the video.")
    print(f"Start with {out}/SEARCH-ENGINES.md — de-indexing helps fastest.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("urls", nargs="?", help="file with one URL per line (# comments ok)")
    p.add_argument("--name", help="your full legal name, for the notice")
    p.add_argument("--email", help="contact address for replies")
    p.add_argument("--send-from", help="address to send from, if different from --email")
    p.add_argument("--postal", default="", help="postal address (DMCA notices require one)")
    p.add_argument("--self-recorded", action="store_true",
                   help="you filmed it yourself, so you own the copyright: adds the "
                        "DMCA 512(c) claim and its sworn statement. Leave OFF if someone "
                        "else recorded it.")
    p.add_argument("--eu", action="store_true", help="add a GDPR Art. 17 erasure demand")
    p.add_argument("--india", action="store_true",
                   help="lead with Rule 3(2)(b) of the IT Rules 2021 as amended in 2026: "
                        "2-hour removal on your complaint, and loss of Section 79 safe "
                        "harbour if they miss it. Much sharper than the US 48-hour duty.")
    p.add_argument("--evidence", action="store_true",
                   help="capture proof first: page markup, hashes and a Wayback copy per "
                        "URL, plus DISCOVERY.md. DO THIS BEFORE REPORTING - a successful "
                        "takedown destroys the evidence.")
    p.add_argument("--preflight", action="store_true",
                   help="can this shell actually reach the sites, and is DNS being "
                        "lied to? Run before every fetch-based step.")
    p.add_argument("--archive", action="store_true",
                   help="also push each URL to the Wayback Machine. OFF by default: it "
                        "creates a PUBLIC permanent copy of the material. The private "
                        "freetsa.org timestamp proves the same thing without publishing.")
    p.add_argument("--origin", action=argparse.BooleanOptionalAction, default=True,
                   help="on by default: read each page's player, find the file host it "
                        "embeds (iframe or stream URL), and write that host its own "
                        "notice citing the embed URL. Several pages usually share one "
                        "file, so this is the highest-leverage target. Reads the saved "
                        "--evidence copy when there is one, otherwise NEEDS THE TUNNEL. "
                        "Also writes out/HOSTS.md with candidate origins to confirm. "
                        "--no-origin skips it.")
    p.add_argument("--use-ytdlp", action="store_true",
                   help="with --origin, also use yt-dlp to read the stream URL out of "
                        "gated/anti-bot players (streamtape and the like). Needs yt-dlp "
                        "and curl_cffi installed; without them this flag is a no-op.")
    p.add_argument("--check", action="store_true",
                   help="re-fetch every URL in STATUS.csv and record whether it is "
                        "actually gone. Safe to re-run as often as you like.")
    p.add_argument("--followup", action="store_true",
                   help="read out/LOG.csv, find who blew the deadline, draft second "
                        "notices and an escalation checklist")
    p.add_argument("--out", default="out", help="output directory (default: out)")
    p.add_argument("--only", nargs="*", metavar="URL",
                   help="restrict this run to these URLs (reporting and --check). "
                        "Anything not listed keeps whatever status it already had.")
    args = p.parse_args()

    if args.evidence:
        if not args.urls:
            sys.exit("--evidence needs the URL file")
        return asyncio.run(run_evidence(args))
    if args.preflight:
        if not args.urls:
            sys.exit("--preflight needs the URL file")
        return asyncio.run(run_preflight(args))
    if args.check:
        return asyncio.run(run_check(args))
    if args.followup:
        if not (args.name and args.email):
            sys.exit("--followup needs --name and --email for the second notices")
        return asyncio.run(run_followup(args))

    missing = [f for f in ("urls", "name", "email") if not getattr(args, f)]
    if missing:
        sys.exit("missing required argument(s): " + ", ".join(missing))
    if args.self_recorded and not args.postal:
        sys.exit("--self-recorded sends a sworn DMCA notice, which must carry a postal "
                 "address. Pass --postal.")
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
