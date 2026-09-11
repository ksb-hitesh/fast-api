#!/usr/bin/env python3
"""Find more copies of the same video, starting from the evidence already captured.

    python discover.py               # full run (needs the tunnel)
    python discover.py --offline     # stage 1 only, works from inside the block

The pages are WordPress shells; the video itself lives on a file host they embed.
Several pages share one embed, so the embed is both the highest-leverage takedown
target and a zero-false-positive search key: a page carrying that ID IS this video.

Writes out/EMBEDS.md, out/CANDIDATES.md and out/candidates.txt. Never touches
urls.txt - you read the candidates before anything gets a legal notice.
"""

from __future__ import annotations

import argparse
import asyncio
import html
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlsplit

import httpx

from takedown import TITLE_RE, UA, preflight, print_preflight, read_urls

# A browser UA for DuckDuckGo only; it serves nothing to an obvious bot. The abuse
# lookups keep takedown.py's honest UA - those desks should know who is asking.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# Domains that appear on every WordPress page ever and mean nothing here.
BORING = {
    "w.org", "schema.org", "gmpg.org", "ogp.me", "purl.org", "w3.org",
    "googleapis.com", "gstatic.com", "unpkg.com", "jsdelivr.net", "cloudflare.com",
    "cdnjs.com", "jquery.com", "bootstrapcdn.com", "rankmath.com", "yoast.com",
    "wordpress.org", "wp.me", "gravatar.com", "googletagmanager.com",
    "google-analytics.com", "facebook.com", "facebook.net", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "tumblr.com", "vk.com", "odnoklassniki.ru",
    "google.com", "pinterest.com", "whatsapp.com", "t.me", "telegram.me",
    "telegram.org", "youtube.com", "instagram.com", "creativecommons.org",
    "theporndude.com", "highrevenueformat.com", "wpadmngr.com", "wprediscache.com",
    "doubleclick.net", "adnxs.com",
}

IFRAME_RE = re.compile(r"<iframe\b[^>]*>", re.I)
SRC_RE = re.compile(r"""\b(?:data-litespeed-src|data-lazy-src|data-src|src)\s*=\s*["']([^"']+)""", re.I)
HREF_RE = re.compile(r"""\bhref\s*=\s*["']([^"']+)""", re.I)
URL_RE = re.compile(r"""https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})""", re.I)
UDDG_RE = re.compile(r"""uddg=([^"'&<>]+)""")

# Assets and boilerplate - never a page, never worth fetching.
SKIP_PATH = re.compile(
    r"/(wp-content|wp-admin|wp-includes|wp-json|comment|feed|privacy|dmca|abuse"
    r"|legal|contact|about|terms|2257|login|register|cdn-cgi)/"
    r"|\.(jpe?g|png|webp|gif|css|js|xml|ico|svg|mp4|m3u8|woff2?)$", re.I)

# Listing pages - not the video, but they list it. The farm tags each copy with the
# title as an "actor", so /actor/<title>/ is a ready-made index of the other copies.
LISTING_PATH = re.compile(
    r"/(category|tag|tags|author|actor|actress|star|model|search|label|genre|series"
    r"|studio|channel|playlist|page)/", re.I)

DDG = "https://html.duckduckgo.com/html/"
MATCH_FLOOR = 0.6          # token overlap needed to call a page a possible copy
HOST_DELAY = 1.0           # seconds between requests to the farm, per worker
MAX_FAILS = 2              # consecutive failures before a host is dropped
MAX_MINE = 3               # listing pages mined per host, before pagination loops


# ---------------------------------------------------------------- small helpers

def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().removeprefix("www.")


def boring(host: str) -> bool:
    h = host.lower().removeprefix("www.")
    return any(h == b or h.endswith("." + b) for b in BORING)


def norm(url: str) -> str:
    """Compare URLs without tripping over www., trailing slash or fragments."""
    sp = urlsplit(url.split("#")[0])
    path = sp.path.rstrip("/") or "/"
    q = f"?{sp.query}" if sp.query else ""
    return f"{host_of(url)}{path}{q}".lower()


def tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t and not t.isdigit()]


def overlap(text: str, core: set[str]) -> float:
    if not core:
        return 0.0
    return len(set(tokens(text)) & core) / len(core)


def embed_id(url: str) -> str:
    """The opaque bit that identifies the file: /e/<id> or ?id=<id>."""
    sp = urlsplit(url)
    qid = parse_qs(sp.query).get("id", [""])[0]
    segs = [s for s in sp.path.split("/") if s]
    return (qid or (segs[-1] if segs else "")).lower()


def searchable(eid: str) -> bool:
    """A short or all-numeric ID matches half the internet - don't search it."""
    return len(eid) >= 8 and not eid.isdigit()


# ---------------------------------------------------------------- extraction

def embeds(text: str, page_url: str) -> set[str]:
    """Off-site iframes on a page: the file host copies of the video.

    ponytail: same-host iframes are skipped - the page host already gets a notice,
    and self-hosted players are mostly ad frames. Revisit if a site turns out to
    serve its own player from a second domain you'd otherwise miss.
    """
    page_host = host_of(page_url)
    out = set()
    # Sites also print the iframe HTML-escaped inside a "copy this embed code" box,
    # and that copy names the file even when the live player is built by JS. Scan
    # both the raw markup and an unescaped pass over it.
    tags = IFRAME_RE.findall(text) + IFRAME_RE.findall(html.unescape(text))
    for tag in tags:
        m = SRC_RE.search(tag)
        if not m:
            continue
        u = urljoin(page_url, m.group(1).strip()).split("#")[0]
        h = host_of(u)
        if h and h != page_host and not boring(h) and embed_id(u):
            out.add(u)
    return out


def siblings(text: str, page_url: str) -> set[str]:
    """Other farm domains the page names itself - mirrors, CDNs, link partners."""
    page_host = host_of(page_url)
    return {h.lower().removeprefix("www.") for h in URL_RE.findall(text)
            if not boring(h) and h.lower().removeprefix("www.") != page_host}


def links_on(text: str, base: str) -> list[str]:
    out = []
    for href in HREF_RE.findall(text):
        u = urljoin(base, href.strip()).split("#")[0]
        sp = urlsplit(u)
        if sp.scheme not in ("http", "https") or not sp.hostname:
            continue
        if sp.path in ("", "/") or SKIP_PATH.search(sp.path):
            continue
        out.append(u)
    return out


def core_phrase(slugs: list[str], floor: int = 3) -> str:
    """Longest run of words shared by at least half the known pages.

    The farm retitles every copy slightly - "beautiful sexy indian hot milf ...",
    "... hd video", "horny mallu wife ..." - but a long run survives in the middle
    of most of them. That run is the fuzzy search key.
    """
    seqs = [t for t in (tokens(s) for s in slugs) if t]
    if not seqs:
        return ""
    need = max(2, (len(seqs) + 1) // 2)
    for n in range(10, floor - 1, -1):
        counts: Counter[str] = Counter()
        for s in seqs:
            counts.update({" ".join(s[i:i + n]) for i in range(len(s) - n + 1)})
        if counts:
            phrase, hits = counts.most_common(1)[0]
            if hits >= need:
                return phrase
    return " ".join(max(seqs, key=len)[:6])


# ---------------------------------------------------------------- seeding

def load_pages(out: Path) -> list[tuple[str, str]]:
    """(url, markup) for every page captured by --evidence."""
    ev = out / "evidence"
    index = ev / "evidence.json"
    if not index.exists():
        sys.exit(f"no {index} - run `python takedown.py urls.txt --evidence` first")
    pages = []
    for rec in json.loads(index.read_text()):
        f = ev / rec.get("saved_as", "")
        if rec.get("saved_as") and f.exists():
            pages.append((rec["url"], f.read_text(errors="replace")))
    return pages


def seed(out: Path, urls_file: str | None) -> dict:
    pages = load_pages(out)
    known = [u for u, _ in pages]
    if urls_file and Path(urls_file).exists():
        known += read_urls(urls_file)

    embed_map: dict[str, list[str]] = {}
    hosts: set[str] = set()
    related: list[str] = []
    for url, text in pages:
        for e in embeds(text, url):
            embed_map.setdefault(e, [])
            if url not in embed_map[e]:
                embed_map[e].append(url)
        hosts |= siblings(text, url)
        related += [u for u in links_on(text, url) if host_of(u) == host_of(url)]

    titles = [m.group(1) for _, t in pages if (m := TITLE_RE.search(t))]
    phrase = core_phrase([urlsplit(u).path for u in known] + titles)
    return {
        "known": known,
        "embed_map": embed_map,
        "hosts": {h for h in hosts | {host_of(u) for u in known} if h},
        "related": related,
        "phrase": phrase,
        "core": set(tokens(phrase)),
    }


# ---------------------------------------------------------------- searching

async def ddg(client: httpx.AsyncClient, query: str) -> list[str]:
    """Keyless DuckDuckGo. Results come back wrapped as uddg=<encoded url>."""
    try:
        r = await client.get(DDG, params={"q": query},
                             headers={"User-Agent": BROWSER_UA}, timeout=25)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    return [u for enc in UDDG_RE.findall(r.text)
            if (u := unquote(enc)).startswith("http")]


async def site_search(client: httpx.AsyncClient, host: str, phrase: str) -> list[str]:
    """The farm is all WordPress, so every host has /?s= - by far the best source.

    A redirect here is itself a finding: luluvdo.com lands on lulustream.com, and a
    mirror domain is a separate registrar and a separate takedown target.
    """
    r = await client.get(f"https://{host}/", params={"s": phrase}, timeout=20)
    if r.status_code != 200:
        raise httpx.HTTPError(f"HTTP {r.status_code}")
    final = host_of(str(r.url))
    return [u for u in links_on(r.text, str(r.url)) if host_of(u) in (host, final)]


def transplant(known: list[str], hosts: set[str], done: set[str]) -> list[str]:
    """Try each known page path on every sibling host.

    The farm mirrors itself path-for-path - bengalisexvideos.center serves the same
    slug as bengalisexvideos.vu - so a path that exists on one host very often
    exists on its mirrors too. Cheap: a miss is one 404.
    """
    paths = {urlsplit(u).path for u in known if urlsplit(u).path not in ("", "/")}
    return [f"https://{h}{path}" for h in sorted(hosts)
            for path in sorted(paths) if f"{h}{path.rstrip('/')}" not in done]


async def harvest(client: httpx.AsyncClient, url: str) -> list[str]:
    """Pull the links out of a listing page. Its whole job is to index the copies."""
    r = await client.get(url, timeout=25)
    if r.status_code != 200:
        raise httpx.HTTPError(f"HTTP {r.status_code}")
    return links_on(r.text, str(r.url))


async def verify(client: httpx.AsyncClient, url: str, known_ids: set[str],
                 known_pairs: set[tuple[str, str]], embed_hosts: set[str],
                 core: set[str]) -> dict | None:
    """Fetch the page and decide what it actually is. Search hits are never trusted.

    A false positive here means a sworn legal notice about someone else's content,
    so anything that does not clear the bar is dropped rather than guessed at.
    """
    try:
        r = await client.get(url, timeout=25)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    text = r.text
    found = embeds(text, str(r.url))
    ids = {embed_id(u) for u in found}
    m = TITLE_RE.search(text)
    title = " ".join(m.group(1).split()) if m else ""
    score = max(overlap(urlsplit(url).path, core), overlap(title, core))

    # Match on the file id alone when it is a long random token - file hosts run
    # mirror domains reusing the same ids. A short or numeric id could collide
    # across unrelated hosts, so that one has to match host and id together.
    hit = {i for i in ids & known_ids if searchable(i)}
    hit |= {embed_id(u) for u in found if (host_of(u), embed_id(u)) in known_pairs}
    if hit:
        why, tier = f"embeds the same file ({sorted(hit)[0]})", "CONFIRMED"
    elif {host_of(u) for u in found} & embed_hosts and score >= MATCH_FLOOR:
        why, tier = f"new file on a known host, {score:.0%} title match", "LIKELY"
    elif score >= MATCH_FLOOR:
        why, tier = f"{score:.0%} title match, no embed found", "MAYBE"
    else:
        return None
    return {"url": str(r.url), "requested": url, "tier": tier, "why": why,
            "title": title, "embeds": sorted(found), "score": score}


# ---------------------------------------------------------------- output

def write_embeds(embed_map: dict[str, list[str]], out: Path) -> None:
    lines = ["# The actual video files\n",
             "\nThe pages are shells. Each file below is embedded by every page listed\n"
             "under it, so removing one file kills all of them at once - and the file\n"
             "host is a single abuse desk, not one per site.\n",
             "\nThese URLs are in candidates.txt. Put them in urls.txt and run the\n"
             "reporter: it will find the file host's abuse contact like any other.\n"]
    for e, pages in sorted(embed_map.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines.append(f"\n## {e}\n\nhost: {host_of(e)}   file id: {embed_id(e)}\n"
                     f"\nEmbedded by {len(pages)} known page(s):\n\n")
        lines += [f"  {p}\n" for p in pages]
    (out / "EMBEDS.md").write_text("".join(lines))


def write_candidates(found: list[dict], embed_map: dict, known: set[str],
                     phrase: str, out: Path, unreachable: list[str] | None = None,
                     mirrors: dict[str, set[str]] | None = None) -> list[str]:
    order = {"CONFIRMED": 0, "LIKELY": 1, "MAYBE": 2}
    found.sort(key=lambda c: (order[c["tier"]], -c["score"], c["url"]))

    accept = [e for e in sorted(embed_map) if norm(e) not in known]
    accept += [c["url"] for c in found
               if c["tier"] == "CONFIRMED" and norm(c["url"]) not in known]
    (out / "candidates.txt").write_text("".join(f"{u}\n" for u in accept))

    counts = Counter(c["tier"] for c in found)
    md = ["# Copies you had not found yet\n",
          f"\nSearch key: `{phrase}`\n",
          "\n" + "  ".join(f"**{k}** {v}" for k, v in sorted(counts.items())) + "\n",
          "\n| URL | Tier | Why | Title |\n|---|---|---|---|\n"]
    for c in found:
        short = c["url"] if len(c["url"]) <= 60 else c["url"][:57] + "..."
        md.append("| [{s}]({u}) | {t} | {w} | {ti} |\n".format(
            s=short.replace("|", "%7C"), u=c["url"].replace("|", "%7C"),
            t=c["tier"], w=c["why"], ti=(c["title"] or "-")[:60].replace("|", " ")))
    md.append(
        "\n## What the tiers mean\n\n"
        "- **CONFIRMED** - the page embeds one of the exact files in EMBEDS.md. It is\n"
        "  this video; there is no judgement call. Already in `candidates.txt`.\n"
        "- **LIKELY** - a different file on a file host the farm already uses, with a\n"
        "  matching title. Almost always a re-encode. Open it and look.\n"
        "- **MAYBE** - the title matches but no embed was readable. Could be a copy,\n"
        "  could be a site that retitles everything the same way. Open it and look.\n"
        "\nOnly CONFIRMED rows are written to `candidates.txt`. Check them, then:\n\n"
        "    cat out/candidates.txt >> urls.txt\n"
        "\nNothing here touches `urls.txt` or `STATUS.csv` on its own - a notice about\n"
        "the wrong content costs you credibility with the desks that do act.\n"
        "\nStill worth doing by hand: the reverse-image links in `DISCOVERY.md`.\n"
        "Yandex Images finds copies no text search will.\n")
    if mirrors:
        md.append("\n## Mirror domains\n\nThese serve the same paths, so they are the "
                  "same operator behind a second domain - a second registrar to go "
                  "after, and a domain that keeps working when the first is suspended:"
                  "\n\n")
        md += [f"  {a} -> {', '.join(sorted(b))}\n" for a, b in sorted(mirrors.items())]
    if unreachable:
        md.append("\n## Not searched\n\nThese hosts never answered, so nothing was "
                  "searched on them. That is not the same as finding nothing there - "
                  "check the tunnel and re-run, or open them by hand:\n\n")
        md += [f"  {h}\n" for h in sorted(unreachable)]
    (out / "CANDIDATES.md").write_text("".join(md))
    return accept


# ---------------------------------------------------------------- main

async def hunt(args, s: dict, out: Path) -> int:
    known_ids = {embed_id(e) for e in s["embed_map"]}
    known_pairs = {(host_of(e), embed_id(e)) for e in s["embed_map"]}
    embed_hosts = {host_of(e) for e in s["embed_map"]}
    seen = {norm(u) for u in s["known"]}
    core, phrase = s["core"], s["phrase"]

    async with httpx.AsyncClient(timeout=25, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        pf = await preflight(client, sorted({host_of(u) for u in s["known"]})[:12])
        if not pf["tunnel_ok"]:
            print_preflight(pf)
            print("\nNot searching: from inside the block every search comes back empty,"
                  "\nand that would read as 'no more copies exist'. Bring the tunnel up.")
            print(f"\nStage 1 still ran - see {out}/EMBEDS.md.")
            return 1

        sem = asyncio.Semaphore(4)
        fails: Counter[str] = Counter()
        searched: set[str] = set()
        pool: list[str] = list(s["related"])

        async def polite(coro_fn, host: str):
            async with sem:
                try:
                    hits = await coro_fn()
                    fails[host] = 0
                    return hits
                except (httpx.HTTPError, asyncio.TimeoutError):
                    fails[host] += 1
                    return []
                finally:
                    await asyncio.sleep(HOST_DELAY)

        queries = [phrase] if phrase else []
        queries += [f'"{eid}"' for e in s["embed_map"] if searchable(eid := embed_id(e))]
        print(f"\nsearch key: {phrase!r}")
        print(f"{len(s['embed_map'])} file(s) behind {len(s['known'])} known URL(s)")
        for q in queries:
            print(f"  duckduckgo: {q}", file=sys.stderr)
            pool += await ddg(client, q)
            await asyncio.sleep(HOST_DELAY)

        found: list[dict] = []
        answered: set[str] = set()
        mined: Counter[str] = Counter()
        mirrors: dict[str, set[str]] = {}
        known_norm = {norm(u) for u in s["known"]}
        found_norm: set[str] = set()
        for rnd in range(1, args.rounds + 1):
            hosts = sorted(s["hosts"] - searched - {h for h in fails if fails[h] >= MAX_FAILS})
            if hosts and phrase:
                print(f"\nround {rnd}: searching {len(hosts)} site(s) for {phrase!r}",
                      file=sys.stderr)
                searched |= set(hosts)
                for h, hits in zip(hosts, await asyncio.gather(
                        *(polite(lambda h=h: site_search(client, h, phrase), h)
                          for h in hosts))):
                    pool += hits
                    if not fails[h]:
                        answered.add(h)
                # Say it out loud: a host that never answered was not searched, and
                # "no copies found there" would be the wrong thing to conclude.
                print(f"round {rnd}: {len(answered & set(hosts))}/{len(hosts)} "
                      f"site(s) answered", file=sys.stderr)
                # The farm mirrors itself path-for-path; try the known slugs on hosts
                # we have never fetched a page from.
                pool += transplant(s["known"], set(hosts) - {host_of(u) for u in s["known"]},
                                   seen)

            # Only fetch what could plausibly be it - the farm's search pages link
            # to hundreds of unrelated posts, and each fetch is a request they see.
            todo, listings = [], []
            for u in pool:
                n, path = norm(u), urlsplit(u).path
                if n in seen or boring(host_of(u)) or SKIP_PATH.search(path):
                    continue
                if overlap(path, core) < MATCH_FLOOR:
                    continue
                seen.add(n)
                if not LISTING_PATH.search(path):
                    todo.append(u)
                elif mined[host_of(u)] < MAX_MINE:
                    # Cap it: listings paginate into each other forever otherwise.
                    mined[host_of(u)] += 1
                    listings.append(u)
            pool = []
            if not todo and not listings:
                break

            if listings:
                # Don't check a listing page - mine it. Its links are the copies.
                print(f"round {rnd}: mining {len(listings)} listing page(s)",
                      file=sys.stderr)
                for hits in await asyncio.gather(
                        *(polite(lambda u=u: harvest(client, u), host_of(u))
                          for u in listings)):
                    pool += hits

            if todo:
                print(f"round {rnd}: checking {len(todo)} candidate page(s)",
                      file=sys.stderr)
                results = await asyncio.gather(
                    *(polite(lambda u=u: verify(client, u, known_ids, known_pairs,
                                                embed_hosts, core),
                             host_of(u)) for u in todo))
                for c in results:
                    if not c:
                        continue
                    asked, final = host_of(c["requested"]), host_of(c["url"])
                    if asked != final:
                        # The same slug served from a second domain: a mirror, and a
                        # separate registrar to go after.
                        mirrors.setdefault(asked, set()).add(final)
                    n = norm(c["url"])
                    if n in known_norm or n in found_norm:
                        continue      # a redirect landed back on something we have
                    found_norm.add(n)
                    found.append(c)
                    if c["tier"] != "CONFIRMED":
                        continue      # never let an unverified page seed a new file
                    s["hosts"].add(final)
                    for e in c["embeds"]:
                        s["embed_map"].setdefault(e, []).append(c["url"])
                        known_ids.add(embed_id(e))
                        known_pairs.add((host_of(e), embed_id(e)))

    unreachable = sorted(searched - answered)
    write_embeds(s["embed_map"], out)
    accept = write_candidates(found, s["embed_map"], known_norm, phrase, out,
                              unreachable, mirrors)
    counts = Counter(c["tier"] for c in found)
    print(f"\nfound {len(found)} new page(s): "
          f"{counts['CONFIRMED']} confirmed, {counts['LIKELY']} likely, "
          f"{counts['MAYBE']} maybe")
    for c in found[:15]:
        print(f"  {c['tier']:9} {c['url'][:70]}")
    if mirrors:
        print(f"\n{len(mirrors)} mirror domain(s) found:")
        for a, b in sorted(mirrors.items()):
            print(f"   {a} -> {', '.join(sorted(b))}")
    if unreachable:
        print(f"\n!! {len(unreachable)} host(s) never answered and were NOT searched - "
              f"that is not the same as nothing being there:")
        for h in unreachable[:10]:
            print(f"   {h}")
    print(f"\n{out}/CANDIDATES.md   ranked, with why each one matched")
    print(f"{out}/EMBEDS.md       the {len(s['embed_map'])} actual files behind them")
    print(f"{out}/candidates.txt  {len(accept)} URL(s) ready for urls.txt - read them first")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("urls", nargs="?", default="urls.txt",
                   help="the URL file you are already working from (default: urls.txt)")
    p.add_argument("--out", default="out", help="output directory (default: out)")
    p.add_argument("--rounds", type=int, default=2,
                   help="how many times a newly found site feeds the next search "
                        "(default: 2)")
    p.add_argument("--offline", action="store_true",
                   help="stage 1 only: pull the embedded file URLs out of the evidence "
                        "already on disk. No network, works from inside the ISP block.")
    args = p.parse_args()

    out = Path(args.out)
    s = seed(out, args.urls)
    if args.offline:
        write_embeds(s["embed_map"], out)
        accept = write_candidates([], s["embed_map"], {norm(u) for u in s["known"]},
                                  s["phrase"], out)
        print(f"\nsearch key: {s['phrase']!r}")
        print(f"{len(s['embed_map'])} file(s) behind {len(s['known'])} known URL(s), "
              f"{len(s['hosts'])} host(s) seen")
        print(f"\n{out}/EMBEDS.md       which pages share which file")
        print(f"{out}/candidates.txt  {len(accept)} file URL(s) to add to urls.txt")
        return 0
    return asyncio.run(hunt(args, s, out))


if __name__ == "__main__":
    raise SystemExit(main())
