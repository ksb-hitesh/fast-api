#!/usr/bin/env python3
"""Offline checks for origin.py - no network, no database.

    python test_origin.py

A false host here means a sworn legal notice to the wrong company, so the extraction
and the crt.sh CDN filter both get a direct test.
"""

import asyncio
import re

import httpx

import takedown
from origin import (crt_candidates, origin_contacts, stream_urls, unpack)


# ---- a real Dean-Edwards packer, so unpack() is tested against genuine output ----

_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _enc(n: int, radix: int) -> str:
    if n == 0:
        return "0"
    out = ""
    while n:
        out = _B62[n % radix] + out
        n //= radix
    return out


def _pack(src: str, radix: int = 36) -> str:
    """Encode src the way p,a,c,k,e,d does: every word -> a base-radix token."""
    words = list(dict.fromkeys(re.findall(r"\b\w+\b", src)))
    idx = {w: i for i, w in enumerate(words)}
    payload = re.sub(r"\b\w+\b", lambda m: _enc(idx[m.group(0)], radix), src)
    syms = "|".join(words)
    return (f"eval(function(p,a,c,k,e,d){{...}}('{payload}',{radix},"
            f"{len(words)},'{syms}'.split('|'),0,{{}}))")


PLAYER_SRC = ('jwplayer("v").setup({sources:[{file:'
              '"https://s-del.luluvdo.com/hls/abc/master.m3u8"}]});')
PACKED_PAGE = ("<html><body><script>" + _pack(PLAYER_SRC, 36)
               + "</script></body></html>")


def test_unpack():
    out = unpack(_pack(PLAYER_SRC, 36))
    assert "master.m3u8" in out, out
    assert "s-del.luluvdo.com" in out, out
    # base-62 radix must decode too (players use it constantly)
    assert "master.m3u8" in unpack(_pack(PLAYER_SRC, 62))
    # not packed -> empty, so the caller falls back rather than guessing
    assert unpack("<html>nothing packed here</html>") == ""
    print("unpack OK")


def test_stream_urls():
    urls = stream_urls(PACKED_PAGE, "https://luluvdo.com/e/abc")
    assert urls == ["https://s-del.luluvdo.com/hls/abc/master.m3u8"], urls

    # plain (unpacked) config, escaped slashes, and a bare .m3u8
    plain = ('<script>var s = {file:"https:\\/\\/cdn.example.net\\/v\\/x.mp4"};'
             '</script> also https://a.edge.tld/live/y.m3u8 here')
    hosts = {re.sub(r"^https?://", "", u).split("/")[0] for u in
             stream_urls(plain, "https://page.tld/e/1")}
    assert hosts == {"cdn.example.net", "a.edge.tld"}, hosts

    # no media at all -> nothing, never a false host
    assert stream_urls("<html>just a page</html>", "https://p.tld/x") == []
    print("stream_urls OK")


def _run(coro):
    return asyncio.run(coro)


def test_origin_contacts():
    """The real delivery host resolves to a datacenter abuse desk, not the CDN form."""
    takedown._dns_cache.clear()
    takedown._dns_cache["s-del.luluvdo.com"] = ("203.0.113.10", "")

    async def _no_abusix(ip):        # keep it offline (abusix uses live DNS)
        return []
    orig_abusix = takedown.abusix_emails
    takedown.abusix_emails = _no_abusix

    rdap = {"name": "HETZNER-AS", "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["email", {}, "text", "abuse@hetzner.com"]]]}]}

    def handler(req):
        u = str(req.url)
        if "rdap.org" in u:
            return httpx.Response(200, json=rdap)
        if req.url.params.get("type") == "PTR":
            return httpx.Response(200, json={"Status": 0, "Answer": []})
        return httpx.Response(200, text=PACKED_PAGE)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await origin_contacts(c, "https://luluvdo.com/e/abc")
    try:
        diag, contacts = _run(go())
    finally:
        takedown.abusix_emails = orig_abusix

    assert [c.address for c in contacts] == ["abuse@hetzner.com"], contacts
    assert contacts[0].kind == "hosting" and contacts[0].type == "email"
    assert diag["delivery"][0]["host"] == "s-del.luluvdo.com"
    print("origin_contacts OK")


IFRAME_PAGE = """<html><body>
  <h1>video</h1>
  <iframe src="https://flash-files.com/e/dUlmhEq13yHMpbwu" allowfullscreen></iframe>
  <iframe src="https://www.google.com/recaptcha/anchor?k=x"></iframe>
</body></html>"""


def test_iframe_embed_is_found_and_attributed_to_its_own_host():
    """A page that iframes the player carries no media URL of its own, so the regex
    path sees nothing and the file host - the highest-leverage target - is missed."""
    takedown._dns_cache.clear()
    takedown._dns_cache["flash-files.com"] = ("203.0.113.44", "")

    async def _no_abusix(ip):
        return []
    orig_abusix = takedown.abusix_emails
    takedown.abusix_emails = _no_abusix

    rdap = {"name": "OVH", "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["email", {}, "text", "abuse@ovh.net"]]]}]}

    def handler(req):
        u = str(req.url)
        if "rdap.org" in u:
            return httpx.Response(200, json=rdap)
        if req.url.params.get("type") == "PTR":
            return httpx.Response(200, json={"Status": 0, "Answer": []})
        return httpx.Response(200, text=IFRAME_PAGE)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await origin_contacts(c, "https://shell-site.example/watch/123")
    try:
        diag, contacts = _run(go())
    finally:
        takedown.abusix_emails = orig_abusix

    assert stream_urls(IFRAME_PAGE, "https://shell-site.example/watch/123") == []
    assert [c.address for c in contacts] == ["abuse@ovh.net"], contacts
    entry = diag["delivery"][0]
    assert entry["host"] == "flash-files.com", diag
    # the URL a notice to that host has to cite - theirs, not the shell page's
    assert entry["urls"] == ["https://flash-files.com/e/dUlmhEq13yHMpbwu"], entry
    # recaptcha and friends must never become a takedown target
    assert [e["host"] for e in diag["delivery"]] == ["flash-files.com"], diag
    print("iframe embed OK")


def test_falls_back_cleanly():
    """No stream URL, or a dead fetch, must yield no contact - the CDN form stays."""
    def empty(req):
        return httpx.Response(200, text="<html>no player here</html>")

    def dead(req):
        raise httpx.ConnectError("boom")

    async def go(handler):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await origin_contacts(c, "https://luluvdo.com/e/x")

    diag, c1 = _run(go(empty))
    assert c1 == [] and diag["delivery"] == [], (c1, diag)
    _, c2 = _run(go(dead))
    assert c2 == [], c2
    print("clean fallback OK")


def test_ytdlp_merge():
    """When enabled, a media URL yt-dlp returns resolves to a real hosting contact,
    even if the page HTML itself gave nothing (gated/anti-bot player)."""
    import origin as O
    takedown._dns_cache.clear()
    takedown._dns_cache["cdn-node.serverius.net"] = ("185.0.0.1", "")

    async def _no_abusix(ip):
        return []
    orig_abusix = takedown.abusix_emails
    orig_yt = O.ytdlp_stream_urls
    takedown.abusix_emails = _no_abusix
    O.ytdlp_stream_urls = lambda u: ["https://cdn-node.serverius.net/v/x.mp4"]

    rdap = {"name": "SERVERIUS", "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [
            ["email", {}, "text", "abuse@serverius.net"]]]}]}

    def handler(req):
        if "rdap.org" in str(req.url):
            return httpx.Response(200, json=rdap)
        if req.url.params.get("type") == "PTR":
            return httpx.Response(200, json={"Status": 0, "Answer": []})
        return httpx.Response(200, text="<html>gated, no media here</html>")

    async def go(use_ytdlp):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await origin_contacts(c, "https://flash-files.com/x", use_ytdlp=use_ytdlp)
    try:
        _, off = _run(go(False))       # regex path alone finds nothing
        _, on = _run(go(True))         # yt-dlp supplies the delivery host
    finally:
        takedown.abusix_emails = orig_abusix
        O.ytdlp_stream_urls = orig_yt

    assert off == [], off
    assert [c.address for c in on] == ["abuse@serverius.net"], on
    print("ytdlp merge OK")


def test_crt_candidates():
    """Only NON-CDN cert hosts are surfaced as candidate origins."""
    takedown._dns_cache.clear()
    takedown._dns_cache["edge.luluvdo.com"] = ("104.21.0.1", "")     # cloudflare
    takedown._dns_cache["origin.luluvdo.com"] = ("203.0.113.20", "")  # hetzner

    crt = [{"name_value": "edge.luluvdo.com\n*.luluvdo.com"},
           {"name_value": "origin.luluvdo.com"}]
    rdap_by_ip = {"104.21.0.1": {"name": "CLOUDFLARENET"},
                  "203.0.113.20": {"name": "HETZNER-AS"}}

    def handler(req):
        u = str(req.url)
        if "crt.sh" in u:
            return httpx.Response(200, json=crt)
        for ip, body in rdap_by_ip.items():
            if u.endswith("/ip/" + ip):
                return httpx.Response(200, json=body)
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await crt_candidates(c, "luluvdo.com")

    out = _run(go())
    assert out == [("origin.luluvdo.com", "203.0.113.20", "HETZNER-AS")], out
    print("crt_candidates OK")


if __name__ == "__main__":
    test_unpack()
    test_stream_urls()
    test_origin_contacts()
    test_iframe_embed_is_found_and_attributed_to_its_own_host()
    test_falls_back_cleanly()
    test_ytdlp_merge()
    test_crt_candidates()
    print("\nall checks passed")
