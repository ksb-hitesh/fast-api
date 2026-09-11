"""Offline checks for discover.py. Run: python test_discover.py

Nothing here touches the network. The four things that would break silently are
embed extraction (miss it and the file hosts never get a notice), the search key,
result parsing, and the tier rules that decide who receives a legal notice.
"""

import asyncio
import json
import tempfile
from pathlib import Path

import httpx

from discover import (LISTING_PATH, SKIP_PATH, boring, core_phrase, embed_id,
                      embeds, links_on, norm, overlap, searchable, seed, siblings,
                      tokens, transplant, verify, write_candidates, write_embeds)

PAGE = """<!doctype html><html><head>
<title>Beautiful Milf Blowjob Pussy Fingering By Husband HD - dropmms.vu</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=X">
<script src="https://unpkg.com/thing"></script>
</head><body>
<iframe data-litespeed-src="https://luluvdo.com/e/wllrgcrkn9zo" allowfullscreen></iframe>
<iframe src="https://ads.doubleclick.net/banner?id=9"></iframe>
<a href="/beautiful-milf-blowjob-pussy-fingering-by-husband-part-2/">Part 2</a>
<a href="/category/desi/">Desi</a>
<a href="https://dropmms.net/topic/383732-beautiful-sexy-indian-hot-milf/">mirror</a>
<a href="https://t.me/somechannel">telegram</a>
</body></html>"""


ESCAPED = """<html><body><textarea readonly>&lt;iframe src=&quot;https://masawatch.top/embed.php?id=72903&quot; width=&quot;640&quot;&gt;&lt;/iframe&gt;</textarea></body></html>"""


def test_embeds():
    """The one extraction that matters: the file the pages all point at."""
    got = embeds(PAGE, "https://dropmms.vu/beautiful-milf-blowjob-x/")
    assert got == {"https://luluvdo.com/e/wllrgcrkn9zo"}, got

    # Some sites only name the file inside an escaped "copy this embed code" box;
    # the live player is built by JS and there is no real iframe to find.
    got = embeds(ESCAPED, "https://lalamasa.mobi/x/")
    assert got == {"https://masawatch.top/embed.php?id=72903"}, got
    assert embed_id("https://luluvdo.com/e/wllrgcrkn9zo") == "wllrgcrkn9zo"
    assert embed_id("https://masawatch.top/embed.php?id=72903") == "72903"
    # A numeric or short id matches half the internet; never search on it.
    assert searchable("wllrgcrkn9zo") and not searchable("72903")
    print("embed extraction OK")


def test_boring_domains():
    assert boring("fonts.googleapis.com") and boring("connect.facebook.net")
    assert not boring("luluvdo.com") and not boring("dropmms.vu")
    sib = siblings(PAGE, "https://dropmms.vu/x/")
    assert "dropmms.net" in sib and "luluvdo.com" in sib, sib
    assert not sib & {"fonts.googleapis.com", "unpkg.com", "t.me"}, sib
    print("sibling harvest OK")


def test_link_classification():
    """Listings are kept, but as sources to mine - never checked as the video itself."""
    got = links_on(PAGE, "https://dropmms.vu/x/")
    assert "https://dropmms.vu/beautiful-milf-blowjob-pussy-fingering-by-husband-part-2/" in got
    assert not any(SKIP_PATH.search(u) for u in got), got
    assert not LISTING_PATH.search("/beautiful-milf-blowjob-by-husband-part-2/")
    for listing in ("/category/desi/", "/actor/beautiful-milf-blowjob/",
                    "/search/milf-blowjob/", "/tag/mallu/"):
        assert LISTING_PATH.search(listing), listing
    assert boring("fonts.googleapis.com"), "assets get dropped by the domain filter"
    print("link classification OK")


def test_core_phrase():
    """The farm retitles every copy; the shared run in the middle is the key."""
    slugs = [
        "/beautiful-sexy-indian-hot-milf-blowjob-pussy-fingering-by-husband/",
        "/beautiful-milf-blowjob-pussy-fingering-by-husband-hd-video/",
        "/beautiful-milf-blowjob-pussy-fingering-by-husband-watch/",
        "/sexy-indian-milf-blowjob-pussy-fingering-by-husband/",
        "/horny-mallu-wife-blowjob-pussy-fingering-by-hubby/",
    ]
    phrase = core_phrase(slugs)
    assert phrase == "milf blowjob pussy fingering by husband", phrase
    core = set(tokens(phrase))
    assert overlap("/beautiful-indian-milf-blowjob-pussy-fucking-by-husband/", core) >= 0.6
    assert overlap("/completely-unrelated-cooking-video/", core) < 0.6
    print("search key OK")


def test_norm():
    a = "https://www.mydesi2.net/beautiful-milf-1/"
    b = "https://mydesi2.net/beautiful-milf-1"
    assert norm(a) == norm(b), (norm(a), norm(b))
    print("url normalisation OK")


def _verify(body, url="https://new-site.tld/beautiful-milf-blowjob-pussy-fingering-by-husband/"):
    def handler(request):
        return httpx.Response(200, text=body)
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await verify(c, url, {"wllrgcrkn9zo"},
                                {("luluvdo.com", "wllrgcrkn9zo")}, {"luluvdo.com"},
                                set(tokens("milf blowjob pussy fingering by husband")))
    return asyncio.run(go())


def test_tiers():
    """A false positive here sends a sworn legal notice about someone else's video."""
    same = _verify(PAGE)
    assert same["tier"] == "CONFIRMED", same

    other_file = PAGE.replace("wllrgcrkn9zo", "zzzz99newfile")
    assert _verify(other_file)["tier"] == "LIKELY"

    # A mirror domain of the same file host, same file id: still the same file.
    mirror = PAGE.replace("luluvdo.com", "lulustream.com")
    assert _verify(mirror)["tier"] == "CONFIRMED", "file ids survive host changes"

    no_embed = PAGE.replace("<iframe data-litespeed-src=", "<span data-x=")
    assert _verify(no_embed)["tier"] == "MAYBE"

    unrelated = "<title>How to bake bread</title><p>flour</p>"
    assert _verify(unrelated, "https://baking.tld/sourdough-starter/") is None, \
        "an unrelated page must be dropped, never guessed at"
    print("tier rules OK")


def test_outputs_never_accept_guesses():
    """Only CONFIRMED reaches candidates.txt - LIKELY and MAYBE stay for review."""
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        embed_map = {"https://luluvdo.com/e/wllrgcrkn9zo":
                     ["https://a.tld/x/", "https://b.tld/y/"]}
        found = [
            {"url": "https://c.tld/sure/", "tier": "CONFIRMED", "why": "w",
             "title": "t", "embeds": [], "score": 1.0},
            {"url": "https://d.tld/guess/", "tier": "MAYBE", "why": "w",
             "title": "t", "embeds": [], "score": 0.7},
        ]
        write_embeds(embed_map, out)
        accept = write_candidates(found, embed_map, set(), "phrase", out)

        assert "https://luluvdo.com/e/wllrgcrkn9zo" in accept, "the file itself must ship"
        assert "https://c.tld/sure/" in accept
        assert "https://d.tld/guess/" not in accept, "a MAYBE must not be auto-accepted"
        txt = (out / "candidates.txt").read_text()
        assert "d.tld" not in txt
        md = (out / "CANDIDATES.md").read_text()
        assert "d.tld" in md, "but it must still be shown for review"
        assert "Embedded by 2 known page(s)" in (out / "EMBEDS.md").read_text()
    print("outputs OK")


def test_transplant():
    """The farm mirrors itself path-for-path, so a known slug is worth trying next door."""
    known = ["https://bengalisexvideos.center/beautiful-milf-x/", "https://a.tld/"]
    got = transplant(known, {"bengalisexvideos.vu", "maal69.cool"}, set())
    assert "https://bengalisexvideos.vu/beautiful-milf-x/" in got, got
    assert not any(u.endswith(".vu/") for u in got), "a bare / is not a page"

    # Already fetched once, never again - `seen` holds normalised host+path.
    done = {"bengalisexvideos.vu/beautiful-milf-x"}
    assert not any("bengalisexvideos.vu" in u for u in transplant(known, {"bengalisexvideos.vu"}, done))
    print("path transplant OK")


def test_unreachable_is_reported():
    """A host that never answered must not read as a host with nothing on it."""
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        write_candidates([], {}, set(), "phrase", out, ["mmsbee27.com", "desixx.net"])
        md = (out / "CANDIDATES.md").read_text()
        assert "Not searched" in md and "mmsbee27.com" in md, md
    print("coverage reporting OK")


def test_mirrors_reported():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        write_candidates([], {}, set(), "p", out, None, {"maal69.cool": {"maal69.int.in"}})
        md = (out / "CANDIDATES.md").read_text()
        assert "Mirror domains" in md and "maal69.cool -> maal69.int.in" in md, md
    print("mirror reporting OK")


def test_seed_reads_evidence():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        ev = out / "evidence"
        ev.mkdir(parents=True)
        (ev / "p.html").write_text(PAGE)
        (ev / "evidence.json").write_text(json.dumps(
            [{"url": "https://dropmms.vu/beautiful-milf-blowjob-pussy-fingering-by-husband-hd/",
              "saved_as": "p.html"}]))
        s = seed(out, None)
        assert "https://luluvdo.com/e/wllrgcrkn9zo" in s["embed_map"]
        assert "dropmms.net" in s["hosts"], s["hosts"]
        assert "blowjob" in s["core"], s["phrase"]
    print("seeding OK")


if __name__ == "__main__":
    test_embeds()
    test_boring_domains()
    test_link_classification()
    test_core_phrase()
    test_norm()
    test_tiers()
    test_outputs_never_accept_guesses()
    test_transplant()
    test_unreachable_is_reported()
    test_mirrors_reported()
    test_seed_reads_evidence()
    print("\nall checks passed")
