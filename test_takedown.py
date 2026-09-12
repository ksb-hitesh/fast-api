"""Offline checks for the two things that break silently. Run: python test_takedown.py"""

import csv
import tempfile
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import hashlib

import httpx

from takedown import (STATUS_FIELDS, Contact, check_one, clear_status_fields,
                      doh_resolve, drop_status_rows, group_contacts, jinja_env,
                      load_status, overdue_rows, poisoned_hosts, read_urls, render,
                      slug, state_of, subset, update_status, write_discovery)


def test_grouping():
    """One desk = one entry holding every URL it covers, across different sites."""
    ovh = Contact("hosting", "OVH", "abuse@ovh.net", "email")
    namecheap = Contact("registrar", "Namecheap", "abuse@namecheap.com", "email")
    cf = Contact("hosting", "Cloudflare (CDN)", "https://abuse.cloudflare.com/", "form")

    results = [
        ("https://sitea.com/1", [ovh, namecheap]),
        ("https://sitea.com/2", [ovh, namecheap]),
        ("https://sitea.com/3", [ovh, namecheap]),
        ("https://siteb.com/x", [cf, namecheap]),
        ("https://siteb.com/y", [cf, namecheap]),
    ]
    g = group_contacts(results)

    assert len(g) == 3, f"expected 3 desks, got {len(g)}"
    # the registrar serves both sites: all five URLs must land in ONE mail
    assert len(g["abuse@namecheap.com"]["urls"]) == 5
    assert len(g["abuse@ovh.net"]["urls"]) == 3
    assert g["abuse@ovh.net"]["urls"] == ["https://sitea.com/1", "https://sitea.com/2",
                                          "https://sitea.com/3"]
    # form and email desks stay in different buckets, or a form URL gets mailed
    assert g["https://abuse.cloudflare.com/"]["type"] == "form"
    assert g["abuse@ovh.net"]["type"] == "email"
    assert g["abuse@namecheap.com"]["kinds"] == {"registrar"}

    # a duplicate URL must not be listed twice in the same mail
    dupe = group_contacts([("https://a.com/1", [ovh]), ("https://a.com/1", [ovh])])
    assert dupe["abuse@ovh.net"]["urls"] == ["https://a.com/1"]
    print("grouping OK")


def _render(self_recorded, eu=False, role="hosting", india=False):
    env = jinja_env()
    args = Namespace(name="A Person", email="a@example.com", postal="1 Road, Town",
                     self_recorded=self_recorded, eu=eu, india=india)
    urls = ["https://site.com/a", "https://site.com/b", "https://other.com/c"]
    return render(env, args, "TestHost", urls, role), urls


def test_template():
    """The legal fork: never swear a copyright claim the reporter doesn't hold."""
    owned, urls = _render(self_recorded=True)
    not_owned, _ = _render(self_recorded=False)

    for body in (owned, not_owned):
        for u in urls:
            assert u in body, f"URL dropped from notice: {u}"
        assert "A Person" in body and "a@example.com" in body
        assert "48 HOURS" in body, "the 48-hour deadline is the main lever, keep it"
        assert "TAKE IT DOWN Act" in body
        assert "within 48 hours" in body

    assert "penalty of perjury" in owned
    assert "512(c)(3)" in owned
    # the whole point: no sworn copyright claim when someone else filmed it
    assert "penalty of perjury" not in not_owned
    assert "copyright" not in not_owned.lower()
    assert "512" not in not_owned

    assert "Article 17" not in owned
    assert "Article 17" in _render(self_recorded=True, eu=True)[0]
    print("template OK")


def test_role_wording():
    """A registrar can suspend a domain but cannot delete a file — ask each for
    what it can actually do, or the notice gets binned as misdirected."""
    host = _render(True, role="hosting")[0]
    reg = _render(True, role="registrar")[0]
    site = _render(True, role="site")[0]

    assert "infrastructure you operate" in host
    assert "domain you sponsor" in reg and "suspend the domain" in reg
    assert "infrastructure you operate" not in reg
    assert "published on your service" in site
    # ASCII only: em-dashes survive quoted-printable badly in old ticket systems
    for body in (host, reg, site):
        assert body.isascii(), "notice must stay ASCII"
    print("role wording OK")


def test_india():
    """India's 2-hour window is the sharpest lever available - it must be the
    deadline the notice actually asks for, not the US 48 hours."""
    body = _render(self_recorded=False, india=True)[0]
    assert "Rule 3(2)(b)" in body
    assert "WITHIN TWO HOURS" in body
    assert "within 2 hours" in body, "the ask must use the 2-hour deadline"
    assert "within 48 hours" not in body, "must not ask for the slower US deadline"
    assert "Section 79" in body, "losing safe harbour is the threat that makes them act"
    assert "cybercrime.gov.in" in body
    assert "Grievance Officer" in body
    assert body.isascii()

    # without the flag, none of it leaks in
    plain = _render(self_recorded=False, india=False)[0]
    assert "Rule 3(2)(b)" not in plain and "within 48 hours" in plain
    print("india OK")


def test_overdue():
    """Only genuinely overdue desks get a second notice, grouped per desk."""
    now = datetime.now(timezone.utc)
    rows = [
        # 5 hours ago -> overdue on the 2h clock, not on the 48h one
        (now - timedelta(hours=5), "https://a.com/1", "abuse@slow.net", "email"),
        (now - timedelta(hours=5), "https://a.com/2", "abuse@slow.net", "email"),
        # 10 minutes ago -> not overdue on either
        (now - timedelta(minutes=10), "https://a.com/3", "abuse@fast.net", "email"),
        # forms can't be emailed a second notice
        (now - timedelta(hours=5), "https://a.com/4", "https://form.example/", "form"),
    ]
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        with (out / "LOG.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["logged_at_utc", "url", "hostname", "ip", "kind", "provider",
                        "contact", "contact_type"])
            for ts, url, contact, kind in rows:
                w.writerow([ts.isoformat(timespec="seconds"), url, "a.com", "1.2.3.4",
                            "hosting", "Slow Inc", contact, kind])

        g2 = overdue_rows(out, 2.0)
        assert set(g2) == {"abuse@slow.net"}, f"got {set(g2)}"

        # a URL already confirmed removed must drop out of the chase
        update_status(out, {"https://a.com/1": {"removed_utc": now.isoformat()}})
        g3 = overdue_rows(out, 2.0)
        assert g3["abuse@slow.net"]["urls"] == ["https://a.com/2"], \
            "already-removed URLs must not be chased again"

        assert g2["abuse@slow.net"]["urls"] == ["https://a.com/1", "https://a.com/2"]
        assert 4.9 < g2["abuse@slow.net"]["age"] < 5.2

        assert overdue_rows(out, 48.0) == {}, "nothing is 48h old yet"
    print("overdue OK")


def test_discovery():
    """Discovery links must be built from whatever the page gave us, and must not
    silently drop a URL that gave us nothing."""
    records = [
        {"url": "https://site.com/v1", "page_title": "a b", "thumbnail": "https://i.co/1.jpg"},
        {"url": "https://site.com/v2", "page_title": "", "thumbnail": ""},
    ]
    with tempfile.TemporaryDirectory() as d:
        write_discovery(records, Path(d))
        md = (Path(d) / "DISCOVERY.md").read_text()
    assert "https://site.com/v1" in md and "https://site.com/v2" in md
    assert "yandex.com/images/search" in md and "lens.google.com" in md
    assert "%22a+b%22" in md, "title must be quoted and url-encoded"
    assert "search manually" in md, "a page with no leads must say so, not vanish"
    print("discovery OK")


def test_read_urls_collapses_duplicates():
    """A URL pasted twice must not produce two rows, two log lines and two notices."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "urls.txt"
        f.write_text("# a comment\nhttps://s.com/a\nhttps://s.com/b\nhttps://s.com/a\n")
        assert read_urls(str(f)) == ["https://s.com/a", "https://s.com/b"]


def test_subset_narrows_a_run_and_refuses_a_miss():
    urls = ["https://s.com/a", "https://s.com/b"]
    assert subset(urls, Namespace(only=None)) == urls
    assert subset(urls, Namespace()) == urls
    assert subset(urls, Namespace(only=["https://s.com/b"])) == ["https://s.com/b"]
    try:
        subset(urls, Namespace(only=["https://elsewhere.io/x"]))
    except SystemExit:
        pass
    else:
        raise AssertionError("a selection matching nothing must not run over everything")


def test_clearing_undoes_what_update_status_cannot():
    """update_status() skips empty values on purpose, so un-reporting needs its own
    path - otherwise a deleted notice leaves the URL looking reported forever."""
    with tempfile.TemporaryDirectory() as d:
        out, u, v = Path(d), "https://s.com/a", "https://s.com/b"
        update_status(out, {u: {"evidence_utc": "e", "reported_utc": "r",
                                "deadline_utc": "dl", "contacts": "abuse@h.com"},
                            v: {"reported_utc": "r"}})
        assert update_status(out, {u: {"reported_utc": ""}})[u]["reported_utc"] == "r"

        rows = clear_status_fields(out, [u], ["reported_utc", "deadline_utc", "contacts"])
        assert rows[u]["reported_utc"] == "" and rows[u]["contacts"] == ""
        assert rows[u]["evidence_utc"] == "e", "clearing must not touch the evidence"
        assert rows[v]["reported_utc"] == "r", "only the named rows change"
        assert state_of(rows[u], datetime.now(timezone.utc)) == "EVIDENCE"
        assert load_status(out)[u]["reported_utc"] == "", "must survive the round trip"

        assert set(drop_status_rows(out, [v])) == {u}
        assert set(load_status(out)) == {u}


def test_followup_skips_urls_whose_notice_was_deleted():
    """LOG.csv is append-only, so nothing else stops a deleted notice being chased."""
    with tempfile.TemporaryDirectory() as d:
        out, u = Path(d), "https://s.com/a"
        old = (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat(timespec="seconds")
        (out / "LOG.csv").write_text(
            "logged_at_utc,url,hostname,ip,kind,provider,contact,contact_type\n"
            f"{old},{u},s.com,1.2.3.4,hosting,H,abuse@h.com,email\n")
        update_status(out, {u: {"reported_utc": old}})
        assert overdue_rows(out, 2.0), "a genuinely overdue URL must be chased"
        clear_status_fields(out, [u], ["reported_utc"])
        assert not overdue_rows(out, 2.0)


def test_status_accumulates():
    """Each step adds its facts to the same row; nothing already recorded is lost."""
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        u = "https://site.com/v1"

        update_status(out, {u: {"evidence_utc": "2026-09-11T10:00:00+00:00",
                                "page_sha256": "abc", "wayback": "https://web.archive.org/x"}})
        rows = update_status(out, {u: {"reported_utc": "2026-09-11T11:00:00+00:00",
                                       "deadline_utc": "2026-09-11T13:00:00+00:00",
                                       "contacts": "abuse@a.net; abuse@b.net"}})

        r = rows[u]
        assert r["page_sha256"] == "abc", "reporting must not wipe the evidence hash"
        assert r["wayback"] == "https://web.archive.org/x"
        assert r["contacts"] == "abuse@a.net; abuse@b.net"
        assert r["hostname"] == "site.com" and r["first_seen_utc"]

        # blank values must never overwrite recorded facts
        rows = update_status(out, {u: {"page_sha256": "", "last_checked_utc": "2026-09-11T14:00:00+00:00"}})
        assert rows[u]["page_sha256"] == "abc"

        # survives a reload from disk
        assert load_status(out)[u]["contacts"] == "abuse@a.net; abuse@b.net"
    print("status accumulates OK")


def test_state_transitions():
    now = datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc)
    base = dict.fromkeys(STATUS_FIELDS, "")

    assert state_of(base, now) == "NEW"
    assert state_of({**base, "evidence_utc": "x"}, now) == "EVIDENCE"
    inside = {**base, "evidence_utc": "x", "reported_utc": "y",
              "deadline_utc": "2026-09-11T15:00:00+00:00"}
    assert state_of(inside, now) == "REPORTED"
    passed = {**inside, "deadline_utc": "2026-09-11T13:00:00+00:00"}
    assert state_of(passed, now) == "OVERDUE", "a blown deadline must surface itself"
    assert state_of({**passed, "followup_utc": "z"}, now) == "CHASED"
    # removal beats everything, including an overdue clock
    assert state_of({**passed, "removed_utc": "z"}, now) == "REMOVED"
    assert state_of({**passed, "check_note": "unclear"}, now) == "UNCLEAR"
    print("state transitions OK")


def test_check_verdicts():
    """A false 'gone' is the one error that makes you stop chasing. Ambiguity
    must come back as 'unclear', never as removed."""
    import asyncio

    class FakeResponse:
        def __init__(self, status, body=b"", encoding="utf-8"):
            self.status_code, self.content, self.encoding = status, body, encoding

    class FakeClient:
        def __init__(self, resp): self.resp = resp
        async def get(self, url, **kw):
            if isinstance(self.resp, Exception):
                raise self.resp
            return self.resp

    def verdict(resp, expect_sha=""):
        return asyncio.run(check_one(FakeClient(resp), "https://x/y", expect_sha))[1]

    assert verdict(FakeResponse(404)) == "gone"
    assert verdict(FakeResponse(410)) == "gone"
    assert verdict(FakeResponse(451)) == "gone"          # blocked for legal reasons
    assert verdict(FakeResponse(200, b"<h1>This video has been removed</h1>")) == "gone"

    page = b"<html>the video is right here, still playing</html>"
    sha = hashlib.sha256(page).hexdigest()
    assert verdict(FakeResponse(200, page), sha) == "still up (unchanged)"
    assert verdict(FakeResponse(200, b"<html>different but present</html>")) \
        == "still up (page changed)"

    # anti-bot and rate limiting are NOT removal
    for code in (401, 403, 429, 500, 503):
        assert verdict(FakeResponse(code)).startswith("unclear"), f"{code} must be unclear"
    assert verdict(httpx.ConnectError("boom")).startswith("unclear")
    print("check verdicts OK")


def test_doh_parsing():
    """Resolution must come from DoH, and fall through to the backup on a bad answer."""
    import asyncio

    class Resp:
        def __init__(self, payload, status=200):
            self.status_code, self._p = status, payload
        def json(self):
            if isinstance(self._p, Exception):
                raise self._p
            return self._p

    class Client:
        def __init__(self, *responses):
            self.responses, self.calls = list(responses), []
        async def get(self, url, **kw):
            self.calls.append(url)
            r = self.responses.pop(0)
            if isinstance(r, Exception):
                raise r
            return r

    ok = Resp({"Status": 0, "Answer": [{"type": 5, "data": "cname."},
                                       {"type": 1, "data": "1.2.3.4"}]})
    assert asyncio.run(doh_resolve(Client(ok), "x.com")) == "1.2.3.4"

    # NXDOMAIN from Cloudflare must fall through to Google, not be taken as truth
    c = Client(Resp({"Status": 3}), Resp({"Status": 0, "Answer": [{"type": 1, "data": "5.6.7.8"}]}))
    assert asyncio.run(doh_resolve(c, "x.com")) == "5.6.7.8"
    assert len(c.calls) == 2 and "dns.google" in c.calls[1]

    # both failing must return "" rather than something made up
    c = Client(httpx.ConnectError("no"), Resp({"Status": 2}))
    assert asyncio.run(doh_resolve(c, "x.com")) == ""
    print("DoH parsing OK")


def test_poison_detection():
    """The block-server signature is several unrelated hosts sharing one address.
    A CDN handing different resolvers different IPs must NOT be flagged."""
    poisoned = poisoned_hosts({
        "pornhub.com": ("66.254.114.41", "13.127.247.216"),
        "xvideos.com": ("89.222.127.13", "13.127.247.216"),
        "github.com": ("20.207.73.82", "20.207.73.82"),
    })
    assert set(poisoned) == {"pornhub.com", "xvideos.com"}, f"got {set(poisoned)}"
    assert poisoned["pornhub.com"] == "13.127.247.216"

    # a single site whose DoH and system answers differ is ordinary geo-DNS, not a block
    assert poisoned_hosts({"example.com": ("93.184.1.1", "23.55.2.2")}) == {}, \
        "must not cry wolf on multi-IP sites"
    # hosts that failed to resolve at all are not evidence of anything
    assert poisoned_hosts({"a.com": ("", ""), "b.com": ("", "")}) == {}
    print("poison detection OK")


def test_blocked_is_not_removed():
    """The one that matters: a page we cannot reach must never be recorded as
    removed. A false all-clear makes the user stop chasing something still online."""
    import asyncio

    class Resp:
        def __init__(self, status, body=b""):
            self.status_code, self.content, self.encoding = status, body, "utf-8"

    class Client:
        def __init__(self, exc): self.exc = exc
        async def get(self, url, **kw): raise self.exc

    reset = httpx.ConnectError("connection reset by peer")
    assert asyncio.run(check_one(Client(reset), "https://x/y", ""))[1] == "blocked"

    # 'blocked' is its own state - not REMOVED, not merely UNCLEAR
    now = datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc)
    base = dict.fromkeys(STATUS_FIELDS, "")
    assert state_of({**base, "check_note": "blocked"}, now) == "BLOCKED"
    assert state_of({**base, "check_note": "unclear"}, now) == "UNCLEAR"
    # and it must never be confused with a confirmed removal
    assert state_of({**base, "check_note": "blocked"}, now) != "REMOVED"

    # a blocked verdict must not carry a removal timestamp through the update path
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        rows = update_status(out, {"https://x/y": {"check_note": "blocked",
                                                   "last_checked_utc": now.isoformat()}})
        assert rows["https://x/y"]["removed_utc"] == "", \
            "a blocked check must leave removed_utc empty"
    print("blocked != removed OK")


def test_slug():
    assert slug("abuse@ovh.net") == "abuse-ovh.net"
    assert "/" not in slug("https://abuse.cloudflare.com/")
    print("slug OK")


if __name__ == "__main__":
    test_grouping()
    test_template()
    test_role_wording()
    test_india()
    test_overdue()
    test_discovery()
    test_status_accumulates()
    test_state_transitions()
    test_check_verdicts()
    test_doh_parsing()
    test_poison_detection()
    test_blocked_is_not_removed()
    test_slug()
    print("\nall checks passed")
