"""Offline checks for the web layer. No network, no pytest.

    python test_app.py
"""
import asyncio
import contextlib
import email.message
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("APP_PASSWORD", "test-password")
os.environ.pop("MONGODB_URI", None)

import app          # noqa: E402
import storage      # noqa: E402
import takedown     # noqa: E402


def test_tee_captures_and_publishes():
    job = app.Job(step="x")
    seen = []
    app._subs.clear()
    q = asyncio.Queue(maxsize=10)
    app._subs.add(q)
    tee = app._LineTee(job)
    tee.write("looking up a.com ...\npartial")
    tee.flush()
    assert job.lines == ["looking up a.com ...", "partial"], job.lines
    while not q.empty():
        seen.append(q.get_nowait()["line"])
    assert seen == job.lines, seen
    app._subs.discard(q)


def test_ring_buffer_is_capped():
    job = app.Job(step="x")
    tee = app._LineTee(job)
    tee.write("".join(f"line {i}\n" for i in range(app.MAX_LINES + 500)))
    assert len(job.lines) == app.MAX_LINES
    assert job.lines[-1] == f"line {app.MAX_LINES + 499}"


def test_systemexit_is_caught_not_fatal():
    """read_urls/run_check/overdue_rows/load_pages all sys.exit() in library code.
    SystemExit is a BaseException - a bare `except Exception` would kill the worker."""
    async def boom(step, ns, offline):
        raise SystemExit("no URLs in urls.txt - add the page URLs, one per line")

    real, app._dispatch = app._dispatch, boom
    app._job = app.Job(step="report")
    try:
        asyncio.run(app._run_job("report", SimpleNamespace(), False))
    finally:
        app._dispatch = real
    assert app._job.state == "failed", app._job.state
    assert app._job.rc == 1
    assert "no URLs" in app._job.lines[-1], app._job.lines


def test_dns_cache_cleared_each_job():
    """A long-lived server would otherwise serve stale IPs forever, and a stale IP
    addresses the notice to the wrong abuse desk."""
    takedown._dns_cache["stale.example"] = ("1.2.3.4", "1.2.3.4")

    async def noop(step, ns, offline):
        return 0

    real, app._dispatch = app._dispatch, noop
    app._job = app.Job(step="preflight")
    try:
        asyncio.run(app._run_job("preflight", SimpleNamespace(), False))
    finally:
        app._dispatch = real
    assert "stale.example" not in takedown._dns_cache


def test_mailto_carries_the_address_and_subject_but_never_the_body():
    """A notice is far longer than any mail app's URL limit. A body in the mailto:
    came back silently cut off mid-sentence, which looks complete and is not - so
    the draft opens empty and the body is pasted from the Copy button instead."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "01-abuse-x.com.eml"
        from email.message import EmailMessage
        m = EmailMessage()
        m["Subject"] = "URGENT - NCII takedown"
        m["To"] = "abuse@x.com"
        m["From"] = "me@example.com"
        m.set_content("https://site.com/a\n" + ("word " * 2000))
        p.write_bytes(m.as_bytes())

        got = app._parse_eml(p, "notice")
        assert got["to"] == "abuse@x.com"
        assert got["body"].startswith("https://site.com/a")   # quoted-printable decoded
        assert got["urls"] == ["https://site.com/a"]
        assert got["mailto"] == ("mailto:abuse%40x.com"
                                 "?subject=URGENT%20-%20NCII%20takedown")
        assert "body=" not in got["mailto"]
        assert "truncated" not in got["mailto"]
        # the full text is still handed to the UI, for Copy and for reading
        assert got["body"].count("word") == 2000


def test_artifact_path_cannot_escape_out():
    for bad in ("../takedown.py", "../../etc/passwd", "evidence/../../app.py"):
        try:
            app._resolve(bad)
        except Exception as e:
            assert getattr(e, "status_code", None) == 404, bad
        else:
            raise AssertionError(f"traversal not blocked: {bad}")


def test_storage_key_traversal_blocked():
    assert storage._safe("out/STATUS.csv") is not None
    assert storage._safe("../../etc/passwd") is None


def test_saved_pages_are_download_only():
    """Rendering a captured page inline would display the material inside this app's
    origin and hand its scripts the session cookie."""
    for ext in (".html", ".htm", ".tsr", ".tsq", ".eml", ".crt", ".pem"):
        assert ext in app.DOWNLOAD_ONLY, ext


def test_build_ns_matches_what_takedown_expects():
    ns = app.build_ns({"name": "A B", "email": "a@b.com", "india": True,
                       "self_recorded": False, "postal": "", "rounds": 3})
    for attr in ("urls", "out", "name", "email", "send_from", "postal",
                 "self_recorded", "eu", "india", "archive", "rounds"):
        assert hasattr(ns, attr), attr
    assert takedown.deadline_text(ns) == "2 hours"
    ns.india = False
    assert takedown.deadline_text(ns) == "48 hours"
    # the real proof: it renders a notice
    body = takedown.render(takedown.jinja_env(), ns, "Example Host",
                           ["https://site.com/a"], "hosting")
    assert "A B" in body and "48 hours" in body


def test_todo_says_what_is_manual():
    with tempfile.TemporaryDirectory() as d:
        out, urls = app.OUT, app.URLS
        app.OUT, app.URLS = Path(d) / "out", Path(d) / "urls.txt"
        app.OUT.mkdir()
        try:
            app.URLS.write_text("https://site.com/a\n")
            t = app._todo({}, {}, app.DEFAULT_CONFIG)
            assert any(x["k"] == "evidence" for x in t), t
            rows = {"https://site.com/a": {"url": "https://site.com/a",
                                           "evidence_utc": "2026-01-01T00:00:00+00:00"}}
            t = app._todo(rows, {"https://site.com/a": "EVIDENCE"}, app.DEFAULT_CONFIG)
            keys = [x["k"] for x in t]
            assert "portal" in keys, keys          # cybercrime.gov.in is manual
            assert "ncii" in keys, keys            # StopNCII is always manual
            cfg = dict(app.DEFAULT_CONFIG, portal_ack="123")
            assert "portal" not in [x["k"] for x in app._todo(rows, {}, cfg)]
        finally:
            app.OUT, app.URLS = out, urls


@contextlib.contextmanager
def sandbox(urls_text=""):
    """Point app.OUT/URLS/CONFIG at a throwaway tree, and log a client in."""
    from fastapi.testclient import TestClient
    with tempfile.TemporaryDirectory() as d:
        saved = app.OUT, app.URLS, app.CONFIG
        app.OUT = Path(d) / "out"
        app.URLS = Path(d) / "urls.txt"
        app.CONFIG = Path(d) / "config.json"
        app.OUT.mkdir()
        app.URLS.write_text(urls_text)
        try:
            with TestClient(app.app) as c:
                c.post("/login", data={"password": "test-password"})
                yield c
        finally:
            app.OUT, app.URLS, app.CONFIG = saved


A, B = "https://site.com/a", "https://site.com/b"


def test_urls_edit_add_dedupes_against_active_and_excluded():
    with sandbox(f"{A}\n# {B}\n") as c:
        r = c.post("/api/urls/edit", json={"op": "add", "text": f"{A}\n{B}\nhttps://c.io/x"})
        assert r.status_code == 200 and r.json()["added"] == 1, r.json()
        assert app._read_urls_text().count(A) == 1
        # already-known-only input is refused rather than silently doing nothing
        assert c.post("/api/urls/edit", json={"op": "add", "text": A}).status_code == 400


def test_urls_edit_include_toggles_the_comment_prefix():
    with sandbox(f"{A}\n{B}\n") as c:
        assert app._url_count() == 2
        c.post("/api/urls/edit", json={"op": "include", "urls": [B], "on": False})
        assert app._list_urls() == {A: True, B: False}
        assert app._url_count() == 1                       # B drops out of every step
        assert takedown.read_urls(str(app.URLS)) == [A]
        c.post("/api/urls/edit", json={"op": "include", "urls": [B], "on": True})
        assert app._list_urls() == {A: True, B: True}


def test_urls_edit_remove_drops_the_line_and_the_status_row():
    with sandbox(f"{A}\n{B}\n") as c:
        takedown.update_status(app.OUT, {A: {"evidence_utc": "x"}, B: {"evidence_utc": "y"}})
        c.post("/api/urls/edit", json={"op": "remove", "urls": [B]})
        assert app._list_urls() == {A: True}
        assert set(takedown.load_status(app.OUT)) == {A}


def test_state_table_unions_the_list_with_the_tracker():
    with sandbox(f"{A}\n# {B}\n") as c:
        takedown.update_status(app.OUT, {"https://gone.io/x": {"evidence_utc": "z"}})
        t = {r["url"]: r for r in c.get("/api/state").json()["table"]}
        assert t[A]["state"] == "NEW" and t[A]["in_list"] is True   # no row yet
        assert t[B]["in_list"] is False                             # held back
        assert t["https://gone.io/x"]["in_list"] is None            # orphaned row


def test_run_passes_the_selection_through_as_only():
    seen = {}

    async def spy(step, ns, offline):
        seen["only"] = ns.only

    with sandbox(f"{A}\n{B}\n") as c:
        (app.OUT / "STATUS.csv").write_text("url\n")
        real, app._dispatch = app._dispatch, spy
        try:
            r = c.post("/api/run/check", json={"urls": [B, "not-a-url"]})
            assert r.status_code == 200, r.json()
            for _ in range(200):
                if "only" in seen:
                    break
                time.sleep(0.01)
        finally:
            app._dispatch = real
    assert seen["only"] == [B], seen


def test_manual_verdicts_write_the_same_fields_the_check_would():
    now = datetime.now(timezone.utc)
    with sandbox(f"{A}\n{B}\n") as c:
        takedown.update_status(app.OUT, {A: {"evidence_utc": "e"}, B: {"evidence_utc": "e"}})

        assert c.post("/api/urls/status",
                      json={"urls": [A, B], "verdict": "removed"}).status_code == 200
        rows = takedown.load_status(app.OUT)
        assert takedown.state_of(rows[A], now) == "REMOVED"
        assert rows[A]["removed_utc"] and rows[A]["last_checked_utc"]

        # a wrong call must be reversible: removed_utc has to actually blank out
        c.post("/api/urls/status", json={"urls": [A], "verdict": "up"})
        rows = takedown.load_status(app.OUT)
        assert rows[A]["removed_utc"] == ""
        assert takedown.state_of(rows[A], now) == "EVIDENCE"
        assert takedown.state_of(rows[B], now) == "REMOVED", "only the named URLs change"

        c.post("/api/urls/status", json={"urls": [A], "verdict": "unclear"})
        assert takedown.state_of(takedown.load_status(app.OUT)[A], now) == "UNCLEAR"

        c.post("/api/urls/status", json={"urls": [A], "verdict": "reported"})
        rows = takedown.load_status(app.OUT)
        assert rows[A]["reported_utc"] and rows[A]["deadline_utc"]

        assert c.post("/api/urls/status",
                      json={"urls": [A], "verdict": "nonsense"}).status_code == 400


def test_contact_override_is_validated_and_reaches_the_draft():
    """The notices are built from live lookups, not from STATUS.csv - an override
    that only landed in the CSV would show in the UI and change no draft at all."""
    with sandbox(f"{A}\n") as c:
        r = c.post("/api/urls/contacts", json={"urls": [A], "contacts": "not an address"})
        assert r.status_code == 400, r.json()

        r = c.post("/api/urls/contacts",
                   json={"urls": [A],
                         "contacts": "abuse@real.com\nhttps://form.example/report"})
        assert r.status_code == 200, r.json()
        assert takedown.load_status(app.OUT)[A]["manual_contacts"] == \
            "abuse@real.com; https://form.example/report"

        found = [(A, [takedown.Contact("registrar", "Wrong Registrar",
                                       "abuse@wrong.com", "email")])]
        merged = takedown.apply_manual_contacts(found, takedown.load_status(app.OUT))
        addrs = [x.address for x in merged[0][1]]
        assert addrs == ["abuse@real.com", "https://form.example/report"], addrs
        groups = takedown.group_contacts(merged)
        assert "abuse@wrong.com" not in groups, "the override must replace the guess"
        assert groups["https://form.example/report"]["type"] == "form"

        # the point of overriding a batch: same address -> still one notice, not N
        c.post("/api/urls/contacts",
               json={"urls": [A, B], "contacts": "abuse@real.com"})
        two = takedown.apply_manual_contacts(
            [(A, []), (B, [takedown.Contact("site", "S", "abuse@b.com", "email")])],
            takedown.load_status(app.OUT))
        g = takedown.group_contacts(two)
        assert list(g) == ["abuse@real.com"], g
        assert g["abuse@real.com"]["urls"] == [A, B]

        # clearing falls back to the lookups
        c.post("/api/urls/contacts", json={"urls": [A, B], "contacts": ""})
        assert takedown.load_status(app.OUT)[A]["manual_contacts"] == ""
        back = takedown.apply_manual_contacts(found, takedown.load_status(app.OUT))
        assert [x.address for x in back[0][1]] == ["abuse@wrong.com"]


def test_deleting_a_notice_puts_its_urls_back_to_unreported():
    with sandbox(f"{A}\n") as c:
        takedown.update_status(app.OUT, {A: {"reported_utc": "2026-01-01T00:00:00+00:00",
                                             "deadline_utc": "2026-01-01T02:00:00+00:00",
                                             "evidence_utc": "2026-01-01T00:00:00+00:00",
                                             "contacts": "abuse@h.com"}})
        msg = email.message.EmailMessage()
        msg["Subject"], msg["To"], msg["From"] = "s", "abuse@h.com", "me@x.com"
        msg.set_content(f"URLS\n\n{A}\n")
        (app.OUT / "01-abuse-h.com.eml").write_bytes(msg.as_bytes())
        app.save_config(dict(app.DEFAULT_CONFIG, sent=["01-abuse-h.com.eml"]))

        r = c.post("/api/notices/delete", json={"file": "01-abuse-h.com.eml"})
        assert r.status_code == 200 and r.json()["unreported"] == 1, r.json()
        assert not (app.OUT / "01-abuse-h.com.eml").exists()
        assert app.load_config()["sent"] == []
        row = takedown.load_status(app.OUT)[A]
        assert row["reported_utc"] == "" and row["contacts"] == ""
        # back to EVIDENCE, so the next reporting pass picks it up again
        assert takedown.state_of(row, datetime.now(timezone.utc)) == "EVIDENCE"


def test_deleting_a_form_notice_cuts_it_out_of_forms_md():
    with sandbox(f"{A}\n") as c:
        takedown.update_status(app.OUT, {A: {"reported_utc": "2026-01-01T00:00:00+00:00"}})
        (app.OUT / "FORMS.md").write_text(
            "# Abuse desks that only take a web form\n\n"
            f"## Cloudflare\n\nForm: https://abuse.cloudflare.com/\n\nCovers 1 URL(s).\n"
            f"\nSubject:\n\n    subj\n\nBody:\n\n```\nURLS\n{A}\n```\n")
        r = c.post("/api/notices/delete",
                   json={"form_url": "https://abuse.cloudflare.com/"})
        assert r.status_code == 200 and r.json()["unreported"] == 1, r.json()
        assert not (app.OUT / "FORMS.md").exists()      # it was the only section
        assert takedown.load_status(app.OUT)[A]["reported_utc"] == ""
        assert c.post("/api/notices/delete",
                      json={"form_url": "https://abuse.cloudflare.com/"}).status_code == 404


def test_mongo_roundtrip_preserves_evidence_bytes():
    """The whole point of the Mongo layer. If a .tsr does not come back byte-identical,
    `openssl ts -verify` prints FAILED and the evidence is worthless."""
    try:
        import mongomock
    except ImportError:
        print("  skip  test_mongo_roundtrip (mongomock not installed)")
        return

    real_root, real_coll = storage.ROOT, storage._coll
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
        coll = mongomock.MongoClient()["takedown"]["files"]
        storage._coll = lambda: coll

        # a real timestamp proof if this repo has one, else synthetic binary
        real_tsr = next(Path("out/evidence").glob("*.tsr"), None)
        blob = real_tsr.read_bytes() if real_tsr else bytes(range(256)) * 40

        storage.ROOT = Path(src)
        ev = Path(src) / "out" / "evidence"
        ev.mkdir(parents=True)
        (ev / "page.tsr").write_bytes(blob)
        (ev / "page.html").write_bytes(b"<html>\xff\xfe binary-ish</html>")
        (Path(src) / "out" / "STATUS.csv").write_text("url,state\nhttps://a.com/x,NEW\n")
        (Path(src) / "urls.txt").write_text("https://a.com/x\n")

        assert storage.push() == 4, "expected 4 files uploaded"
        assert storage.push() == 0, "unchanged files must not re-upload"

        storage.ROOT = Path(dst)
        assert storage.pull() == 4
        out = Path(dst)
        assert (out / "out/evidence/page.tsr").read_bytes() == blob, "tsr corrupted"
        assert (out / "out/evidence/page.html").read_bytes() == b"<html>\xff\xfe binary-ish</html>"
        assert (out / "urls.txt").read_text() == "https://a.com/x\n"

        # a changed file re-uploads, an untouched one does not
        (out / "out/STATUS.csv").write_text("url,state\nhttps://a.com/x,REMOVED\n")
        assert storage.push() == 1

    storage.ROOT, storage._coll = real_root, real_coll


def test_sample_files_match_the_code():
    """A sample that has drifted from DEFAULT_CONFIG is worse than no sample."""
    import json
    sample = json.loads(Path("config.json.example").read_text())
    assert set(sample) == set(app.DEFAULT_CONFIG), (
        set(app.DEFAULT_CONFIG) ^ set(sample))
    for k, v in app.DEFAULT_CONFIG.items():
        assert type(sample[k]) is type(v), f"{k}: {type(sample[k])} vs {type(v)}"
    # it must actually be loadable as config
    assert app.build_ns(sample).name == "Your Full Name"

    env = Path(".env.example").read_text()
    for key in ("APP_PASSWORD", "SESSION_SECRET", "MONGODB_URI", "MONGODB_DB", "PORT"):
        assert f"\n{key}=" in env, f"{key} missing from .env.example"
    # every env var the code actually reads must be documented
    for key in ("APP_PASSWORD", "SESSION_SECRET", "MONGODB_URI", "MONGODB_DB"):
        assert key in env


def test_dialog_ids_do_not_shadow_window_builtins():
    """app.js opens dialogs through the id-global (`identity.showModal()`).

    That only reaches the element when window has no property of that name - and a
    Window built-in wins. `<dialog id="confirm">` resolved to window.confirm, so
    ask() threw a TypeError and every button behind it silently did nothing.
    """
    html = Path("templates/app.html").read_text()
    js = Path("static/app.js").read_text()
    builtins = {"confirm", "alert", "prompt", "print", "close", "open", "focus",
                "blur", "status", "name", "length", "top", "self", "parent",
                "history", "location", "navigator", "screen", "find", "stop"}
    ids = re.findall(r'<dialog id="([^"]+)"', html)
    assert ids, "no dialogs found - did the template move?"
    for i in ids:
        assert i not in builtins, (
            f'<dialog id="{i}"> is shadowed by window.{i}; rename it')
        # and it must actually be driven that way somewhere, or this check is moot
        assert f"{i}.showModal()" in js or f"{i}.close()" in js or f"{i}.close()" in html


def test_secrets_stay_out_of_the_image():
    ignore = Path(".dockerignore").read_text().split()
    for leak in ("cyber_secure.conf", "config.json", "urls.txt", ".env", "out/"):
        assert leak in ignore, f"{leak} would be baked into the docker image"


def test_login_required():
    from fastapi.testclient import TestClient
    with TestClient(app.app) as c:
        assert c.get("/health").status_code == 200
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"
        assert c.get("/api/state").status_code == 401
        assert c.post("/login", data={"password": "wrong"}).status_code == 401
        assert c.get("/api/state").status_code == 401
        c.post("/login", data={"password": "test-password"})
        assert c.get("/api/state").status_code == 200


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"all {len(fns)} checks passed")
