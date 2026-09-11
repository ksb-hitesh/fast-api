"""Offline checks for the web layer. No network, no pytest.

    python test_app.py
"""
import asyncio
import os
import sys
import tempfile
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


def test_mailto_truncates_long_notices_and_flags_it():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "01-abuse-x.com.eml"
        from email.message import EmailMessage
        m = EmailMessage()
        m["Subject"] = "URGENT - NCII takedown"
        m["To"] = "abuse@x.com"
        m["From"] = "me@example.com"
        body = "https://site.com/a\n" + ("word " * 2000)
        m.set_content(body)
        p.write_bytes(m.as_bytes())

        got = app._parse_eml(p, "notice")
        assert got["to"] == "abuse@x.com"
        assert got["body"].startswith("https://site.com/a")   # quoted-printable decoded
        assert got["urls"] == ["https://site.com/a"]
        assert got["too_long"] is True
        assert "truncated" in got["mailto"]
        assert len(got["mailto"]) < len(body) * 3

        short = EmailMessage()
        short["Subject"] = "s"
        short["To"] = "a@b.com"
        short.set_content("https://x.com/1\nshort body")
        p.write_bytes(short.as_bytes())
        got = app._parse_eml(p, "notice")
        assert got["too_long"] is False
        assert "truncated" not in got["mailto"]


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
