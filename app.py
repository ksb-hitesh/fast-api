"""Web front end for takedown.py / discover.py.

The scripts are imported, not shelled out to: `args` is a duck-typed attribute bag
throughout takedown.py, so a SimpleNamespace drives every run_* coroutine directly -
the same trick test_takedown.py already uses with argparse.Namespace.

Nothing here sends email. The tool's core guarantee is that you read every draft
before it goes, so the UI hands you mailto:/clipboard/.eml and stops there.
"""
from __future__ import annotations

import asyncio
import contextlib
import csv
import email
import email.policy
import html
import io
import json
import os
import re
import secrets
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, RedirectResponse, Response,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from starlette.middleware.sessions import SessionMiddleware

import discover
import storage
import takedown

ROOT = Path(__file__).parent
OUT = ROOT / "out"
URLS = ROOT / "urls.txt"
CONFIG = ROOT / "config.json"

PASSWORD = os.environ.get("APP_PASSWORD", "")
if not PASSWORD:
    sys.exit("APP_PASSWORD is not set - refusing to start an unprotected instance")

app = FastAPI(title="takedown")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET") or secrets.token_hex(32),
    max_age=30 * 24 * 3600,
    same_site="lax",
    https_only=os.environ.get("RENDER") is not None,
)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")

_md = MarkdownIt("commonmark", {"html": False, "linkify": True}).enable("table")

DEFAULT_CONFIG = {
    "name": "", "email": "", "send_from": "", "postal": "",
    "india": True, "eu": False, "self_recorded": False, "archive": False,
    "origin": False, "use_ytdlp": False,
    "rounds": 2, "portal_ack": "", "sent": [],
}


# ------------------------------------------------------------------ config

def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG.exists():
        with contextlib.suppress(Exception):
            cfg.update(json.loads(CONFIG.read_text()))
    return cfg


def save_config(cfg: dict) -> None:
    CONFIG.write_text(json.dumps(cfg, indent=2, sort_keys=True))


def build_ns(cfg: dict) -> SimpleNamespace:
    """The attribute bag every takedown.run_* function expects."""
    return SimpleNamespace(
        urls=str(URLS), out=str(OUT),
        name=cfg.get("name") or None,
        email=cfg.get("email") or None,
        send_from=cfg.get("send_from") or None,
        postal=cfg.get("postal") or "",
        self_recorded=bool(cfg.get("self_recorded")),
        eu=bool(cfg.get("eu")),
        india=bool(cfg.get("india")),
        archive=bool(cfg.get("archive")),
        origin=bool(cfg.get("origin")),
        use_ytdlp=bool(cfg.get("use_ytdlp")),
        rounds=int(cfg.get("rounds") or 2),
    )


# ------------------------------------------------------------------ job runner

@dataclass
class Job:
    step: str
    state: str = "running"          # running | done | failed
    rc: int | None = None
    started: float = field(default_factory=time.time)
    finished: float | None = None
    lines: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"step": self.step, "state": self.state, "rc": self.rc,
                "started": self.started, "finished": self.finished,
                "lines": self.lines[-400:]}


_job: Job | None = None
_lock = asyncio.Lock()
_subs: set[asyncio.Queue] = set()
MAX_LINES = 2000


def _publish(event: dict) -> None:
    for q in list(_subs):
        with contextlib.suppress(asyncio.QueueFull):
            q.put_nowait(event)


class _LineTee(io.TextIOBase):
    """Collects whatever the scripts print and pushes it to the SSE subscribers.

    Both scripts already emit per-item progress to stderr (takedown.py:852 "capturing",
    :1151 "looking up", discover.py's per-round lines), so capturing the streams gives
    a live log with no changes to either file.
    """

    def __init__(self, job: Job):
        self.job = job
        self.buf = ""

    def write(self, s: str) -> int:
        self.buf += s
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self._emit(line)
        return len(s)

    def _emit(self, line: str) -> None:
        self.job.lines.append(line)
        del self.job.lines[:-MAX_LINES]
        _publish({"type": "line", "line": line})

    def flush(self) -> None:
        if self.buf:
            self._emit(self.buf)
            self.buf = ""

    def isatty(self) -> bool:
        return False


async def _dispatch(step: str, ns: SimpleNamespace, offline: bool) -> int:
    if step == "preflight":
        return await takedown.run_preflight(ns)
    if step == "evidence":
        return await takedown.run_evidence(ns)
    if step == "report":
        return await takedown.run(ns)
    if step == "check":
        return await takedown.run_check(ns)
    if step == "followup":
        return await takedown.run_followup(ns)
    if step == "discover":
        s = discover.seed(OUT, str(URLS))
        # Stage 1 always lands on disk first: hunt() returns without writing
        # anything at all when preflight fails, and EMBEDS.md is the useful half.
        discover.write_embeds(s["embed_map"], OUT)
        print(f"stage 1: {len(s['embed_map'])} file(s), "
              f"{len(s['hosts'])} host(s), key '{s['phrase']}'")
        if offline:
            discover.write_candidates([], s["embed_map"], set(s["known"]),
                                      s["phrase"], OUT)
            return 0
        return await discover.hunt(ns, s, OUT)
    raise ValueError(f"unknown step {step}")


async def _run_job(step: str, ns: SimpleNamespace, offline: bool) -> None:
    global _job
    job = _job
    tee = _LineTee(job)
    # Stale entries here would silently send notices to the wrong abuse desk.
    takedown._dns_cache.clear()
    try:
        # ponytail: redirect_stdout is process-global, which is only safe because
        # _lock keeps this to one job at a time. Needs per-job capture if this
        # ever grows concurrent runs.
        with contextlib.redirect_stdout(tee), contextlib.redirect_stderr(tee):
            job.rc = await _dispatch(step, ns, offline)
        tee.flush()
        job.state = "done" if job.rc == 0 else "failed"
    except SystemExit as e:
        # read_urls(), run_check(), overdue_rows() and discover.load_pages() all
        # sys.exit() in library code. SystemExit is a BaseException, so a bare
        # `except Exception` would let it kill the worker.
        tee.flush()
        job.lines.append(f"!! {e.code}")
        job.state, job.rc = "failed", 1
    except Exception as e:                       # noqa: BLE001 - surfaced to the UI
        tee.flush()
        job.lines.append(f"!! {type(e).__name__}: {e}")
        job.state, job.rc = "failed", 1
    finally:
        job.finished = time.time()
        with contextlib.suppress(Exception):
            n = await asyncio.to_thread(storage.push)
            if n:
                job.lines.append(f"saved {n} file(s) to MongoDB")
        _publish({"type": "done", "job": job.as_dict()})


# ------------------------------------------------------------------ auth

def require_login(request: Request) -> None:
    if not request.session.get("ok"):
        raise HTTPException(status_code=401, detail="login required")


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"bad": False})


@app.post("/login")
async def login(request: Request, password: str = Form("")):
    if secrets.compare_digest(password, PASSWORD):
        request.session["ok"] = True
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"bad": True},
                                      status_code=401)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not request.session.get("ok"):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "app.html", {})


@app.on_event("startup")
async def _startup():
    OUT.mkdir(parents=True, exist_ok=True)
    if storage.enabled():
        with contextlib.suppress(Exception):
            n = await asyncio.to_thread(storage.pull)
            print(f"restored {n} file(s) from MongoDB", file=sys.stderr)
    else:
        print("MONGODB_URI unset - state is ephemeral on this instance",
              file=sys.stderr)


# ------------------------------------------------------------------ state

def _rows_and_states() -> tuple[dict, dict]:
    rows = takedown.load_status(OUT)
    now = datetime.now(timezone.utc)
    return rows, {u: takedown.state_of(r, now) for u, r in rows.items()}


def _read_urls_text() -> str:
    return URLS.read_text() if URLS.exists() else ""


def _url_count() -> int:
    return len([ln for ln in _read_urls_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")])


def _emls(folder: Path) -> list[Path]:
    return sorted(folder.glob("[0-9][0-9]-*.eml")) if folder.exists() else []


def _candidate_urls() -> list[str]:
    f = OUT / "candidates.txt"
    if not f.exists():
        return []
    known = set(_read_urls_text().split())
    return [u for u in f.read_text().split() if u and u not in known]


def _todo(rows: dict, states: dict, cfg: dict) -> list[dict]:
    """What still needs a human. Computed, never static."""
    t: list[dict] = []
    sent = set(cfg.get("sent", []))
    counts: dict[str, int] = {}
    for s in states.values():
        counts[s] = counts.get(s, 0) + 1

    if not _url_count():
        t.append({"k": "urls", "t": "Add the page URLs", "go": "urls",
                  "d": "Nothing to work on yet - paste the URLs of the pages."})
        return t

    if not any(r.get("evidence_utc") for r in rows.values()):
        t.append({"k": "evidence", "t": "Capture evidence first", "go": "steps",
                  "d": "A takedown destroys the proof it was ever there. Do this "
                       "before reporting anything."})
    elif not cfg.get("portal_ack"):
        t.append({"k": "portal", "t": "File on cybercrime.gov.in", "go": "steps",
                  "d": "Anonymous, no police station visit. Attach MANIFEST.csv and "
                       "save the acknowledgement number - the notices cite it."})

    cands = _candidate_urls()
    if cands:
        t.append({"k": "cand", "t": f"{len(cands)} new copies to review", "go": "cand",
                  "d": "Read them, then append the real ones to your URL list."})

    unsent = [f.name for f in _emls(OUT) if f.name not in sent]
    if unsent:
        t.append({"k": "send", "t": f"Send {len(unsent)} notice(s)", "go": "notices",
                  "d": "Read each one, then open it in your mail app. Nothing is "
                       "sent for you."})
    fu = [f.name for f in _emls(OUT / "followup") if f.name not in sent]
    if fu:
        t.append({"k": "send2", "t": f"Send {len(fu)} second notice(s)", "go": "notices",
                  "d": "Deadline already missed on these."})

    if (OUT / "FORMS.md").exists():
        t.append({"k": "forms", "t": "Desks that only take a web form", "go": "notices",
                  "d": "Open each link and paste the body - no email possible."})
    if (OUT / "SEARCH-ENGINES.md").exists():
        t.append({"k": "deindex", "t": "De-index from search engines", "go": "files",
                  "d": "Kills most of the real-world harm fastest, independently of "
                       "whether the sites ever reply."})
    if (OUT / "DISCOVERY.md").exists():
        t.append({"k": "rev", "t": "Reverse-image search by hand", "go": "files",
                  "d": "Yandex Images finds copies no text search will. Nothing here "
                       "replaces doing this yourself."})

    if counts.get("OVERDUE"):
        t.append({"k": "od", "t": f"{counts['OVERDUE']} past deadline", "go": "steps",
                  "d": "Run the follow-up to send second notices."})
    if counts.get("UNCLEAR"):
        t.append({"k": "un", "t": f"{counts['UNCLEAR']} need you to look", "go": "files",
                  "d": "A 403 can be a takedown or just anti-bot. The check refuses "
                       "to guess - open them yourself."})
    if counts.get("BLOCKED"):
        t.append({"k": "bl", "t": f"{counts['BLOCKED']} unreachable", "go": "steps",
                  "d": "Your connection could not reach these. Not the same as "
                       "removed - re-check."})

    t.append({"k": "ncii", "t": "File with StopNCII.org", "go": "stopncii",
              "d": "Hashes the video on your device - the file never leaves it - and "
                   "partner platforms block re-uploads. This tool only kills URLs you "
                   "already know about."})
    return t


@app.get("/api/state")
async def api_state(request: Request):
    require_login(request)
    rows, states = _rows_and_states()
    cfg = load_config()
    counts: dict[str, int] = {}
    for s in states.values():
        counts[s] = counts.get(s, 0) + 1
    artifacts = []
    if OUT.exists():
        for f in sorted(OUT.rglob("*")):
            if f.is_file():
                artifacts.append({"path": f.relative_to(OUT).as_posix(),
                                  "size": f.stat().st_size})
    table = [{"url": u, "state": states[u],
              "reported": r.get("reported_utc", ""),
              "deadline": r.get("deadline_utc", ""),
              "checked": r.get("last_checked_utc", ""),
              "note": r.get("check_note", ""),
              "evidence": bool(r.get("evidence_utc"))}
             for u, r in sorted(rows.items(), key=lambda kv: kv[0])]
    return {
        "counts": counts, "total": len(rows), "urls": _url_count(),
        "table": table, "todo": _todo(rows, states, cfg),
        "artifacts": artifacts, "config": cfg,
        "job": _job.as_dict() if _job else None,
        "storage": "mongodb" if storage.enabled() else "ephemeral",
        "candidates": len(_candidate_urls()),
        "notices": len(_emls(OUT)) + len(_emls(OUT / "followup")),
        "needs_identity": not (cfg.get("name") and cfg.get("email")),
    }


# ------------------------------------------------------------------ running steps

NEEDS_IDENTITY = {"report", "followup"}


@app.post("/api/run/{step}")
async def api_run(request: Request, step: str):
    require_login(request)
    global _job
    if step not in {"preflight", "evidence", "discover", "report", "check", "followup"}:
        raise HTTPException(404, "no such step")
    body = {}
    with contextlib.suppress(Exception):
        body = await request.json()
    cfg = load_config()

    if step in NEEDS_IDENTITY and not (cfg.get("name") and cfg.get("email")):
        raise HTTPException(400, "your name and reply-to email are needed first")
    if step in NEEDS_IDENTITY and cfg.get("self_recorded") and not cfg.get("postal"):
        raise HTTPException(400, "a postal address is required for a self-recorded "
                                 "(DMCA) claim - it is sworn under penalty of perjury")
    if step in {"preflight", "evidence", "report"} and not _url_count():
        raise HTTPException(400, "no URLs yet - add them first")
    if step == "followup" and not (OUT / "LOG.csv").exists():
        raise HTTPException(400, "no LOG.csv yet - generate and send notices first")
    if step == "check" and not (OUT / "STATUS.csv").exists():
        raise HTTPException(400, "nothing tracked yet - capture evidence first")

    if step == "evidence" and bool(body.get("archive")) != bool(cfg.get("archive")):
        cfg["archive"] = bool(body.get("archive"))
        save_config(cfg)

    # Checked here, with no await between this and create_task, so two requests
    # racing in cannot both claim the slot and clobber each other's _job.
    if _lock.locked() or (_job and _job.state == "running"):
        raise HTTPException(409, "a step is already running")

    ns = build_ns(cfg)
    _job = Job(step=step)
    _publish({"type": "start", "job": _job.as_dict()})

    async def runner():
        async with _lock:
            await _run_job(step, ns, offline=bool(body.get("offline")))

    asyncio.create_task(runner())
    return {"ok": True, "job": _job.as_dict()}


@app.get("/api/job")
async def api_job(request: Request):
    require_login(request)
    return _job.as_dict() if _job else {}


@app.get("/api/ping")
async def api_ping(request: Request):
    require_login(request)
    return {"ok": True, "running": _lock.locked()}


@app.get("/api/events")
async def api_events(request: Request):
    require_login(request)
    q: asyncio.Queue = asyncio.Queue(maxsize=2000)
    _subs.add(q)

    async def gen():
        try:
            if _job:
                yield f"data: {json.dumps({'type': 'snapshot', 'job': _job.as_dict()})}\n\n"
            while True:
                try:
                    item = await asyncio.wait_for(q.get(), timeout=20)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            _subs.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ urls + config

@app.get("/api/urls", response_class=PlainTextResponse)
async def api_urls_get(request: Request):
    require_login(request)
    return _read_urls_text()


@app.post("/api/urls")
async def api_urls_post(request: Request):
    require_login(request)
    body = await request.json()
    text = body.get("text", "")
    if not text.endswith("\n"):
        text += "\n"
    URLS.write_text(text)
    await asyncio.to_thread(storage.push)
    return {"ok": True, "count": _url_count()}


@app.post("/api/config")
async def api_config_post(request: Request):
    require_login(request)
    body = await request.json()
    cfg = load_config()
    for k in DEFAULT_CONFIG:
        if k in body:
            cfg[k] = body[k]
    if cfg.get("self_recorded") and not cfg.get("postal"):
        raise HTTPException(400, "a postal address is required for a self-recorded "
                                 "(DMCA) claim - it is sworn under penalty of perjury")
    save_config(cfg)
    await asyncio.to_thread(storage.push)
    return {"ok": True, "config": cfg}


# ------------------------------------------------------------------ candidates

TIER_RE = re.compile(r"^\|\s*\[[^\]]*\]\(([^)]+)\)\s*\|\s*([A-Z]+)\s*\|\s*([^|]*)\|\s*([^|]*)\|")


@app.get("/api/candidates")
async def api_candidates(request: Request):
    require_login(request)
    meta: dict[str, dict] = {}
    md = OUT / "CANDIDATES.md"
    if md.exists():
        for line in md.read_text().splitlines():
            m = TIER_RE.match(line.strip())
            if m:
                meta[m.group(1)] = {"tier": m.group(2), "why": m.group(3).strip(),
                                    "title": m.group(4).strip()}
    return {"items": [dict(url=u, **meta.get(u, {"tier": "FILE", "why": "video file host", "title": ""}))
                      for u in _candidate_urls()]}


@app.post("/api/candidates/append")
async def api_candidates_append(request: Request):
    require_login(request)
    body = await request.json()
    picked = [u for u in body.get("urls", []) if u.startswith("http")]
    if not picked:
        raise HTTPException(400, "nothing selected")
    existing = _read_urls_text()
    if existing and not existing.endswith("\n"):
        existing += "\n"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    URLS.write_text(existing + f"# added from candidates {stamp}\n" +
                    "\n".join(picked) + "\n")
    await asyncio.to_thread(storage.push)
    return {"ok": True, "added": len(picked), "count": _url_count()}


# ------------------------------------------------------------------ notices

MAILTO_LIMIT = 1800


def _parse_eml(path: Path, kind: str) -> dict:
    # policy=default gives EmailMessage (so .get_body works) and decodes the
    # quoted-printable body takedown.py's set_content() produces.
    msg = email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
    body = msg.get_body(preferencelist=("plain",))
    text = body.get_content() if body else msg.get_payload(decode=True).decode(
        "utf-8", "replace")
    to = str(msg["To"] or "")
    subject = str(msg["Subject"] or "").replace("\n", " ").replace("\r", "")
    return {
        "file": path.name, "kind": kind, "to": to, "subject": subject,
        "body": text,
        "urls": [ln.strip() for ln in text.splitlines()
                 if ln.strip().startswith("http")],
        "too_long": len(text) > MAILTO_LIMIT,
        "mailto": "mailto:" + quote(to) + "?subject=" + quote(subject) + "&body=" +
                  quote(text if len(text) <= MAILTO_LIMIT else
                        text[:MAILTO_LIMIT].rsplit("\n", 1)[0] +
                        "\n\n[... truncated by your mail app's URL limit - use "
                        "\"Copy full notice\" in the web app and paste it here ...]"),
    }


FORM_RE = re.compile(
    r"^## (?P<provider>.+?)\n\nForm: (?P<url>\S+)\n\nCovers (?P<n>\d+) URL\(s\)\.\n"
    r"\nSubject:\n\n    (?P<subject>.+?)\n\nBody:\n\n```\n(?P<body>.*?)\n```",
    re.S | re.M)


@app.get("/api/notices")
async def api_notices(request: Request):
    require_login(request)
    cfg = load_config()
    sent = set(cfg.get("sent", []))
    items = [_parse_eml(f, "notice") for f in _emls(OUT)]
    items += [_parse_eml(f, "second notice") for f in _emls(OUT / "followup")]
    for it in items:
        it["sent"] = it["file"] in sent
    forms = []
    fm = OUT / "FORMS.md"
    if fm.exists():
        for m in FORM_RE.finditer(fm.read_text()):
            forms.append({"provider": m.group("provider"), "url": m.group("url"),
                          "count": int(m.group("n")), "subject": m.group("subject"),
                          "body": m.group("body"),
                          "sent": m.group("url") in sent})
    return {"items": items, "forms": forms}


@app.post("/api/notices/sent")
async def api_notices_sent(request: Request):
    require_login(request)
    body = await request.json()
    key, on = body.get("file", ""), bool(body.get("sent", True))
    cfg = load_config()
    sent = set(cfg.get("sent", []))
    sent.add(key) if on else sent.discard(key)
    cfg["sent"] = sorted(sent)
    save_config(cfg)
    await asyncio.to_thread(storage.push)
    return {"ok": True}


# ------------------------------------------------------------------ artifacts

DOWNLOAD_ONLY = {".html", ".htm", ".tsq", ".tsr", ".pem", ".crt", ".eml"}


def _resolve(rel: str) -> Path:
    p = (OUT / rel).resolve()
    if not p.is_relative_to(OUT.resolve()) or not p.is_file():
        raise HTTPException(404, "no such file")
    return p


def _csv_table(text: str) -> str:
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return "<p>empty</p>"
    head = "".join(f"<th>{html.escape(c)}</th>" for c in rows[0])
    body = "".join("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in r) + "</tr>"
                   for r in rows[1:])
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead>' \
           f"<tbody>{body}</tbody></table></div>"


@app.get("/artifact/{rel:path}")
async def artifact(request: Request, rel: str):
    require_login(request)
    p = _resolve(rel)
    suffix = p.suffix.lower()
    if request.query_params.get("raw") or suffix in DOWNLOAD_ONLY:
        # Saved pages are copies of the offending sites. Serving one as text/html
        # would render the material inside this app's own origin and hand its
        # scripts access to the session cookie. Always an attachment, never inline.
        return FileResponse(p, media_type="text/plain; charset=utf-8",
                            filename=p.name,
                            headers={"Content-Disposition":
                                     f'attachment; filename="{p.name}"',
                                     "X-Content-Type-Options": "nosniff"})
    text = p.read_text(errors="replace")
    if suffix == ".md":
        return HTMLResponse(_md.render(text))
    if suffix == ".csv":
        return HTMLResponse(_csv_table(text))
    return HTMLResponse(f"<pre>{html.escape(text)}</pre>")


@app.get("/download/zip")
async def download_zip(request: Request):
    require_login(request)
    tmp = Path("/tmp/takedown-out")
    shutil.make_archive(str(tmp), "zip", root_dir=OUT)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return FileResponse(f"{tmp}.zip", media_type="application/zip",
                        filename=f"takedown-{stamp}.zip")
