# fast-api

## takedown.py — NCII takedown reporter

Takes a list of URLs, works out who hosts each one, and writes ready-to-send abuse
emails — one per provider, with every URL at that provider grouped into it. Then
tracks each URL through to confirmed removal.

Nothing is ever sent automatically. You read every draft before it goes.

### Setup (once)

```bash
cd ~/learning/fast-api
source venv/bin/activate
```

No installation needed — it uses `httpx`, `dnspython` and `Jinja2`, which are
already in `requirement.txt`. Check it runs:

```bash
python test_takedown.py     # offline, no network, ~1 second
```

### Put your URLs in a file

Edit `urls.txt`. One full URL per line, pointing at the page the video is on.
Lines starting with `#` are ignored.

```
# my list
https://example-site.com/video/12345
https://another-site.net/watch?v=abcde
```

`urls.txt` is gitignored. Don't commit it.

---

### Step 1 — Capture evidence. Do this BEFORE anything else.

```bash
python takedown.py urls.txt --evidence
```

A successful takedown destroys the proof the material was ever there. This grabs
it first: the page markup, a SHA-256 hash, and a **Wayback Machine copy** with an
independent timestamp. Police, a lawyer, or a civil claim will all ask for this.

Produces `out/evidence/` (with `MANIFEST.csv`) and `out/DISCOVERY.md`.

The video itself is deliberately not downloaded. You don't need more copies of it.

**Then:** work through `out/DISCOVERY.md`. It has reverse-image and exact-title
search links built from each page. Anything new you find goes into `urls.txt`, and
you re-run this step. A first pass typically finds well under half of what exists,
so this is where the outcome is really decided.

### Step 2 — File on the cybercrime portal

Go to **https://cybercrime.gov.in/** and file under *"Report Women/Child Related
Crime"*. It accepts anonymous reports and doesn't need a police station visit.
Attach `out/evidence/MANIFEST.csv`. Keep the acknowledgement number.

Do this before sending the notices — they reference it.

### Step 3 — Generate and send the notices

```bash
python takedown.py urls.txt \
    --name "Your Full Name" \
    --email you@example.com \
    --india
```

Produces one `.eml` per abuse desk in `out/`. Double-click each to open it in your
mail client, **read it**, then send.

Also produced:
- `out/FORMS.md` — desks that only take a web form (Cloudflare and similar). Open
  the link, paste the text.
- `out/SEARCH-ENGINES.md` — de-indexing links plus a paste-ready URL list. Do this
  too; it kills most of the practical harm fastest.

### Step 4 — Check whether it actually came down

```bash
python takedown.py --check
```

Re-fetches every URL and records what it found. Safe to run as often as you like —
after two hours, the next morning, a week later.

### Step 5 — Chase whoever missed the deadline

```bash
python takedown.py --followup --india \
    --name "Your Full Name" --email you@example.com
```

Second notices for every desk past its deadline, citing the missed window and lost
safe harbour, plus `out/followup/ESCALATE.md` — the ordered escalation path.
Anything already confirmed removed is skipped automatically.

Then go back to step 4. Repeat until the table is all `REMOVED`.

---

### Tracking: `out/STATUS.csv` and `out/STATUS.md`

Every step writes into one table, so you can always see where each URL stands and
pick the work back up weeks later.

`STATUS.md` is the readable version:

| URL | State | Evidence | Reported | Deadline | Last check | Result |
|---|---|---|---|---|---|---|
| https://site.com/a | REMOVED | yes | 2026-09-11 12:26 | 2026-09-11 14:26 | 2026-09-11 18:26 | gone (404) |
| https://site.com/b | OVERDUE | yes | 2026-09-11 12:26 | 2026-09-11 14:26 | 2026-09-11 18:26 | still up (200) |

`STATUS.csv` is the same data with every column — opens in Excel, and holds the
page hash, the Wayback link, and exactly which abuse desks were contacted per URL.

| State | Meaning | What to do |
|---|---|---|
| `NEW` | in the list, nothing done | step 1 |
| `EVIDENCE` | snapshot + Wayback copy taken | step 3 |
| `REPORTED` | notices sent, still inside the deadline | wait, then `--check` |
| `OVERDUE` | deadline passed, still up | `--followup` |
| `CHASED` | second notice sent | `ESCALATE.md` |
| `UNCLEAR` | the check couldn't tell | open it yourself and look |
| `REMOVED` | confirmed gone | nothing |

`UNCLEAR` means exactly that — a 403 can be a takedown or just anti-bot blocking,
so the check refuses to guess. A false all-clear is the one error that would make
you stop chasing something still online.

Adding URLs later is fine: append to `urls.txt` and re-run. Existing rows keep
their history.

### Options

| Flag | |
|---|---|
| `--india` | Rule 3(2)(b), IT Rules 2021 as amended by G.S.R. 120(E) (in force 20 Feb 2026): removal **within 2 hours of your complaint**, and loss of Section 79 safe harbour if missed. Triggers on your complaint alone — no court order. Use this. |
| `--self-recorded` | **Only if you filmed it yourself.** Adds a DMCA §512(c) claim sworn under penalty of perjury, so it also needs `--postal`. If someone else recorded it you don't hold the copyright — leave this off and the notice runs on NCII grounds instead. |
| `--eu` | adds a GDPR Art. 17 erasure demand |
| `--send-from` | send from a different address than the reply-to |
| `--out` | output directory (default `out/`) |

### Before you start

- **Don't send from a work address.** The reply-to reaches site operators.
- **Never attach the video**, and don't download it again. URLs only.
- **File with [StopNCII.org](https://stopncii.org/)** as well. It hashes the video
  on your device — the file never leaves it — and partner platforms block
  re-uploads. This tool only kills URLs you already know about; StopNCII is what
  stops new ones appearing.
- **This is not foolproof, and nothing is.** The tool handles identification,
  drafting, tracking and chasing. What decides the outcome is how many copies you
  find, whether you captured evidence first, and how hard you escalate. A lawyer's
  letterhead moves hosts that ignore individuals.

### Files it writes

```
out/
  STATUS.csv          every URL, every step, one row each   <- your tracker
  STATUS.md           the same as a readable table
  NN-*.eml            one draft per abuse desk
  FORMS.md            desks that only take a web form
  SEARCH-ENGINES.md   de-indexing links + paste-ready URL list
  DISCOVERY.md        leads for copies you haven't found
  LOG.csv             full contact log (who, what, when)
  evidence/
    MANIFEST.csv      timestamps, hashes, Wayback links
    *.html            pages exactly as served
  followup/
    NN-*.eml          second notices
    ESCALATE.md       ordered escalation path
```

Checks: `python test_takedown.py` (offline, no network).
