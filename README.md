# fast-api

## takedown.py — NCII takedown reporter

Takes a list of URLs, works out who hosts each one, and writes ready-to-send abuse
emails — one per provider, with every URL at that provider grouped into it. Then
tracks each URL through to confirmed removal.

Nothing is ever sent automatically. You read every draft before it goes.

---

## Use it from your phone — the web app

The same pipeline, behind one password-protected URL. Every step below has a button,
a live progress log, and a **Your turn** panel listing what only you can do.

Deploying it also solves the tunnel problem for free: Render's outbound IP is US, so
there is no DNS poisoning and no SNI reset. **Preflight passes by default and you stop
having to think about WireGuard.** That is the real reason to run it there.

### Deploy to Render (free tier)

1. **A database, so your evidence survives.** Render's free tier has no persistent
   disk — the filesystem is wiped on every deploy, restart and idle spin-down, which
   would destroy your RFC-3161 timestamps. Create a free
   [MongoDB Atlas](https://www.mongodb.com/cloud/atlas/register) **M0** cluster
   (512MB, free forever, no expiry) and copy the connection string.

   Render has no static outbound IP, so Atlas → *Network Access* must allow
   `0.0.0.0/0`. Security then rests entirely on the connection string: use a dedicated
   database user with a long generated password.

2. **Deploy.** Push this repo, then on Render: *New → Blueprint*, point it at the repo.
   `render.yaml` does the rest. Set two environment variables when asked:

   | Variable | |
   |---|---|
   | `APP_PASSWORD` | how you log in. The app refuses to start without it |
   | `MONGODB_URI` | the Atlas string. Without it the instance is ephemeral and says so |

   `SESSION_SECRET` is generated for you by `render.yaml`. See `.env.example` for
   what each variable does and how to generate a good value.

3. **Open the URL on your phone** and log in. Add it to your home screen.

Free tier notes: the service sleeps after 15 minutes of no traffic and takes ~50s to
wake. While a step is running the page pings it, so nothing gets killed mid-capture —
and a job keeps running server-side even if you lock your phone or close the tab.

### Run it locally instead

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirement.txt

cp .env.example .env          # then edit it - at minimum set APP_PASSWORD
uvicorn app:app --env-file .env --reload
```

Then open **http://127.0.0.1:8000** and log in with `APP_PASSWORD`.
(`--port 8000` if you want a different one; `PORT` in `.env` is only read by the
Dockerfile, not by `uvicorn` directly.)

`.env.example` documents every variable with working sample values and the one-liners
to generate real secrets. `.env` is gitignored. `--env-file` needs no extra install —
`uvicorn[standard]` already bundles `python-dotenv`.

Without `MONGODB_URI` it just uses the local `out/` directory, exactly like the CLI,
and the header says *ephemeral* so you are never guessing. Locally you still need the
tunnel (see Step 0) — that requirement only disappears when it runs outside India.

### Sample files

| Copy this | To | Holds |
|---|---|---|
| `.env.example` | `.env` | password, session secret, Mongo connection string |
| `urls.txt.example` | `urls.txt` | the pages you are reporting |
| `config.json.example` | `config.json` | your name, reply-to, postal address, legal grounds |

All three targets are gitignored. You do not need to write `config.json` by hand — the
web app's **Edit your details** form writes it for you, and the sample is there so you
can see the shape or pre-seed it.

### What the web app adds

- **Your turn** — a computed list of everything the tool cannot do for you: the
  cybercrime portal, reading and sending each notice, web-form-only desks, de-indexing,
  reverse-image searching, reviewing new copies, StopNCII. It shrinks as you tick
  things off.
- **One button per abuse desk** — *Open in mail* prefills your mail app, *Copy full
  notice* puts the complete text on the clipboard (notices are ~4KB, which is past what
  a `mailto:` link can carry — the app tells you when that happens instead of letting
  your mail app truncate it silently), *Download .eml*, and *Mark sent*.
- **A details form** that asks for your name, reply-to, postal address and which legal
  grounds apply, before it writes anything — and enforces that a self-recorded (DMCA)
  claim has a postal address, since it is sworn under penalty of perjury.
- **A URL list editor**, so you can add a copy you found on your phone.
- **Every report rendered** — STATUS, CANDIDATES, EMBEDS, DISCOVERY, FORMS,
  SEARCH-ENGINES, the evidence manifest — plus a *Download all (.zip)*.

Saved evidence pages are always served as downloads, never rendered in the browser:
they are copies of the offending sites, and displaying one inside the app would show
the material and give its scripts access to your session.

Nothing about the safety design changes. No notice is ever sent for you, `--archive`
stays off behind a warning, and nothing is added to your URL list without you
selecting it.

Checks: `python test_app.py` (offline, no network, no database needed).

---

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

### Step 0 — Get a tunnel up, and confirm the script is actually using it

These sites are blocked by Indian ISPs in two ways, and both break the tool if ignored:

- **DNS poisoning.** Your resolver answers blocked domains with a block-server address
  (`13.127.247.216` / `202.56.230.30` here). The tool resolves over DNS-over-HTTPS instead,
  so abuse lookups find the real host. Without that fix, every notice would have been
  addressed to **your own ISP's abuse desk** about its own block page.
- **SNI blocking.** TCP connects to the real server, then the TLS handshake is reset. No
  amount of DNS trickery gets past this — fetching pages needs a real tunnel.

Run WireGuard **inside WSL**. A VPN running in Windows very likely will *not* cover this
shell: `.wslconfig` here has no `networkingMode=mirrored`, so WSL2 is on NAT networking.
Your browser works, the script stays blocked, and blocked pages look like removed pages.

```bash
sudo apt install wireguard          # the kernel side is already present
sudo cp cyber_secure.conf /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf
sudo wg-quick up wg0

python takedown.py urls.txt --preflight
```

Preflight tells you your exit IP and country, whether DNS is being lied to, and whether
each host's TLS handshake actually completes:

```
exit IP 106.215.176.201 (IN)
  -> going out through an Indian connection; expect ISP blocking

  www.pornhub.com    DoH=66.254.114.41  system=13.127.247.216 POISONED  TLS reset - SNI blocked

  NOT TUNNELLED - pages cannot be fetched from here, and a removal
  check would be meaningless: everything would look gone when it isn't.
```

Run it before every fetch-based step. Blocking is intermittent, so a preflight that passed
an hour ago can fail now.

`sudo wg-quick down wg0` when you're done.

**What needs the tunnel:**

| Step | Tunnel required |
|---|---|
| `--preflight` | no (that's the point) |
| `--evidence` | **yes** — refuses to run without it |
| `discover.py` | **yes** — `--offline` runs the useful half without it |
| reporting | **no** — RDAP and Abusix aren't blocked, and lookups use DoH |
| `--check` | **yes** — refuses to mark anything removed without it |
| `--followup` | no — reads local files only |

### Step 1 — Capture evidence. Do this BEFORE anything else.

```bash
python takedown.py urls.txt --evidence
```

A successful takedown destroys the proof the material was ever there. This grabs
it first: the page markup, a SHA-256 hash, and an **RFC-3161 trusted timestamp**
from freetsa.org. Police, a lawyer, or a civil claim will all ask for this.

The timestamp is a third party's signature saying *this exact file existed at this
exact time*. It proves the page was there without publishing anything — verified
offline, years later, with:

```bash
cd out/evidence
openssl ts -verify -in PAGE.tsr -queryfile PAGE.tsq -CAfile cacert.pem -untrusted tsa.crt
# Verification: OK
```

Change one byte of the saved page and that returns `Verification: FAILED`.

Produces `out/evidence/` (with `MANIFEST.csv` and `VERIFY.md`) and `out/DISCOVERY.md`.

The video itself is deliberately not downloaded. You don't need more copies of it.

`--archive` additionally pushes each URL to the Wayback Machine. It is **off by
default and you should think before using it**: it creates a permanent *public* copy
of the material, which is one more place you'd then have to get it removed from. The
timestamp above proves the same fact privately.

### Step 1b — Find the rest of the copies

A first pass typically finds well under half of what exists, so this is where the
outcome is really decided.

```bash
python discover.py
```

It reads the pages `--evidence` already saved and works outward from them. The key
thing it finds is that **the pages are not where the video lives**:

```
## https://luluvdo.com/e/wllrgcrkn9zo
Embedded by 6 known page(s):
  https://maal69.int.in/beautiful-milf-blowjob-pussy-fingering-by-husband-hd-video/
  https://fry99.center/beautiful-milf-blowjob-pussy-fingering-by-husband-watch/
  ...
```

Those sites are WordPress shells. The file sits on a video host they all embed, so
16 page URLs turn out to be **4 files**. Removing one file kills every page carrying
it at once, and the file host is a single abuse desk instead of one per site — which
is why `out/candidates.txt` puts those embed URLs first. Add them to `urls.txt` and
the reporter goes after the file host like any other target.

It also finds:

- **New copies.** Every farm site is WordPress, so it searches each one's own `/?s=`,
  mines `/actor/` and `/tag/` listings, and tries known slugs on sibling domains.
- **Mirror domains** — `maal69.cool` serving `maal69.int.in`, `luluvdo.com` landing on
  `lulustream.com`. A second domain is a second registrar to go after, and it keeps
  working after the first is suspended.
- **What it could not reach.** Hosts that never answered are listed as *not searched*.
  That is not the same as nothing being there, and the report says so rather than
  letting silence read as an all-clear.

Each hit is fetched and classified before it is reported:

| Tier | Meaning |
|---|---|
| `CONFIRMED` | embeds one of the exact files in `EMBEDS.md`. No judgement call. |
| `LIKELY` | a different file on a host the farm already uses, title matches |
| `MAYBE` | title matches, no embed readable |

**Only `CONFIRMED` reaches `candidates.txt`.** Nothing is ever appended to `urls.txt`
automatically — a notice about the wrong content costs you credibility with the one
desk that did act. Read them, then:

```bash
cat out/candidates.txt >> urls.txt
python takedown.py urls.txt --evidence      # capture the new ones too
```

`--offline` runs the file-extraction half with no network at all, so `EMBEDS.md` is
still produced from inside the ISP block.

**Then keep going by hand** with `out/DISCOVERY.md` — reverse-image and exact-title
links built from each page. Yandex Images finds copies no text search will, and
nothing here replaces it. Re-run `discover.py` each time you add URLs: new sites
mean new sites to search.

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

**It runs preflight first and aborts if the tunnel is down**, recording those URLs as
 rather than guessing. From inside the ISP block every site looks gone, and a
false  is the one error that would make you stop chasing something still online.

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
page hash, the timestamp proof, and exactly which abuse desks were contacted per URL.

| State | Meaning | What to do |
|---|---|---|
| `NEW` | in the list, nothing done | step 1 |
| `EVIDENCE` | page saved, hashed and timestamped | step 3 |
| `REPORTED` | notices sent, still inside the deadline | wait, then `--check` |
| `OVERDUE` | deadline passed, still up | `--followup` |
| `CHASED` | second notice sent | `ESCALATE.md` |
| `BLOCKED` | your connection can't reach it | bring the tunnel up, re-check |
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
| `--preflight` | can this shell reach the sites, and is DNS being lied to? |
| `--archive` | also push to the Wayback Machine. **Off by default** — creates a public copy |
| `--send-from` | send from a different address than the reply-to |
| `--out` | output directory (default `out/`) |

`discover.py` takes `--offline` (no network), `--rounds N` (how many times a newly
found site feeds the next search, default 2) and `--out`.

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
  DISCOVERY.md        manual reverse-image / title search leads
  EMBEDS.md           the actual video files, and which pages embed each one
  CANDIDATES.md       ranked new copies, mirror domains, hosts not reached
  candidates.txt      CONFIRMED URLs + file hosts, ready for urls.txt
  LOG.csv             full contact log (who, what, when)
  evidence/
    MANIFEST.csv      timestamps, hashes, capture times
    *.html            pages exactly as served
    *.tsq *.tsr       RFC-3161 timestamp proofs
    tsa.crt cacert.pem  certs to verify them offline, later
    VERIFY.md         how to verify
  followup/
    NN-*.eml          second notices
    ESCALATE.md       ordered escalation path
```

Checks: `python test_takedown.py` and `python test_discover.py` (offline, no network).
