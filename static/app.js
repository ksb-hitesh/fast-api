'use strict';
let S = null, CFG = {}, running = false, beat = null;
const $ = s => document.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t);
  if (c) e.className = c; if (h !== undefined) e.innerHTML = h; return e; };
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const STEPS = [
  { id:'preflight', n:'0', t:'Preflight',
    d:'Can this server reach the sites, and is DNS being lied to? Shows your exit IP and country.',
    note:'Runs host by host, up to ~8s each — give it a moment with a long list.' },
  { id:'evidence', n:'1', t:'Capture evidence',
    d:'Saves each page, hashes it, and gets an RFC-3161 trusted timestamp from freetsa.org. A successful takedown destroys the proof it was ever there — this grabs it first.',
    note:'Do this before reporting anything.' },
  { id:'discover', n:'2', t:'Find more copies',
    d:'Works outward from the saved pages. Finds the video-file hosts the sites embed (16 pages are often only 4 files), mirror domains, and new copies.',
    note:'A first pass typically finds well under half of what exists.' },
  { id:'report', n:'3', t:'Generate notices',
    d:'Works out who hosts each URL and writes one ready-to-send abuse email per provider, plus web-form and de-indexing lists.',
    note:'Nothing is sent. You read every draft before it goes.' },
  { id:'check', n:'4', t:'Check removal',
    d:'Re-fetches every URL and records what it found. Safe to run as often as you like.',
    note:'BLOCKED is not REMOVED — it refuses to guess rather than give a false all-clear.' },
  { id:'followup', n:'5', t:'Follow up',
    d:'Second notices for every desk past its deadline, citing the missed window and lost safe harbour, plus the escalation path.',
    note:'Anything already confirmed removed is skipped automatically.' },
];

const QUICK = [
  ['STATUS.md',        'Progress table'],
  ['CANDIDATES.md',    'New copies found'],
  ['EMBEDS.md',        'The actual video files'],
  ['SEARCH-ENGINES.md','De-index from search'],
  ['DISCOVERY.md',     'Reverse-image leads'],
  ['FORMS.md',         'Web-form-only desks'],
  ['followup/ESCALATE.md','Escalation path'],
  ['evidence/MANIFEST.csv','Evidence manifest'],
  ['evidence/VERIFY.md','How to verify timestamps'],
  ['STATUS.csv',       'Full tracker (CSV)'],
  ['LOG.csv',          'Contact log'],
];

/* ─────────────────────────── navigation ─────────────────────────── */
function go(p) {
  document.querySelectorAll('.panel').forEach(s => s.hidden = s.id !== 'p-' + p);
  document.querySelectorAll('nav button').forEach(b =>
    b.classList.toggle('on', b.dataset.go === p));
  window.scrollTo(0, 0);
  if (p === 'urls')    loadUrls();
  if (p === 'cand')    loadCands();
  if (p === 'notices') loadNotices();
}
document.querySelectorAll('nav button').forEach(b =>
  b.onclick = () => go(b.dataset.go));

/* ─────────────────────────── state ─────────────────────────── */
async function refresh() {
  const r = await fetch('/api/state');
  if (r.status === 401) return location.href = '/login';
  S = await r.json(); CFG = S.config;
  $('#storage').textContent = S.storage === 'mongodb' ? 'saved to mongodb' : 'ephemeral';
  $('#storage').style.color = S.storage === 'mongodb' ? '' : 'var(--warn)';
  $('#urlcount').textContent = `${S.urls} URL${S.urls === 1 ? '' : 's'} in the list`;
  drawCounts(); drawTodo(); drawMini(); drawSteps(); drawFiles(); drawUrls();
  $('#nav-cand').hidden = !S.candidates;
  $('#nav-not').hidden = !S.notices;
  if (S.job) showJob(S.job);
}

function drawCounts() {
  const c = $('#counts'); c.innerHTML = '';
  const order = ['OVERDUE','UNCLEAR','BLOCKED','NEW','EVIDENCE','REPORTED','CHASED','REMOVED'];
  const ks = Object.keys(S.counts).sort((a, b) => order.indexOf(a) - order.indexOf(b));
  if (!ks.length) { c.innerHTML = '<p class="muted sm">Nothing tracked yet.</p>'; return; }
  ks.forEach(k => c.append(el('span', 'chip',
    `<i class="dotc s-${esc(k)}"></i>${esc(k)} <b>${S.counts[k]}</b>`)));
}

function drawTodo() {
  const d = $('#todo'); d.innerHTML = '';
  $('#todo-n').textContent = S.todo.length;
  S.todo.forEach(t => {
    const it = el('div', 'item');
    it.append(el('h3', '', esc(t.t)), el('p', 'muted sm', esc(t.d)));
    const row = el('div', 'row');
    if (t.k === 'portal') {
      row.append(mk('Open cybercrime.gov.in', () =>
        window.open('https://cybercrime.gov.in/', '_blank', 'noopener')));
      row.append(mk('Save ack number', openIdentity, 'ghost sm'));
    } else if (t.k === 'ncii') {
      row.append(mk('Open StopNCII.org', () =>
        window.open('https://stopncii.org/', '_blank', 'noopener')));
    } else if (t.k === 'deindex') {
      row.append(mk('Open list', () => view('SEARCH-ENGINES.md')));
    } else if (t.k === 'rev') {
      row.append(mk('Open leads', () => view('DISCOVERY.md')));
    } else if (t.k === 'un' || t.k === 'bl') {
      row.append(mk('See which', () => { go('files'); view('STATUS.md'); }));
    } else {
      row.append(mk('Go', () => go(t.go)));
    }
    it.append(row); d.append(it);
  });
  $('#todo-card').hidden = !S.todo.length;
}

function mk(label, fn, cls) {
  const b = el('button', cls || 'sm', esc(label)); b.onclick = fn; return b;
}

function drawMini() {
  const m = $('#minitable');
  if (!S.table.length) {
    m.innerHTML = '<p class="muted sm">Nothing tracked yet. Add URLs, then capture evidence.</p>';
    return;
  }
  m.innerHTML = '<div class="scroll"><table><thead><tr><th>URL</th><th>State</th>' +
    '<th>Last check</th></tr></thead><tbody>' +
    S.table.map(r => `<tr><td class="brk">${esc(r.url)}</td>` +
      `<td><i class="dotc s-${esc(r.state)}"></i> ${esc(r.state)}</td>` +
      `<td>${short(r.checked)}` +
      (r.note ? `<br><span class="muted sm">${esc(r.note)}</span>` : '') +
      '</td></tr>').join('') + '</tbody></table></div>';
}

/* ─────────────────────────── steps ─────────────────────────── */
function drawSteps() {
  const c = $('#steps'); c.innerHTML = '';
  STEPS.forEach(s => {
    const card = el('div', 'card');
    card.append(el('div', 'row',
      `<h2>${s.n} · ${esc(s.t)}</h2>`));
    card.append(el('p', 'muted sm', esc(s.d)));
    card.append(el('p', 'sm', '<b>' + esc(s.note) + '</b>'));

    if (s.id === 'evidence') {
      const l = el('label', 'check',
        '<input type="checkbox" id="opt-archive"><span><b>Also push to the Wayback Machine</b>'
        + '<br><span class="muted sm">Off by default, and think before using it: it creates a '
        + 'permanent <b>public</b> copy of the material, which is one more place you would then '
        + 'have to get it removed from. The timestamp already proves the same fact privately.'
        + '</span></span>');
      card.append(l);
      l.querySelector('input').checked = !!CFG.archive;
    }
    if (s.id === 'discover') {
      const l = el('label', 'check',
        '<input type="checkbox" id="opt-offline"><span><b>Offline only</b><br>'
        + '<span class="muted sm">Extracts the video files from pages already saved, with no '
        + 'network at all. Use it if the search half is blocked.</span></span>');
      card.append(l);
      const r = el('label', '', 'Search rounds <input type="number" id="opt-rounds" min="1" max="5">');
      r.querySelector('input').value = CFG.rounds || 2;
      card.append(r);
    }

    const row = el('div', 'row');
    const b = el('button', '', 'Run');
    b.onclick = () => runStep(s);
    row.append(b);
    const why = disabledReason(s.id);
    if (why) { b.disabled = true; row.append(el('span', 'muted sm', esc(why))); }
    card.append(row);
    c.append(card);
  });
}

function disabledReason(id) {
  if (running) return 'another step is running';
  if (!S.urls && ['preflight','evidence','report'].includes(id))
    return 'add URLs first';
  if (id === 'report' && S.needs_identity) return 'your name and email are needed first';
  if (id === 'followup' && S.needs_identity) return 'your name and email are needed first';
  if (id === 'followup' && !S.artifacts.some(a => a.path === 'LOG.csv'))
    return 'generate and send notices first';
  if (id === 'check' && !S.artifacts.some(a => a.path === 'STATUS.csv'))
    return 'capture evidence first';
  if (id === 'discover' && !S.artifacts.some(a => a.path === 'evidence/evidence.json'))
    return 'capture evidence first';
  return '';
}

async function runStep(s) {
  if ((s.id === 'report' || s.id === 'followup') && S.needs_identity)
    return openIdentity();
  // Step 3 from here means "everything currently in the list", but it still goes
  // through the same gate the URLs tab uses, so nothing is re-reported by surprise.
  if (s.id === 'report')
    return reportRun(S.table.filter(r => r.in_list).map(r => r.url));

  const body = {};
  if (s.id === 'discover') {
    body.offline = $('#opt-offline')?.checked;
    const n = parseInt($('#opt-rounds')?.value, 10);
    if (n >= 1) await saveCfg({ rounds: n });
  }
  if (s.id === 'evidence') {
    body.archive = $('#opt-archive')?.checked;
    if (body.archive && !await ask('Push to the Wayback Machine?',
      '<p>This creates a <b>permanent public copy</b> of the material at archive.org, ' +
      'which then becomes one more place you have to get it removed from.</p>' +
      '<p class="muted sm">The RFC-3161 timestamp already proves the page existed, ' +
      'privately. You almost certainly do not need this.</p>')) return;
  }
  await start(s, body);
}

async function start(s, body) {
  const r = await fetch('/api/run/' + s.id, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return alert(j.detail || 'could not start');
  $('#job-title').textContent = s.n + ' · ' + s.t;
  showJob(j.job); go('steps');
}

function showJob(j) {
  running = j.state === 'running';
  $('#job-card').hidden = false;
  const st = $('#job-state');
  st.textContent = j.state;
  st.style.color = j.state === 'failed' ? 'var(--danger)'
    : j.state === 'done' ? 'var(--ok)' : 'var(--warn)';
  const meta = STEPS.find(s => s.id === j.step);
  $('#job-title').textContent = meta ? meta.n + ' · ' + meta.t : j.step;
  $('#job-log').textContent = (j.lines || []).join('\n');
  scrollLog(); heartbeat();
}

function scrollLog() { const l = $('#job-log'); l.scrollTop = l.scrollHeight; }

/* Free tier sleeps on 15 min of zero traffic. Only ping while work is in flight. */
function heartbeat() {
  if (running && !beat) beat = setInterval(() => fetch('/api/ping'), 60000);
  if (!running && beat) { clearInterval(beat); beat = null; }
}

/* ─────────────────────────── live log ─────────────────────────── */
function connect() {
  const es = new EventSource('/api/events');
  es.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.type === 'line') {
      const l = $('#job-log');
      l.textContent += (l.textContent ? '\n' : '') + m.line;
      scrollLog();
    } else if (m.type === 'start' || m.type === 'snapshot') {
      showJob(m.job);
    } else if (m.type === 'done') {
      showJob(m.job); refresh();
    }
  };
  es.onerror = () => { es.close(); setTimeout(connect, 3000); };
}

/* ─────────────────────────── urls ─────────────────────────── */
const urlBoxes = () => [...document.querySelectorAll('#urls-table input[value]')];
const picked = () => urlBoxes().filter(b => b.checked).map(b => b.value);
const short = t => t ? esc(t.slice(0, 16).replace('T', ' ')) : '—';

function syncUrlBtns() {
  const n = picked().length;
  document.querySelectorAll('#p-urls .sel').forEach(b => b.disabled = !n);
}

function drawUrls() {
  const t = $('#urls-table'), rows = S.table;
  const held = rows.filter(r => r.in_list === false).length;
  $('#urls-count').textContent = rows.length
    ? `${S.urls} in the next run${held ? ` · ${held} held back` : ''}` : '';
  if (!rows.length) {
    t.innerHTML = '<p class="muted sm">Nothing here yet. <b>+ Add URLs</b> to start.</p>';
    return syncUrlBtns();
  }
  t.innerHTML = '<div class="scroll"><table><thead><tr><th><input type="checkbox" '
    + 'id="url-all" aria-label="Select all"></th><th>URL</th><th>Status</th>'
    + '<th>Reported</th><th>Last check</th><th>Abuse contact</th><th>In report</th>'
    + '</tr></thead><tbody>'
    + rows.map(r => {
      // null means STATUS.csv still tracks it but the line is gone from urls.txt.
      const orphan = r.in_list === null || r.in_list === undefined;
      const out = r.in_list === false;
      return `<tr${out || orphan ? ' style="opacity:.55"' : ''}>`
        + `<td><input type="checkbox" value="${esc(r.url)}"></td>`
        // noreferrer as well as noopener: the site must not learn this app's address.
        + `<td class="brk"><a href="${esc(r.url)}" target="_blank" rel="noopener `
        + `noreferrer" title="Open in a new tab and check it yourself">${esc(r.url)}</a>`
        + (orphan ? '<br><span class="muted sm">tracked, no longer in the list</span>' : '')
        + `</td><td><i class="dotc s-${esc(r.state)}"></i> ${esc(r.state)}`
        + (r.note ? `<br><span class="muted sm">${esc(r.note)}`
            + (r.http_status ? ` · ${esc(r.http_status)}` : '') + '</span>' : '')
        + `</td><td>${short(r.reported)}`
        + (r.deadline ? `<br><span class="muted sm">due ${short(r.deadline)}</span>` : '')
        + `</td><td>${short(r.checked)}</td>`
        + `<td>${contactCell(r)}</td>`
        + `<td>${orphan ? '—' : out ? '✗' : '✓'}</td></tr>`;
    }).join('') + '</tbody></table></div>';
  $('#url-all').onchange = e => {
    urlBoxes().forEach(b => b.checked = e.target.checked);
    syncUrlBtns();
  };
  urlBoxes().forEach(b => b.onchange = syncUrlBtns);
  t.querySelectorAll('button[data-contact]').forEach(b =>
    b.onclick = () => openContacts([b.dataset.contact]));
  syncUrlBtns();
}

/* What the next notice will actually be addressed to. A hand-entered address wins,
   and says so — the whole point is knowing which one is in force. */
function contactCell(r) {
  const own = r.manual_contacts;
  const shown = own || r.contacts;
  return (shown
      ? `<span class="brk sm">${esc(shown.split('; ').join(', '))}</span>`
        + (own ? ' <span class="tier t-CONFIRMED">by hand</span>' : '')
      : '<span class="muted sm">not looked up yet</span>')
    + `<br><button class="ghost sm" data-contact="${esc(r.url)}">✉ Edit</button>`;
}

async function urlEdit(payload, msg) {
  const r = await fetch('/api/urls/edit', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return toast(j.detail || 'failed');
  toast(msg(j));
  refresh();
}

async function addUrls() {
  const r = await fetch('/api/urls/edit', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ op: 'add', text: $('#add-text').value }),
  });
  const j = await r.json().catch(() => ({}));
  $('#add-err').textContent = j.detail || '';
  $('#add-err').hidden = r.ok;
  if (!r.ok) return;
  $('#add-text').value = '';
  addurls.close();
  toast(`Added ${j.added}. Capture evidence for them next.`);
  refresh();
}

const includeSel = on => urlEdit({ op: 'include', urls: picked(), on },
  j => on ? `${j.changed} back in the next run.` : `${j.changed} held back.`);

async function removeSel() {
  const urls = picked();
  if (!await ask(`Remove ${urls.length} URL(s)?`,
    '<p>They leave the list and their tracked status is deleted.</p>' +
    '<p class="muted sm">Saved evidence stays — that is the proof the page existed. ' +
    'To stop working on a URL without deleting anything, use <b>Out</b> instead.</p>'))
    return;
  urlEdit({ op: 'remove', urls }, j => `Removed ${j.removed}.`);
}

async function markSel(sel) {
  const verdict = sel.value, urls = picked();
  sel.value = '';                                  // never sticks as a mode
  if (!verdict || !urls.length) return;
  const r = await fetch('/api/urls/status', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ urls, verdict }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return toast(j.detail || 'failed');
  toast(`${j.changed} URL(s) updated.`);
  refresh();
}

let contactUrls = [], contactAlso = [];
const effContact = r => r.manual_contacts || r.contacts || '';

function openContacts(urls) {
  if (!urls.length) return toast('Nothing selected.');
  contactUrls = urls;
  const rows = urls.map(u => S.table.find(x => x.url === u)).filter(Boolean);
  const vals = [...new Set(rows.map(effContact))];
  const one = rows.length === 1 ? rows[0] : null;

  // group_contacts() batches by address, so URLs already sharing this desk are in
  // the same notice. Correcting one and leaving the rest splits that mail in two.
  contactAlso = one && effContact(one)
    ? S.table.filter(r => r.url !== one.url && effContact(r) === effContact(one))
        .map(r => r.url)
    : [];

  $('#contact-for').textContent = one ? one.url : `${rows.length} URLs selected`;
  $('#contact-text').value = vals.length === 1
    ? vals[0].split('; ').filter(Boolean).join('\n') : '';
  $('#contact-found').textContent =
    vals.length > 1 ? `These ${rows.length} URLs do not share one address — saving `
                      + 'sets every one of them to what you type.'
    : one && one.contacts ? `Lookups found: ${one.contacts}`
    : 'Lookups have not run for these yet.';
  $('#contact-also-wrap').hidden = !contactAlso.length;
  $('#contact-also').checked = true;
  $('#contact-also-n').textContent = contactAlso.length;
  $('#contact-err').hidden = true;
  contactdlg.showModal();
}

async function saveContacts() {
  const urls = contactUrls.concat(
    contactAlso.length && $('#contact-also').checked ? contactAlso : []);
  const r = await fetch('/api/urls/contacts', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ urls, contacts: $('#contact-text').value }),
  });
  const j = await r.json().catch(() => ({}));
  $('#contact-err').textContent = j.detail || '';
  $('#contact-err').hidden = r.ok;
  if (!r.ok) return;
  contactdlg.close();
  toast(j.contacts ? `Saved — ${j.changed} URL(s) now go to this address, as one notice.`
                   : 'Cleared — back to whatever the lookups find.');
  refresh();
}

const stepBy = id => STEPS.find(s => s.id === id);
const recheckSel = () => start(stepBy('check'), { urls: picked() });
const reportSel = () => reportRun(picked());

/* Nothing is silently re-reported. A URL that already went out is listed and left
   unticked: re-reporting restarts its deadline, which is rarely what you want —
   chasing a desk that ignored you is what "Follow up" is for. */
async function reportRun(urls) {
  if (S.needs_identity) return openIdentity();
  if (!urls.length) return toast('Nothing selected.');
  const by = Object.fromEntries(S.table.map(r => [r.url, r]));
  const fresh = urls.filter(u => !(by[u] && by[u].reported));
  const again = urls.filter(u => by[u] && by[u].reported);
  let extra = [];
  if (again.length) {
    const ok = await ask(`${again.length} already reported`,
      (fresh.length
        ? `<p><b>${fresh.length} new URL(s)</b> will be reported. The rest went out `
          + 'already — tick any you want to send again.</p>'
        : '<p><b>Every URL you picked has already been reported.</b> Tick the ones to '
          + 'send again, or cancel — nothing happens otherwise.</p>')
      + '<p class="muted sm">Re-reporting restarts the deadline. To chase a desk that '
      + 'ignored you, run <b>5 · Follow up</b> instead.</p>'
      + '<div class="row"><button class="ghost sm" onclick="tickAll(this)">Tick all'
      + '</button></div>'
      + again.map(u => '<label class="check"><input type="checkbox" '
          + `value="${esc(u)}"><span><span class="brk">${esc(u)}</span><br>`
          + `<span class="muted sm">reported ${short(by[u].reported)}</span>`
          + '</span></label>').join(''));
    if (!ok) return;
    extra = [...document.querySelectorAll('#c-body input:checked')].map(b => b.value);
  }
  const final = [...new Set([...fresh, ...extra])];
  if (!final.length)
    return toast('Nothing reported — none were ticked to send again.');
  start(stepBy('report'), { urls: final });
}

function tickAll(btn) {
  const boxes = [...document.querySelectorAll('#c-body input[type=checkbox]')];
  const all = boxes.every(b => b.checked);
  boxes.forEach(b => b.checked = !all);
  btn.textContent = all ? 'Tick all' : 'Untick all';
}

async function loadUrls() {
  $('#urls-text').value = await (await fetch('/api/urls')).text();
}
async function saveUrls() {
  const r = await fetch('/api/urls', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: $('#urls-text').value }),
  });
  const j = await r.json();
  $('#urls-msg').textContent = `saved — ${j.count} URL(s)`;
  refresh();
}

/* ─────────────────────────── candidates ─────────────────────────── */
async function loadCands() {
  const { items } = await (await fetch('/api/candidates')).json();
  const c = $('#cand-list'); c.innerHTML = '';
  if (!items.length) {
    c.innerHTML = '<p class="muted sm">Nothing new. Run <b>Find more copies</b> after '
      + 'capturing evidence.</p>';
    $('#cand-btn').disabled = true; return;
  }
  items.forEach(i => {
    const l = el('label', 'check');
    l.innerHTML = `<input type="checkbox" value="${esc(i.url)}">`
      + `<span><span class="tier t-${esc(i.tier)}">${esc(i.tier)}</span> `
      + `<span class="muted sm">${esc(i.why)}</span><br>`
      + `<span class="brk">${esc(i.url)}</span>`
      + (i.title ? `<br><span class="muted sm">${esc(i.title)}</span>` : '') + '</span>';
    l.querySelector('input').onchange = syncCandBtn;
    c.append(l);
  });
  syncCandBtn();
}
const candBoxes = () => [...document.querySelectorAll('#cand-list input')];
function syncCandBtn() {
  $('#cand-btn').disabled = !candBoxes().some(b => b.checked);
}
function toggleAllCands() {
  const all = candBoxes().every(b => b.checked);
  candBoxes().forEach(b => b.checked = !all);
  syncCandBtn();
}
async function appendCands() {
  const urls = candBoxes().filter(b => b.checked).map(b => b.value);
  const r = await fetch('/api/candidates/append', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ urls }),
  });
  const j = await r.json();
  if (!r.ok) return alert(j.detail || 'failed');
  alert(`Added ${j.added}. Capture evidence for the new ones next.`);
  loadCands(); refresh();
}

/* ─────────────────────────── notices ─────────────────────────── */
async function loadNotices() {
  const { items, forms } = await (await fetch('/api/notices')).json();
  const c = $('#notices'); c.innerHTML = '';
  if (!items.length && !forms.length) {
    c.append(el('div', 'card',
      '<p class="muted sm">No notices yet. Run <b>Generate notices</b>.</p>'));
    return;
  }
  items.forEach(i => c.append(noticeCard(i)));
  forms.forEach(f => c.append(formCard(f)));
}

function noticeCard(i) {
  const card = el('div', 'card' + (i.sent ? ' done' : ''));
  card.append(el('div', 'row',
    `<h2>${esc(i.to)}</h2><span class="pill">${esc(i.kind)}</span>`));
  card.append(el('p', 'muted sm',
    `${i.urls.length} URL(s) · ${esc(i.file)}`));

  const det = el('details');
  det.append(el('summary', 'sm', 'Read the notice'));
  det.append(el('pre', 'log', esc(i.body)));
  card.append(det);

  card.append(el('p', 'muted sm',
    '<b>1.</b> Copy the notice · <b>2.</b> open the mail — it comes addressed and '
    + 'titled, with an empty body · <b>3.</b> paste, read it once more, send.'));

  const row = el('div', 'row');
  row.append(mk('📋 Copy notice', () => copy(i.body)));
  const mail = el('a', 'btn ghost', '📧 Open in mail');
  mail.href = i.mailto; row.append(mail);
  const dl = el('a', 'btn ghost sm', '⬇ .eml');
  dl.href = '/artifact/' + (i.kind === 'notice' ? '' : 'followup/') + i.file + '?raw=1';
  row.append(dl);
  row.append(mk(i.sent ? '↩ Not sent' : '✓ Mark sent',
    () => markSent(i.file, !i.sent), 'ghost sm'));
  row.append(mk('🗑 Delete', () => delNotice(
    { file: (i.kind === 'notice' ? '' : 'followup/') + i.file },
    i.to, i.urls.length), 'ghost sm danger'));
  card.append(row);
  return card;
}

function formCard(f) {
  const card = el('div', 'card' + (f.sent ? ' done' : ''));
  card.append(el('div', 'row',
    `<h2>${esc(f.provider)}</h2><span class="pill">web form</span>`));
  card.append(el('p', 'muted sm',
    `${f.count} URL(s) · no email possible, open the form and paste the body`));
  const det = el('details');
  det.append(el('summary', 'sm', 'Read the body'));
  det.append(el('pre', 'log', esc(f.body)));
  card.append(det);
  const row = el('div', 'row');
  const a = el('a', 'btn', '🔗 Open form');
  a.href = f.url; a.target = '_blank'; a.rel = 'noopener';
  row.append(a);
  row.append(mk('📋 Copy body', () => copy(f.body), 'ghost'));
  row.append(mk('📋 Copy subject', () => copy(f.subject), 'ghost sm'));
  row.append(mk(f.sent ? '↩ Not done' : '✓ Mark done',
    () => markSent(f.url, !f.sent), 'ghost sm'));
  row.append(mk('🗑 Delete', () => delNotice({ form_url: f.url }, f.provider, f.count),
    'ghost sm danger'));
  card.append(row);
  return card;
}

/* Deleting the draft alone would leave its URLs stamped reported_utc with nothing
   to show for it, and the next reporting pass would treat them as done. */
async function delNotice(payload, who, n) {
  if (!await ask(`Delete the notice to ${who}?`,
    `<p>The draft goes, and its ${n} URL(s) go back to <b>un-reported</b> so the next ` +
    'reporting pass picks them up again.</p>' +
    '<p class="muted sm">If you already sent it, deleting the draft does not unsend ' +
    'it — the contact stays in LOG.csv.</p>')) return;
  const r = await fetch('/api/notices/delete', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return toast(j.detail || 'failed');
  toast(`Deleted — ${j.unreported} URL(s) back to un-reported.`);
  loadNotices(); refresh();
}

async function markSent(file, sent) {
  await fetch('/api/notices/sent', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file, sent }),
  });
  loadNotices(); refresh();
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied — paste it into your mail app.');
  } catch {
    // Clipboard API needs a secure context and can still be refused.
    const t = el('textarea'); t.value = text;
    t.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    document.body.append(t); t.select();
    toast(document.execCommand('copy') ? 'Copied.' : 'Could not copy — select it by hand.');
    t.remove();
  }
}

function toast(msg) {
  const t = el('div', '', esc(msg));
  t.style.cssText = 'position:fixed;left:50%;bottom:76px;transform:translateX(-50%);' +
    'background:#0b0d11;border:1px solid var(--line);padding:.6rem 1rem;border-radius:9px;' +
    'z-index:20;font-size:.85rem;max-width:90%';
  document.body.append(t);
  setTimeout(() => t.remove(), 2600);
}

/* ─────────────────────────── files ─────────────────────────── */
function drawFiles() {
  const have = new Set(S.artifacts.map(a => a.path));
  const q = $('#quicklinks'); q.innerHTML = '';
  QUICK.filter(([p]) => have.has(p)).forEach(([p, label]) => {
    const it = el('div', 'item');
    const row = el('div', 'row', `<h3>${esc(label)}</h3>`);
    row.append(mk('Open', () => view(p), 'ghost sm'));
    it.append(row, el('p', 'muted sm', esc(p)));
    q.append(it);
  });
  if (!q.children.length)
    q.innerHTML = '<p class="muted sm">Nothing generated yet.</p>';

  const f = $('#files'); f.innerHTML = '';
  if (!S.artifacts.length) { f.innerHTML = '<p class="muted sm">Empty.</p>'; return; }
  S.artifacts.forEach(a => {
    const row = el('div', 'item');
    const r = el('div', 'row', `<span class="brk">${esc(a.path)}</span>`);
    r.append(el('span', 'muted sm', kb(a.size)));
    const raw = /\.(html?|tsq|tsr|pem|crt|eml)$/i.test(a.path);
    if (raw) {
      const d = el('a', 'btn ghost sm', '⬇');
      d.href = '/artifact/' + a.path + '?raw=1'; r.append(d);
    } else {
      r.append(mk('Open', () => view(a.path), 'ghost sm'));
    }
    row.append(r); f.append(row);
  });
}
const kb = n => n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB';

async function view(p) {
  const r = await fetch('/artifact/' + p);
  $('#viewer').innerHTML = await r.text();
  $('#viewer-title').textContent = p;
  $('#viewer-card').hidden = false;
  go('files');
  $('#viewer-card').scrollIntoView({ behavior: 'smooth' });
}
function closeViewer() { $('#viewer-card').hidden = true; }

/* ─────────────────────────── identity ─────────────────────────── */
const FIELDS = ['name','email','send_from','postal','portal_ack'];
const CHECKS = ['india','eu','self_recorded'];

function openIdentity() {
  FIELDS.forEach(k => $('#f-' + k).value = CFG[k] || '');
  CHECKS.forEach(k => $('#f-' + k).checked = !!CFG[k]);
  $('#ident-err').hidden = true;
  syncPostal();
  identity.showModal();
}
$('#f-self_recorded').onchange = syncPostal;
function syncPostal() { $('#postal-req').hidden = !$('#f-self_recorded').checked; }

async function saveIdentity() {
  const body = {};
  FIELDS.forEach(k => body[k] = $('#f-' + k).value.trim());
  CHECKS.forEach(k => body[k] = $('#f-' + k).checked);
  const err = m => { $('#ident-err').textContent = m; $('#ident-err').hidden = false; };
  if (!body.name)  return err('Your full name is required.');
  if (!body.email) return err('A reply-to email is required.');
  if (body.self_recorded && !body.postal)
    return err('A postal address is required for a self-recorded (DMCA) claim — ' +
               'it is sworn under penalty of perjury.');
  const r = await fetch('/api/config', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok) return err(j.detail || 'could not save');
  identity.close(); refresh();
}
async function saveCfg(patch) {
  await fetch('/api/config', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  });
}

function ask(title, html) {
  $('#c-title').textContent = title;
  $('#c-body').innerHTML = html;
  confirmdlg.showModal();
  return new Promise(res => {
    // Drop the cancel handler first: close() fires `close` on its own, and which of
    // the two resolves first must not decide the answer.
    $('#c-ok').onclick = () => { confirmdlg.onclose = null; confirmdlg.close(); res(true); };
    confirmdlg.onclose = () => res(false);
  });
}

/* ─────────────────────────── boot ─────────────────────────── */
refresh().then(() => { if (S.needs_identity && S.urls) openIdentity(); });
connect();
