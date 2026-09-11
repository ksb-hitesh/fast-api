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
  drawCounts(); drawTodo(); drawMini(); drawSteps(); drawFiles();
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
      `<td>${esc((r.checked || '').slice(0, 16).replace('T', ' ') || '—')}` +
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

  if (i.too_long) card.append(el('p', 'sm',
    '<span class="err">Too long for a mailto: link.</span> ' +
    '<span class="muted">Your mail app would silently cut it off — open the mail app, ' +
    'then tap <b>Copy full notice</b> and paste over the body.</span>'));

  const row = el('div', 'row');
  const mail = el('a', 'btn', '📧 Open in mail');
  mail.href = i.mailto; row.append(mail);
  row.append(mk('📋 Copy full notice', () => copy(i.body), 'ghost'));
  const dl = el('a', 'btn ghost sm', '⬇ .eml');
  dl.href = '/artifact/' + (i.kind === 'notice' ? '' : 'followup/') + i.file + '?raw=1';
  row.append(dl);
  row.append(mk(i.sent ? '↩ Not sent' : '✓ Mark sent',
    () => markSent(i.file, !i.sent), 'ghost sm'));
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
  card.append(row);
  return card;
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
  confirm.showModal();
  return new Promise(res => {
    $('#c-ok').onclick = () => { confirm.close(); res(true); };
    confirm.onclose = () => res(false);
  });
}

/* ─────────────────────────── boot ─────────────────────────── */
refresh().then(() => { if (S.needs_identity && S.urls) openIdentity(); });
connect();
