'use strict';
// Cloudflare, as plain as possible: sign in, pick an account, look at Storage / Workers / Domains.
// Approvals appear only when Oscar has prepared something. Secrets never reach this page.
const $ = id => document.getElementById(id);
let csrf = '', home = null, popup = null, timer = null, stack = [], seq = 0, busy = false;

function el(tag, text, cls) { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; }
function btn(text, fn, cls) { const n = el('button', text, cls); n.type = 'button'; n.addEventListener('click', fn); return n; }
function say(text) { $('status').textContent = text || ''; }
function row(title, sub, fn) {
  const n = fn ? btn('', fn, 'wz-row') : el('div', undefined, 'wz-row');
  const main = el('span', undefined, 'wz-main'); main.append(el('b', title)); if (sub) main.append(el('small', sub));
  n.append(main); if (fn) n.append(el('span', '›', 'chev')); return n;
}
async function api(path, body) {
  const init = { credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (body !== undefined) { init.method = 'POST'; init.headers['Content-Type'] = 'application/json'; init.headers['X-CSRF-Token'] = csrf; init.body = JSON.stringify(body); }
  const r = await fetch(path, init); let v = {}; try { v = await r.json(); } catch (_) {}
  if (!r.ok) throw Object.assign(Error(v.error?.message || 'Something went wrong.'), { code: v.error?.code });
  return v;
}

// ---------- home ----------
async function refresh() {
  home = await api('api/home');
  const s = home.signin || {}, waiting = s.status === 'pending' || s.status === 'exchanging';
  if (!waiting && timer) { clearTimeout(timer); timer = null; if (popup && !popup.closed) popup.close(); popup = null; }
  if (s.status === 'failed' && !waiting && !busy) say('Not connected. Try again.');
  if (s.status === 'completed') say('');
  renderApprovals(); renderHome(waiting);
  if (waiting && !timer) timer = setTimeout(poll, 2000);
}
async function poll() { timer = null; try { await refresh(); } catch (_) { timer = setTimeout(poll, 3000); } }
function renderHome(waiting) {
  const connected = home.connections.length > 0, inAccount = stack.length > 0;
  $('home').hidden = inAccount; $('account').hidden = !inAccount;
  $('waiting').hidden = !waiting; $('signed-out').hidden = waiting || connected; $('signed-in').hidden = waiting || !connected;
  $('signin').disabled = !home.signin.available; $('line').textContent = home.signin.available ? 'Not connected' : 'Sign-in unavailable';
  const list = $('accounts'); list.replaceChildren();
  const many = home.connections.length > 1;
  for (const c of home.connections) for (const a of c.accounts) list.append(row(a.name, many ? c.name : '', () => openAccount(c, a)));
  const logins = $('logins'); logins.replaceChildren();
  for (const c of home.connections) logins.append(btn(many ? `Sign out ${c.name}` : 'Sign out', () => signOut(c), 'link quiet'));
}
async function signIn() {
  if (busy) return; busy = true; say('');
  popup = window.open('about:blank', '_blank'); if (popup) popup.opener = null;
  try {
    const out = await api('api/oauth/start', {});
    const url = new URL(out.authorization_url);
    if (url.origin !== 'https://dash.cloudflare.com' || url.pathname !== '/oauth2/auth') throw Error('Unexpected sign-in page.');
    if (popup && !popup.closed) popup.location.assign(url.href); else popup = window.open(url.href, '_blank', 'noopener');
    await refresh();
  } catch (e) { if (popup && !popup.closed) popup.close(); popup = null; say(e.message); }
  finally { busy = false; }
}
async function cancel() {
  try { await api('api/oauth/cancel', {}); } catch (e) { say(e.message); return false; }
  if (popup && !popup.closed) popup.close(); popup = null; say(''); await refresh(); return true;
}
async function signOut(c) {
  if (!confirm(home.connections.length > 1 ? `Sign out ${c.name}?` : 'Sign out of Cloudflare?')) return;
  try { await api(`api/connections/${c.id}/disconnect`, {}); stack = []; await refresh(); } catch (e) { say(e.message); }
}

// ---------- approvals (only when something is waiting) ----------
function renderApprovals() {
  const box = $('approvals'); box.replaceChildren(); box.hidden = !home.approvals.length;
  for (const a of home.approvals) {
    const card = el('div', undefined, 'ask');
    card.append(el('p', `Oscar wants to ${a.text}`, 'ask-text'));
    const acts = el('div', undefined, 'ask-acts');
    acts.append(btn('Approve', () => decide(a, true), 'action primary'), btn('Decline', () => decide(a, false), 'action'));
    const more = el('details'); more.append(el('summary', 'Details'), el('pre', JSON.stringify(a.payload, null, 2)));
    card.append(acts, more); box.append(card);
  }
}
async function decide(a, yes) {
  try {
    if (!yes) { await api(`api/approvals/${a.id}/cancel`, {}); say('Declined.'); }
    else {
      if (a.status === 'pending_review') await api(`api/approvals/${a.id}/review`, {});
      await api(`api/approvals/${a.id}/confirm`, { payload_digest: a.payload_digest }); say('Done.');
    }
  } catch (e) { say(e.code === 'writes_disabled' ? 'Changes are switched off on this box.' : e.message); }
  await refresh();
}

// ---------- account → Storage / Workers / Domains ----------
function show(view) { stack.push(view); say(''); paint(); }
function back() { if (!stack.length) return false; stack.pop(); seq++; if (stack.length) paint(); else renderHome(false); return true; }
function openAccount(c, a) { stack = []; show({ kind: 'account', c, a }); }
function read(view, section, params = {}) {
  const q = new URLSearchParams({ account_id: view.a.id, section, per_page: '50', ...params });
  return api(`api/connections/${view.c.id}/resources?${q}`);
}
async function paint() {
  const v = stack[stack.length - 1], body = $('account-body'), mine = ++seq;
  $('home').hidden = true; $('account').hidden = false; body.replaceChildren();
  const head = el('div', undefined, 'crumb'); head.append(btn('‹', back, 'back'), el('h2', v.title || v.a.name)); body.append(head);
  const list = el('div', undefined, 'wz-list'); body.append(list);
  if (v.kind === 'account') {
    list.append(row('Storage', '', () => show({ ...v, kind: 'storage', title: 'Storage' })),
      row('Workers', '', () => show({ ...v, kind: 'workers', title: 'Workers' })),
      row('Domains', '', () => show({ ...v, kind: 'domains', title: 'Domains' })));
    const bill = el('a', 'Billing ↗', 'link quiet'); bill.href = `https://dash.cloudflare.com/${v.a.id}/billing`; bill.target = '_blank'; bill.rel = 'noopener noreferrer';
    const foot = el('div', undefined, 'foot'); foot.append(bill); body.append(foot); return;
  }
  if (v.kind === 'domains') {
    const form = el('form', undefined, 'find'), input = el('input', undefined, 'wz-input');
    input.type = 'search'; input.placeholder = 'Find a domain'; input.setAttribute('aria-label', 'Find a domain'); input.autocapitalize = 'none'; input.spellcheck = false;
    form.append(input); form.onsubmit = e => { e.preventDefault(); if (input.value.trim()) show({ ...v, kind: 'search', q: input.value.trim().toLowerCase(), title: input.value.trim().toLowerCase() }); };
    body.insertBefore(form, list);
  }
  list.append(el('p', '…', 'quiet pad'));
  try {
    let items = [];
    if (v.kind === 'storage') items = (await read(v, 'r2')).result.map(b => row(b.name || b, '', () => show({ ...v, kind: 'bucket', bucket: b.name || b, title: b.name || b })));
    else if (v.kind === 'bucket') items = (await read(v, 'r2_objects', { bucket: v.bucket })).result.map(o => row(o.key, size(o.size)));
    else if (v.kind === 'workers') items = (await read(v, 'workers')).result.map(w => row(w.id || w.name, ''));
    else if (v.kind === 'domains') items = (await read(v, 'zones')).result.map(z => row(z.name, '', () => show({ ...v, kind: 'records', zone: z, title: z.name })));
    else if (v.kind === 'records') items = (await read(v, 'dns', { zone: v.zone.id })).result.map(r => row(`${r.type} ${r.name}`, r.content));
    else if (v.kind === 'search') {
      const out = await api('api/registrar/search', { connection_id: v.c.id, account_id: v.a.id, q: v.q });
      const found = Array.isArray(out.result) ? out.result : (out.result?.domains || []);
      items = found.map(d => row(d.name || d.domain_name || String(d), d.registrable === true ? 'Available' : d.registrable === false ? 'Taken' : ''));
    }
    if (mine !== seq) return;
    list.replaceChildren(...(items.length ? items : [el('p', 'Nothing here', 'quiet pad')]));
  } catch (e) { if (mine === seq) list.replaceChildren(el('p', e.message, 'quiet pad')); }
}
function size(n) { if (typeof n !== 'number') return ''; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`; }

// ---------- wiring ----------
$('signin').onclick = signIn; $('add').onclick = signIn; $('cancel').onclick = () => { void cancel(); };
window.__wizardCloseOverlay = () => {
  if (home && (home.signin.status === 'pending' || home.signin.status === 'exchanging')) { void cancel(); return true; }
  return back();
};
window.addEventListener('focus', () => { if (csrf) refresh().catch(() => {}); });
document.addEventListener('visibilitychange', () => { if (!document.hidden && csrf) refresh().catch(() => {}); });
fetch('api/session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Wizard-Request': 'bootstrap' }, body: '{}' })
  .then(async r => { const v = await r.json(); if (!r.ok) throw Error(v.error?.message || 'Unavailable.'); csrf = v.csrf; return refresh(); })
  .catch(e => say(e.message));
