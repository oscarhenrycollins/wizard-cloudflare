'use strict';
// Cloudflare, connect-only: sign in here; your Wizard does the rest. Connector pattern: status card, accounts,
// what is in use (websites, storage, domains), one primary action, details. Approvals appear only when your
// Wizard has prepared a change. Secrets never reach this page.
const $ = id => document.getElementById(id);
let csrf = '', home = null, popup = null, timer = null, busy = false, sheetKey = '';
const metrics = new Map();

function el(tag, text, cls) { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; }
function btn(text, fn, cls) { const n = el('button', text, cls); n.type = 'button'; n.addEventListener('click', fn); return n; }
function say(text) { $('status').textContent = text || ''; }
const SVG = 'http://www.w3.org/2000/svg';
const ICONS = { websites: 'M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zM3 9h18M9 9v11', storage: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zm0 0v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3', domains: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm-9 9h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z', account: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-7 8c0-3.3 3.1-6 7-6s7 2.7 7 6', spark: 'M12 2l2.4 6.9L21 12l-6.6 3.1L12 22l-2.4-6.9L3 12l6.6-3.1z' };
function icon(name) { const s = document.createElementNS(SVG, 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('aria-hidden', 'true'); const p = document.createElementNS(SVG, 'path'); p.setAttribute('d', ICONS[name]); s.append(p); return s; }
function tile(name, cls) { const t = el('span', undefined, 'wz-tile' + (cls ? ' ' + cls : '')); t.append(icon(name)); return t; }
function main(title, sub) { const m = el('span', undefined, 'wz-main'); m.append(el('b', title)); if (sub) m.append(el('small', sub)); return m; }
function pill(text, kind) { return el('span', text, 'wz-pill ' + kind); }
async function api(path, body) {
  const init = { credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (body !== undefined) { init.method = 'POST'; init.headers['Content-Type'] = 'application/json'; init.headers['X-CSRF-Token'] = csrf; init.body = JSON.stringify(body); }
  const r = await fetch(path, init); let v = {}; try { v = await r.json(); } catch (_) {}
  if (!r.ok) throw Object.assign(Error(v.error?.message || 'Something went wrong.'), { code: v.error?.code });
  return v;
}
function size(n) { if (typeof n !== 'number') return ''; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; } return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`; }
const shortName = name => String(name).replace(/'s Account$/i, '');
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

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
const accountsOf = () => home ? home.connections.flatMap(c => c.accounts.map(a => ({ c, a, key: `${c.id}/${a.id}` }))) : [];
const needsSignIn = c => home.writes_allowed && home.can_change?.[c.id] === false;
function renderHome(waiting) {
  const connected = home.connections.length > 0, keep = new Set();
  for (const { c, a, key } of accountsOf()) { keep.add(key); load(c, a, key); }
  for (const key of metrics.keys()) if (!keep.has(key)) metrics.delete(key);
  renderStatus(waiting);
  $('accounts-sec').hidden = !connected; $('sections').hidden = !connected; $('new-hint').hidden = connected || waiting;
  $('signin').hidden = waiting; $('cancel').hidden = !waiting;
  $('signin').textContent = connected ? 'Add account' : 'Connect';
  $('signin').disabled = !home.signin.available;
  // One accent button per screen: while an approval waits, Approve is the accent.
  $('signin').classList.toggle('secondary', home.approvals.length > 0);
  renderAccounts(); renderSections(); renderDetails();
  if (sheetKey && $('account-sheet').open) renderSheet(sheetKey);
}
function renderStatus(waiting) {
  const connected = home.connections.length > 0;
  const attention = connected && (home.connections.some(needsSignIn) || [...metrics.values()].some(m => m.value?.error));
  const p = $('pill');
  p.className = 'wz-pill ' + (attention ? 'warn' : connected ? 'ok' : 'off');
  p.textContent = attention ? 'Needs attention' : connected ? 'Connected' : 'Not connected';
  $('line').textContent = waiting ? 'Waiting for Cloudflare…'
    : !connected && !home.signin.available ? 'Sign-in unavailable'
    : home.connections.some(needsSignIn) ? 'Sign in again to let your Wizard make changes'
    : 'Publish sites, back up files, find domains';
}
function summary(m) {
  if (!m) return 'Loading…';
  // R2 answers "unauthorized" on accounts that never turned it on, so a blocked read counts as not in use here.
  if (m.error) return 'Usage unavailable right now';
  const n = v => (typeof v === 'number' ? v : 0), parts = [];
  if (n(m.websites)) parts.push(plural(m.websites, 'website'));
  if (n(m.buckets)) parts.push(typeof m.storage?.bytes === 'number' ? `${size(m.storage.bytes)} stored` : plural(m.buckets, 'bucket'));
  if (n(m.domains)) parts.push(plural(m.domains, 'domain'));
  return parts.join(' · ') || 'Nothing set up yet';
}
function accountPill(c, m) {
  if (needsSignIn(c)) return pill('Sign in again', 'warn');
  if (m?.error) return pill('Couldn’t load', 'warn');
  return pill('Active', 'ok');
}
function renderAccounts() {
  const list = $('accounts'), all = accountsOf(), many = home.connections.length > 1;
  $('account-count').textContent = all.length; list.replaceChildren();
  for (const { c, a, key } of all) {
    const m = metrics.get(key)?.value, li = el('li'), row = el('button', undefined, 'wz-row'); row.type = 'button'; row.dataset.key = key;
    row.append(tile('account'), main(shortName(a.name), (many ? c.name + ' · ' : '') + summary(m)), accountPill(c, m));
    row.title = a.name; row.addEventListener('click', () => openSheet(key)); li.append(row); list.append(li);
  }
}
const SECTIONS = [
  { id: 'websites', title: 'Websites', count: m => m.websites, text: m => m.websites ? plural(m.websites, 'website') : 'None yet', prompt: 'Publish my website' },
  { id: 'storage', title: 'Backups', count: m => m.buckets, text: m => m.buckets ? (typeof m.storage?.bytes === 'number' ? `${size(m.storage.bytes)} in ${plural(m.buckets, 'bucket')}` : plural(m.buckets, 'bucket')) : 'None yet', prompt: 'Back up my files' },
  { id: 'domains', title: 'Domains', count: m => m.domains, text: m => m.domains ? plural(m.domains, 'domain') : 'None yet', prompt: 'Find a domain' },
];
function renderSections() {
  const box = $('sections'); box.replaceChildren();
  for (const s of SECTIONS) {
    const sec = el('section', undefined, 'wz-sec'); sec.dataset.section = s.id;
    const h = el('h2', s.title, 'wz-sec-h'); let total = 0;
    const list = el('ul', undefined, 'wz-list');
    for (const { a, key } of accountsOf()) {
      const m = metrics.get(key)?.value, n = m && !m.error && typeof s.count(m) === 'number' ? s.count(m) : 0; total += n;
      const li = el('li'), row = el('div', undefined, 'wz-row');
      row.append(tile(s.id, n ? '' : 'none'), main(!m ? '…' : m.error ? 'Couldn’t load' : s.text(m), shortName(a.name))); li.append(row); list.append(li);
    }
    const ask = el('li'), go = el('button', undefined, 'wz-row cf-ask-row'); go.type = 'button';
    go.append(tile('spark', 'cf-spark'), main(s.prompt, 'Ask your Wizard')); go.addEventListener('click', () => askWizard(s.prompt)); ask.append(go); list.append(ask);
    h.append(el('span', total, 'wz-count')); sec.append(h, list); box.append(sec);
  }
}
function renderDetails() {
  const box = $('details'); box.replaceChildren();
  box.append(el('p', home.writes_allowed ? 'Changes are on. Each one waits for you to approve it here.' : 'Changes are switched off on this box.'));
  for (const c of home.connections) {
    box.append(el('p', `Login: ${c.name} (${c.id})`));
    for (const a of c.accounts) box.append(el('p', `Account: ${a.name} · ${a.id}`));
  }
  if (home.signin.status) box.append(el('p', `Last sign-in: ${home.signin.status}`));
}
async function load(c, a, key) {
  const have = metrics.get(key); if (have && (have.pending || Date.now() - have.at < 60000)) return;
  metrics.set(key, { pending: true, at: Date.now(), value: have?.value });
  let value;
  try { value = await api(`api/metrics?${new URLSearchParams({ connection_id: c.id, account_id: a.id })}`); }
  catch (e) { value = { error: e.code || 'unavailable' }; }
  metrics.set(key, { at: Date.now(), value });
  if (home) { renderStatus(home.signin.status === 'pending' || home.signin.status === 'exchanging'); renderAccounts(); renderSections(); if (sheetKey === key && $('account-sheet').open) renderSheet(key); }
}

// ---------- account sheet (rare actions: sign in again, sign out) ----------
function openSheet(key) { sheetKey = key; renderSheet(key); window.WzSheet ? WzSheet.open($('account-sheet')) : $('account-sheet').showModal(); }
function closeSheet() { const d = $('account-sheet'); window.WzSheet ? WzSheet.close(d) : d.open && d.close(); }
function renderSheet(key, confirming) {
  const found = accountsOf().find(x => x.key === key), body = $('account-sheet-body'); body.replaceChildren();
  if (!found) { closeSheet(); return; }
  const { c, a } = found, m = metrics.get(key)?.value;
  $('account-sheet-h').textContent = shortName(a.name);
  const sub = home.connections.length > 1 ? c.name : a.name !== shortName(a.name) ? a.name : '';
  if (sub) body.append(el('p', sub, 'cf-sheet-sub'));
  if (confirming) {
    body.append(el('p', home.connections.length > 1 ? `Sign out ${c.name}?` : 'Sign out of Cloudflare?', 'cf-sheet-note'));
    const acts = el('div', undefined, 'wz-actions');
    acts.append(btn('Sign out', () => signOut(c), 'wz-button'), btn('Cancel', () => renderSheet(key), 'wz-button secondary'));
    body.append(acts); return;
  }
  const list = el('ul', undefined, 'wz-list');
  for (const s of SECTIONS) { const li = el('li'), row = el('div', undefined, 'wz-row'); const n = m && !m.error ? s.count(m) : 0; row.append(tile(s.id, n ? '' : 'none'), main(!m ? '…' : m.error ? 'Couldn’t load' : s.text(m), s.title)); li.append(row); list.append(li); }
  body.append(list);
  const acts = el('div', undefined, 'wz-actions');
  if (needsSignIn(c)) { body.append(el('p', 'Sign in again to let your Wizard make changes', 'cf-sheet-note')); acts.append(btn('Sign in again', () => { closeSheet(); signIn(); }, 'wz-button')); }
  acts.append(btn(home.connections.length > 1 ? `Sign out ${c.name}` : 'Sign out', () => renderSheet(key, true), 'wz-button secondary cf-danger'));
  body.append(acts);
}

// ---------- actions ----------
async function askWizard(text) {
  let shared = false;
  try { if (window.WizardApp?.chat?.prompt) shared = await window.WizardApp.chat.prompt(text) === true; } catch (_) {}
  if (!shared) {
    try { await navigator.clipboard.writeText(text); say('Copied. Paste it in your Wizard chat.'); }
    catch (_) { say(`Ask your Wizard: “${text}”`); }
  }
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
  closeSheet();
  try { await api(`api/connections/${c.id}/disconnect`, {}); await refresh(); } catch (e) { say(e.message); }
}

// ---------- approvals (only when something is waiting) ----------
function renderApprovals() {
  const box = $('approval-list'); box.replaceChildren(); $('approvals').hidden = !home.approvals.length; $('approval-count').textContent = home.approvals.length;
  home.approvals.forEach((a, i) => {
    const card = el('div', undefined, 'cf-ask');
    card.append(el('p', `Your Wizard wants to ${a.text}`, 'cf-ask-text'));
    const where = home.connections.flatMap(c => c.accounts).find(x => x.id === a.account_id);
    if (where) card.append(el('p', shortName(where.name), 'cf-ask-where'));
    const acts = el('div', undefined, 'wz-actions');
    acts.append(btn('Approve', () => decide(a, true), 'wz-button' + (i ? ' secondary' : '')), btn('Decline', () => decide(a, false), 'wz-button secondary'));
    const more = el('details'); more.append(el('summary', 'Details'), el('pre', JSON.stringify(a.payload, null, 2)));
    card.append(acts, more); box.append(card);
  });
}
async function decide(a, yes) {
  try {
    if (!yes) { await api(`api/approvals/${a.id}/cancel`, {}); say('Declined.'); }
    else {
      say('Working…');
      if (a.status === 'pending_review') await api(`api/approvals/${a.id}/review`, {});
      const out = await api(`api/approvals/${a.id}/confirm`, { payload_digest: a.payload_digest });
      say(out.result?.url ? `Done. Live at ${out.result.url}` : 'Done.');
      metrics.clear();
    }
  } catch (e) { say(e.code === 'writes_disabled' ? 'Changes are switched off on this box.' : e.message); }
  await refresh();
}

// ---------- wiring ----------
$('signin').onclick = signIn; $('cancel').onclick = () => { void cancel(); };
// Defined before wizard-sheet.js loads: the sheet closes first on Back, then this handler cancels a waiting sign-in.
window.__wizardCloseOverlay = () => {
  if (home && (home.signin.status === 'pending' || home.signin.status === 'exchanging')) { void cancel(); return true; }
  return false;
};
window.addEventListener('focus', () => { if (csrf) refresh().catch(() => {}); });
document.addEventListener('visibilitychange', () => { if (!document.hidden && csrf) refresh().catch(() => {}); });
fetch('api/session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Wizard-Request': 'bootstrap' }, body: '{}' })
  .then(async r => { const v = await r.json(); if (!r.ok) throw Error(v.error?.message || 'Unavailable.'); csrf = v.csrf; return refresh(); })
  .catch(e => say(e.message));
