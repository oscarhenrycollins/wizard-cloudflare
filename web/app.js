'use strict';
// Cloudflare, connect-only: sign in here; your Wizard does the rest. A small at-a-glance card per account.
// Approvals appear only when your Wizard has prepared a change. Secrets never reach this page.
const $ = id => document.getElementById(id);
const PROMPTS = ['Publish my website', 'Back up my files', 'Find a domain'];
let csrf = '', home = null, popup = null, timer = null, busy = false;
const metrics = new Map();

function el(tag, text, cls) { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; }
function btn(text, fn, cls) { const n = el('button', text, cls); n.type = 'button'; n.addEventListener('click', fn); return n; }
function say(text) { $('status').textContent = text || ''; }
const SVG = 'http://www.w3.org/2000/svg';
const ICONS = { websites: 'M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zM3 9h18M9 9v11', storage: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zm0 0v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3', domains: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm-9 9h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z' };
function icon(name) { const s = document.createElementNS(SVG, 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('aria-hidden', 'true'); const p = document.createElementNS(SVG, 'path'); p.setAttribute('d', ICONS[name]); s.append(p); return s; }
async function api(path, body) {
  const init = { credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (body !== undefined) { init.method = 'POST'; init.headers['Content-Type'] = 'application/json'; init.headers['X-CSRF-Token'] = csrf; init.body = JSON.stringify(body); }
  const r = await fetch(path, init); let v = {}; try { v = await r.json(); } catch (_) {}
  if (!r.ok) throw Object.assign(Error(v.error?.message || 'Something went wrong.'), { code: v.error?.code });
  return v;
}
function size(n) { if (typeof n !== 'number') return ''; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; } return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`; }

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
  const connected = home.connections.length > 0;
  $('waiting').hidden = !waiting; $('signed-out').hidden = waiting || connected; $('signed-in').hidden = waiting || !connected;
  $('signin').disabled = !home.signin.available; $('line').textContent = home.signin.available ? 'Not connected' : 'Sign-in unavailable';
  $('reauth').hidden = !home.writes_allowed || !home.connections.some(c => home.can_change?.[c.id] === false);
  const list = $('accounts'), many = home.connections.length > 1, keep = new Set();
  list.replaceChildren();
  for (const c of home.connections) for (const a of c.accounts) { const key = `${c.id}/${a.id}`; keep.add(key); list.append(card(c, a, key, many)); load(c, a, key); }
  for (const key of metrics.keys()) if (!keep.has(key)) metrics.delete(key);
  const logins = $('logins'); logins.replaceChildren();
  for (const c of home.connections) logins.append(btn(many ? `Sign out ${c.name}` : 'Sign out', () => signOut(c), 'link quiet'));
}
const LABELS = [['websites', 'Websites'], ['storage', 'Storage'], ['domains', 'Domains']];
const shortName = name => String(name).replace(/'s Account$/i, '');
function card(c, a, key, many) {
  const box = el('article', undefined, 'acct'); box.dataset.key = key;
  const head = el('div', undefined, 'acct-h'); head.append(el('h3', shortName(a.name))); if (many) head.append(el('small', c.name));
  head.append(el('span', '', 'acct-note')); box.append(head);
  const grid = el('div', undefined, 'stats');
  for (const [name, label] of LABELS) {
    const t = el('div', undefined, 'stat'); t.dataset.metric = name;
    const ic = el('span', undefined, 'ic'); ic.append(icon(name)); t.append(ic);
    const txt = el('span', undefined, 'stat-t'); txt.append(el('b', '…'), el('small', label)); t.append(txt); grid.append(t);
  }
  box.append(grid); paintCard(box, metrics.get(key)?.value); return box;
}
function paintCard(box, m) {
  if (!box || !m) return;
  const n = v => (typeof v === 'number' ? v : null);
  const w = n(m.websites), b = n(m.buckets), d = n(m.domains), bytes = m.storage?.bytes;
  const values = { websites: w ? String(w) : '', storage: b ? (typeof bytes === 'number' ? size(bytes) : `${b}`) : '', domains: d ? String(d) : '' };
  for (const [name, label] of LABELS) {
    const t = box.querySelector(`[data-metric="${name}"]`); const v = values[name];
    const one = name !== 'storage' && v === '1';
    t.querySelector('b').textContent = v || '—'; t.querySelector('small').textContent = one ? label.slice(0, -1) : label; t.classList.toggle('none', !v);
  }
  // An account with nothing in use collapses to one quiet line; a failed read never shows an error wall.
  // R2 answers "unauthorized" on accounts that never turned it on, so a blocked read counts as not in use here.
  const empty = !m.error && [w, b, d].every(x => !x);
  box.classList.toggle('empty', empty);
  box.querySelector('.acct-note').textContent = m.error ? 'Couldn’t load' : empty ? 'Nothing set up yet' : '';
}
async function load(c, a, key) {
  const have = metrics.get(key); if (have && (have.pending || Date.now() - have.at < 60000)) return;
  metrics.set(key, { pending: true, at: Date.now(), value: have?.value });
  let value;
  try { value = await api(`api/metrics?${new URLSearchParams({ connection_id: c.id, account_id: a.id })}`); }
  catch (e) { value = { error: e.code || 'unavailable' }; }
  metrics.set(key, { at: Date.now(), value });
  paintCard(document.querySelector(`.acct[data-key="${CSS.escape(key)}"]`), value);
}
function renderPrompts() {
  const box = $('prompts'); box.replaceChildren();
  for (const text of PROMPTS) box.append(btn(text, () => ask(text), 'prompt'));
}
async function ask(text) {
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
  if (!confirm(home.connections.length > 1 ? `Sign out ${c.name}?` : 'Sign out of Cloudflare?')) return;
  try { await api(`api/connections/${c.id}/disconnect`, {}); await refresh(); } catch (e) { say(e.message); }
}

// ---------- approvals (only when something is waiting) ----------
function renderApprovals() {
  const box = $('approvals'); box.replaceChildren(); box.hidden = !home.approvals.length;
  for (const a of home.approvals) {
    const card = el('div', undefined, 'ask');
    card.append(el('p', `Your Wizard wants to ${a.text}`, 'ask-text'));
    const where = home.connections.flatMap(c => c.accounts).find(x => x.id === a.account_id);
    if (where) card.append(el('p', shortName(where.name), 'ask-where'));
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
$('signin').onclick = signIn; $('add').onclick = signIn; $('reauth-btn').onclick = signIn; $('cancel').onclick = () => { void cancel(); };
renderPrompts();
window.__wizardCloseOverlay = () => {
  if (home && (home.signin.status === 'pending' || home.signin.status === 'exchanging')) { void cancel(); return true; }
  return false;
};
window.addEventListener('focus', () => { if (csrf) refresh().catch(() => {}); });
document.addEventListener('visibilitychange', () => { if (!document.hidden && csrf) refresh().catch(() => {}); });
fetch('api/session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Wizard-Request': 'bootstrap' }, body: '{}' })
  .then(async r => { const v = await r.json(); if (!r.ok) throw Error(v.error?.message || 'Unavailable.'); csrf = v.csrf; return refresh(); })
  .catch(e => say(e.message));
