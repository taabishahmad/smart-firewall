// shared front-end helpers
const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';

async function api(path, opts = {}) {
  const options = Object.assign({ headers: {} }, opts);
  options.headers['X-CSRFToken'] = CSRF;
  if (opts.body) options.headers['Content-Type'] = 'application/json';
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

function post(path, payload) {
  return api(path, { method: 'POST', body: JSON.stringify(payload || {}) });
}

function toast(message, kind = 'ok') {
  const host = document.getElementById('toastHost');
  if (!host) return;
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity .3s';
    setTimeout(() => el.remove(), 300);
  }, 3600);
}

// mobile sidebar
(function () {
  const sidebar = document.getElementById('sidebar');
  const scrim = document.getElementById('scrim');
  const toggle = document.getElementById('menuToggle');
  if (!toggle) return;
  const open = () => { sidebar.classList.add('open'); scrim.classList.add('show'); };
  const close = () => { sidebar.classList.remove('open'); scrim.classList.remove('show'); };
  toggle.addEventListener('click', () => sidebar.classList.contains('open') ? close() : open());
  scrim && scrim.addEventListener('click', close);
})();

// keep the sidebar engine chip fresh everywhere
async function refreshEngineChip() {
  try {
    const d = await api('/api/overview');
    const s = d.snapshot || {};
    const dot = document.getElementById('engineDot');
    const state = document.getElementById('engineState');
    if (state) state.textContent = s.capturing ? 'capturing' : (s.source_status || 'idle');
    if (dot) dot.className = 'dot ' + (s.capturing ? 'dot-live' : 'dot-idle');
    const model = document.getElementById('engineModel');
    const enf = document.getElementById('engineEnforce');
    if (model) model.textContent = s.model || '—';
    if (enf) enf.textContent = s.enforcement || '—';
  } catch (e) { /* ignore transient */ }
}

if (document.getElementById('engineChip')) {
  refreshEngineChip();
  setInterval(refreshEngineChip, 5000);
}

function fmtUptime(sec) {
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  return `${h}h ${m}m ${s}s`;
}
