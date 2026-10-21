'use strict';
const root = document.querySelector('#app');
const csrf = root.dataset.csrf;
const el = id => document.getElementById(id);
const keys = ['all', 'review', 'ok', 'errors'];
const labels = {pending:'Afventer',review:'Bør undersøges',ok:'Samme domæne',error:'Kontrolfejl',http_error:'HTTP-fejl',cancelled:'Stoppet'};
const phases = {idle:'Klar til scanning',metadata:'Henter indeksoversigt',inventory:'Finder startposition',seek:'Finder startposition',discovery:'Finder danske forsider',scan:'Kontrollerer viderestillinger',done:'Scanning afsluttet',failed:'Scanning afbrudt',stopped:'Scanning stoppet'};
let groups = {}, busy = false, timer, queuedAction = null, searchTimer, initialized = false;
const pages = Object.fromEntries(keys.map(key => [key, 0]));
function schedule() {
  busy = false;
  if (queuedAction) { const next = queuedAction; queuedAction = null; timer = setTimeout(() => action(next), 0); }
  else timer = setTimeout(cycle, 1600);
}
async function api(action, post = false) {
  const params = new URLSearchParams({api:action});
  if (action === 'state') {
    params.set('q', el('search').value);
    for (const key of keys) params.set('page_' + key, pages[key]);
  }
  const options = {method:post?'POST':'GET', headers:post?{'X-CSRF-Token':csrf}:{}, credentials:'same-origin'};
  if (action === 'start') options.body = new URLSearchParams({limit:el('scan-limit').value, start_char:el('start-char').value});
  const response = await fetch('index.php?' + params, options);
  if (response.status === 401) { location.reload(); throw Error('Log ind igen'); }
  const data = await response.json();
  if (!response.ok) throw Error(data.error || 'Serveren kunne ikke behandle forespørgslen');
  return data;
}
function cell(value, className) {
  const node = document.createElement('td'); node.textContent = value;
  if (className) node.className = className;
  return node;
}
function renderGroup(key) {
  const group = groups[key]; if (!group) return;
  pages[key] = group.page;
  const body = el('rows-' + key); body.replaceChildren();
  for (const row of group.rows) {
    const tr = document.createElement('tr');
    const domain = cell(row.domain, 'domain-cell');
    const time = document.createElement('small'); time.textContent = row.checked_at + ' UTC'; domain.append(time);
    const destination = cell(row.current_url, 'url-cell');
    const status = document.createElement('td');
    const badge = document.createElement('span'); badge.className = 'status-badge ' + (row.status==='http_error'?'error':row.status); badge.textContent = labels[row.status] || row.status;
    const detail = document.createElement('small'); detail.textContent = row.detail;
    status.append(badge, detail); tr.append(domain, destination, status); body.append(tr);
  }
  if (!body.children.length) {
    const tr = document.createElement('tr'); const td = cell(el('search').value ? 'Ingen resultater matcher søgningen.' : 'Ingen resultater i denne kategori endnu.', 'empty-cell'); td.colSpan = 3; tr.append(td); body.append(tr);
  }
  el('count-' + key).textContent = group.total.toLocaleString('da-DK');
  const from = group.total ? group.page * 8 + 1 : 0;
  el('range-' + key).textContent = `${from}–${Math.min((group.page + 1) * 8, group.total)} af ${group.total.toLocaleString('da-DK')}`;
  document.querySelectorAll(`[data-page="${key}"]`).forEach(button => {
    button.disabled = Number(button.dataset.direction) < 0 ? group.page === 0 : group.page + 1 >= group.pages;
  });
}
function chart(counts) {
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const metrics = {review:counts.review || 0, ok:counts.ok || 0, errors:(counts.error || 0)+(counts.http_error || 0)};
  el('total').textContent = el('chart-total').textContent = total.toLocaleString('da-DK');
  el('review').textContent = metrics.review.toLocaleString('da-DK');
  el('same').textContent = metrics.ok.toLocaleString('da-DK');
  el('errors').textContent = metrics.errors.toLocaleString('da-DK');
  const circumference = 2 * Math.PI * 46; let offset = 0;
  for (const key of ['review', 'ok', 'errors']) {
    const ratio = total ? metrics[key] / total : 0;
    el('arc-' + key).setAttribute('stroke-dasharray', `${ratio * circumference} ${circumference}`);
    el('arc-' + key).setAttribute('stroke-dashoffset', -offset);
    offset += ratio * circumference;
    el('pct-' + key).textContent = (ratio * 100).toLocaleString('da-DK', {maximumFractionDigits:1}) + '%';
  }
  const other = total - metrics.review - metrics.ok - metrics.errors;
  el('pct-other').textContent = (total ? other * 100 / total : 0).toLocaleString('da-DK', {maximumFractionDigits:1}) + '%';
}
async function refresh() {
  const requestedPages = {...pages}, requestedSearch = el('search').value;
  const data = await api('state');
  if (requestedSearch !== el('search').value || keys.some(key => requestedPages[key] !== pages[key])) return data.state.running;
  groups = data.groups;
  for (const key of keys) renderGroup(key);
  chart(data.counts);
  if (!initialized) {
    el('scan-limit').value = data.state.target;
    el('start-char').value = data.state.start_char;
    initialized = true;
  }
  el('start').disabled = el('scan-limit').disabled = el('start-char').disabled = data.state.running;
  el('stop').hidden = !data.state.running;
  el('live-status').textContent = data.state.running ? 'Scanning aktiv' : 'Klar til scanning';
  el('live-status').classList.toggle('running', data.state.running);
  const checking = ['scan', 'done', 'stopped', 'failed'].includes(data.state.phase);
  const found = data.state.pending + data.state.checked;
  const goal = checking && !['stopped', 'failed'].includes(data.state.phase) ? found || data.state.target : data.state.target;
  const value = checking ? data.state.checked : data.state.pending;
  el('state').textContent = `${phases[data.state.phase] || data.state.phase}${checking ? ' · ' + data.state.checked + ' kontrolleret' : ''}`;
  el('progress-label').textContent = `${value.toLocaleString('da-DK')} / ${goal.toLocaleString('da-DK')}`;
  el('progress').value = goal ? Math.min(100, 100 * value / goal) : 0;
  el('error').textContent = data.state.error;
  el('notice').textContent = data.state.notice;
  return data.state.running;
}
async function cycle() {
  if (busy) return;
  busy = true;
  try { if (await refresh()) { await api('tick', true); await refresh(); } }
  catch (e) { el('error').textContent = e.message; }
  finally { schedule(); }
}
async function action(name) {
  clearTimeout(timer);
  if (busy) { queuedAction = name; el('notice').textContent = 'Handlingen udføres efter den igangværende kontrol.'; return; }
  busy = true;
  try { await api(name, true); await refresh(); }
  catch (e) { el('error').textContent = e.message; }
  finally { schedule(); }
}
el('scan-form').onsubmit = event => { event.preventDefault(); if (el('scan-form').reportValidity()) action('start'); };
el('stop').onclick = () => action('stop');
el('search').oninput = () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { for (const key of keys) pages[key] = 0; if (!busy) { clearTimeout(timer); cycle(); } }, 300);
};
document.querySelectorAll('[data-page]').forEach(button => button.onclick = () => {
  pages[button.dataset.page] += Number(button.dataset.direction);
  if (!busy) { clearTimeout(timer); cycle(); }
});
el('logout').onclick = async () => { try { await api('logout', true); location.reload(); } catch (e) { el('error').textContent = e.message; } };
cycle();
