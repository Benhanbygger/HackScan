'use strict';
const root = document.querySelector('#app');
const csrf = root.dataset.csrf;
const el = id => document.getElementById(id);
const labels = {pending:'Afventer kontrol',review:'Bør undersøges',ok:'Samme domæne',error:'Kontrolfejl',http_error:'HTTP-fejl',cancelled:'Stoppet'};
const phases = {idle:'Klar til scanning',metadata:'Henter indeksoversigt',discovery:'Finder danske forsider',scan:'Kontrollerer viderestillinger',done:'Scanning afsluttet',failed:'Scanning afbrudt',stopped:'Scanning stoppet'};
let rows = [], busy = false, timer, queuedAction = null;
function schedule() {
  busy=false;
  if (queuedAction) { const next=queuedAction; queuedAction=null; timer=setTimeout(()=>action(next),0); }
  else timer=setTimeout(cycle,1600);
}
async function api(action, post = false) {
  const response = await fetch('index.php?api=' + action, {method:post?'POST':'GET', headers:post?{'X-CSRF-Token':csrf}:{}, credentials:'same-origin'});
  if (response.status === 401) { location.reload(); throw Error('Log ind igen'); }
  const data = await response.json();
  if (!response.ok) throw Error(data.error || 'Serveren kunne ikke behandle forespørgslen');
  return data;
}
function render() {
  const filter = el('filter').value; const tbody = el('rows'); tbody.replaceChildren();
  for (const row of rows.filter(r => filter==='all' || (filter==='errors'?['error','http_error'].includes(r.status):r.status===filter))) {
    const tr = document.createElement('tr');
    for (const value of [row.domain,row.current_url,labels[row.status] || row.status,row.checked_at]) {
      const td = document.createElement('td'); td.textContent=value; tr.append(td);
    }
    tr.children[2].className=row.status==='review'?'flag':'';
    const small = document.createElement('small'); small.textContent=row.detail; tr.children[2].append(small);
    tbody.append(tr);
  }
  if (!tbody.children.length) { const tr=document.createElement('tr'); const td=document.createElement('td'); td.colSpan=4; td.textContent='Ingen resultater i denne visning.'; tr.append(td); tbody.append(tr); }
}
async function refresh() {
  const data = await api('state'); rows=data.results; render();
  el('start').disabled=data.state.running; el('stop').hidden=!data.state.running;
  el('state').textContent=`${phases[data.state.phase] || data.state.phase} · ${data.state.checked} færdigkontrolleret i seneste scanning`;
  el('error').textContent=data.state.error; el('notice').textContent=data.state.notice;
  el('total').textContent=Object.values(data.counts).reduce((a,b)=>a+b,0);
  el('review').textContent=data.counts.review || 0;
  el('errors').textContent=(data.counts.error || 0)+(data.counts.http_error || 0);
  return data.state.running;
}
async function cycle() {
  if (busy) return;
  busy=true;
  try { if (await refresh()) { await api('tick',true); await refresh(); } }
  catch(e) { el('error').textContent=e.message; }
  finally { schedule(); }
}
async function action(name) {
  clearTimeout(timer);
  if (busy) { queuedAction=name; el('notice').textContent='Handlingen udføres, når den igangværende kontrol er afsluttet.'; return; }
  busy=true;
  try { await api(name,true); await refresh(); }
  catch(e) { el('error').textContent=e.message; }
  finally { schedule(); }
}
el('start').onclick=()=>action('start'); el('stop').onclick=()=>action('stop'); el('filter').onchange=render;
el('logout').onclick=async()=>{ try { await api('logout',true); location.reload(); } catch(e) { el('error').textContent=e.message; } };
cycle();
