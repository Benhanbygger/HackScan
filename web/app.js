const labels = {review: 'Bør undersøges', ok: 'Samme domæne', error: 'Kunne ikke kontrolleres', http_error: 'HTTP-fejl'};
let rows = [];
function render() {
  const filter = document.querySelector('#filter').value;
  const body = document.querySelector('#results'); body.replaceChildren();
  for (const row of rows.filter(r => filter === 'all' || (filter === 'error' ? ['error','http_error'].includes(r.status) : r.status === filter))) {
    const tr = document.createElement('tr');
    for (const value of [row.domain, row.final_url || '—', `${labels[row.status]} (${row.detail})`, row.checked_at]) {
      const td = document.createElement('td'); td.textContent = value; tr.append(td);
    }
    body.append(tr);
  }
  if (!body.children.length) { const tr = document.createElement('tr'); const td = document.createElement('td'); td.colSpan = 4; td.textContent = 'Ingen resultater i denne visning.'; tr.append(td); body.append(tr); }
}
async function refresh() {
  try {
    const r = await fetch('/api/results'); if (!r.ok) throw Error('Serverfejl');
    const data = await r.json(); rows = data.results;
    document.querySelector('#scan').disabled = data.state.running;
    document.querySelector('#state').textContent = data.state.error ? `Scanning stoppet: ${data.state.error}` : data.state.running ? `Scanning kører · ${data.state.checked} kontrolleret` : `${rows.length} gemte resultater · Klar til scanning`;
    render();
  } catch(e) { document.querySelector('#state').textContent = 'Kunne ikke hente resultater. Kontrollér serveren.'; }
}
document.querySelector('#scan').onclick = async () => {
  document.querySelector('#scan').disabled = true;
  try { const r = await fetch('/api/scan', {method: 'POST', headers: {'X-HackScan':'1'}}); if (!r.ok) throw Error('Kunne ikke starte'); await refresh(); }
  catch(e) { document.querySelector('#state').textContent = e.message; document.querySelector('#scan').disabled = false; }
};
document.querySelector('#filter').onchange = render;
refresh(); setInterval(refresh, 3000);
