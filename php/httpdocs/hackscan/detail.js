'use strict';
const report = document.querySelector('#report');
function filterChecks(filter) {
  let visible = 0;
  document.querySelectorAll('[data-check-state]').forEach(card => {
    const state = card.dataset.checkState;
    card.hidden = !(filter === 'all' || (filter === 'unknown' ? ['unknown','not_tested'].includes(state) : state === filter));
    if (!card.hidden) visible++;
  });
  document.querySelectorAll('[data-check-filter]').forEach(button => {
    const selected = button.dataset.checkFilter === filter;
    button.classList.toggle('selected', selected); button.setAttribute('aria-pressed', String(selected));
  });
  const empty = document.querySelector('#no-checks'); if (empty) empty.hidden = visible > 0;
}
document.querySelectorAll('[data-check-filter]').forEach(button => button.onclick = () => filterChecks(button.dataset.checkFilter));
filterChecks('finding');
document.querySelector('#reassess').onclick = async () => {
  const button = document.querySelector('#reassess'); button.disabled = true;
  try {
    const response = await fetch('index.php?api=reassess', {method:'POST', credentials:'same-origin',headers:{'X-CSRF-Token':report.dataset.csrf},body:new URLSearchParams({domain:report.dataset.domain})});
    if (response.status === 401) { location.href = 'index.php'; return; }
    const data = await response.json(); if (!response.ok) throw Error(data.error || 'Kontrollen kunne ikke starte');
    location.href = 'index.php';
  } catch (e) { document.querySelector('#detail-message').textContent = e.message; button.disabled = false; }
};
