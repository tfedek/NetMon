const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content ?? '';

async function apiFetch(url, opts = {}) {
    opts.headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...(opts.headers || {}) };
    return fetch(url, opts);
}

function showFlash(msg, type = 'info') {
    const el = document.getElementById('flash-container');
    if (!el) return;
    el.innerHTML = `<div class="nm-alert nm-alert-${type} d-flex align-items-center gap-2 mb-3">
        <i class="bi bi-${type==='success'?'check-circle':type==='danger'?'exclamation-triangle':'info-circle'}"></i>${msg}</div>`;
    setTimeout(() => el.innerHTML = '', 4000);
}

async function checkLocation(id, cardEl) {
    try {
        const r = await apiFetch(`${appUrl}/api/locations/${id}/check`, { method: 'POST' });
        const d = await r.json();
        if (!d.success) return;
        const res = d.data;
        const cls = res.success ? 'online' : 'offline';
        cardEl.className = cardEl.className.replace(/online|offline|unknown/g, cls);
        const dot   = cardEl.querySelector('.nm-dot');
        const badge = cardEl.querySelector('.nm-badge');
        const rt    = cardEl.querySelector('.loc-rt');
        if (dot)   { dot.className = `nm-dot nm-dot-${cls}`; }
        if (badge) { badge.className = `nm-badge nm-badge-${cls}`; badge.innerHTML = `<span class="nm-dot nm-dot-${cls}"></span>${cls}`; }
        if (rt)    rt.textContent = res.response_time ? `${res.response_time} ms` : 'unreachable';
    } catch(e) { console.warn('Check failed:', e); }
}

function initDashboardRefresh() {
    const cards = document.querySelectorAll('.loc-card[data-id]');
    if (!cards.length) return;
    cards.forEach(c => checkLocation(c.dataset.id, c));
    setInterval(() => cards.forEach(c => checkLocation(c.dataset.id, c)), 300000);
}

async function deleteLocation(id) {
    if (!confirm('Obrisati ovu lokaciju? Biće obrisana i sva istorija provera.')) return;
    const r = await apiFetch(`${appUrl}/api/locations/${id}`, { method: 'DELETE' });
    const d = await r.json();
    if (d.success) { document.getElementById(`loc-row-${id}`)?.remove(); showFlash('Lokacija obrisana.', 'success'); }
    else showFlash(d.message || 'Greška pri brisanju.', 'danger');
}

document.addEventListener('DOMContentLoaded', () => {
    initDashboardRefresh();
    const pw = document.getElementById('password');
    const meter = document.getElementById('pw-strength');
    if (pw && meter) {
        pw.addEventListener('input', () => {
            const v = pw.value;
            let s = 0;
            if (v.length >= 8) s++;
            if (/[A-Z]/.test(v)) s++;
            if (/[0-9]/.test(v)) s++;
            if (/[^A-Za-z0-9]/.test(v)) s++;
            const labels = ['','Slaba','Srednja','Dobra','Jaka'];
            const colors = ['','#f85149','#d29922','#58a6ff','#3fb950'];
            meter.textContent = labels[s] || '';
            meter.style.color = colors[s] || '';
        });
    }
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el));
});
