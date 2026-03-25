document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadHistory();
  setupInput();

  document.getElementById('runScan').addEventListener('click', runScan);
  document.getElementById('clearHistory').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ action: 'clearHistory' });
    loadHistory();
    loadStats();
  });
});

// ── stats ──────────────────────────────────────────────────────────────────
async function loadStats() {
  const s = await chrome.runtime.sendMessage({ action: 'getStats' }) || { total: 0, clean: 0, threats: 0 };
  document.getElementById('statTotal').textContent   = s.total;
  document.getElementById('statClean').textContent   = s.clean;
  document.getElementById('statThreats').textContent = s.threats;
}

// ── history ────────────────────────────────────────────────────────────────
async function loadHistory() {
  const history = await chrome.runtime.sendMessage({ action: 'getHistory' }) || [];
  const list = document.getElementById('historyList');

  if (!history.length) {
    list.innerHTML = '<div class="empty-msg">no files scanned yet</div>';
    return;
  }

  list.innerHTML = '';
  [...history].reverse().forEach(item => {
    const risk  = (item.result || {}).risk_score || 0;
    const exps  = (item.result || {}).explanations || [];
    const hash  = (item.result || {}).hash || '';
    const threats = (item.result || {}).threats || [];

    let tag, tagClass;
    if (risk >= 60)      { tag = '[THREAT]'; tagClass = 'threat'; }
    else if (risk >= 20) { tag = '[WARN]';   tagClass = 'warn'; }
    else                 { tag = '[OK]';     tagClass = 'ok'; }

    const row = document.createElement('div');
    row.className = 'h-row';
    row.innerHTML = `
      <span class="h-time">${formatTime(item.timestamp)}</span>
      <span class="h-name">${esc(item.filename || 'unknown')}</span>
      <span class="tag ${tagClass}">${tag}</span>
    `;

    const detail = document.createElement('div');
    detail.className = 'h-detail';
    detail.innerHTML = buildDetail(item, risk, hash, exps, threats);

    row.addEventListener('click', () => row.classList.toggle('open'));

    list.appendChild(row);
    list.appendChild(detail);
  });
}

function buildDetail(item, risk, hash, exps, threats) {
  const lines = [];
  const path = item.path || item.filename || 'unknown';
  lines.push(treeLine('├─', 'path', esc(path)));
  lines.push(treeLine('├─', 'risk', `${risk}%`));
  if (hash) lines.push(treeLine('├─', 'sha256', hash.slice(0, 16) + '…'));
  if (exps.length) {
    lines.push(treeLine('├─', 'reasons', ''));
    exps.forEach((e, i) => {
      const sym = i === exps.length - 1 && !threats.length ? '└─' : '├─';
      lines.push(`<div class="tree-line" style="padding-left:12px">${sym} <span>${esc(e)}</span></div>`);
    });
  }
  if (threats.length) {
    lines.push(treeLine('└─', 'threats', ''));
    threats.forEach((t, i) => {
      const sym = i === threats.length - 1 ? '└─' : '├─';
      lines.push(`<div class="tree-line threat-name" style="padding-left:12px">${sym} <span>${esc(t)}</span></div>`);
    });
  }
  return lines.join('');
}

function treeLine(sym, key, val) {
  return `<div class="tree-line">${sym} ${key}${val ? '&nbsp;&nbsp;<span>' + val + '</span>' : ''}</div>`;
}

// ── scan with progress bar ─────────────────────────────────────────────────
async function runScan() {
  const wrap = document.getElementById('progressWrap');
  const link = document.getElementById('runScan');
  link.style.display = 'none';
  wrap.classList.add('active');

  let pct = 0;
  const iv = setInterval(() => {
    pct = Math.min(pct + Math.random() * 18, 95);
    renderBar(pct);
  }, 220);

  await chrome.runtime.sendMessage({ action: 'quickScan' });

  clearInterval(iv);
  renderBar(100);

  setTimeout(() => {
    wrap.classList.remove('active');
    link.style.display = '';
    loadHistory();
    loadStats();
  }, 600);
}

function renderBar(pct) {
  const total = 20;
  const filled = Math.round((pct / 100) * total);
  document.getElementById('barFilled').textContent = '█'.repeat(filled);
  document.getElementById('barEmpty').textContent  = '░'.repeat(total - filled);
  document.getElementById('barPct').textContent    = Math.round(pct) + '%';
}

// ── command input ──────────────────────────────────────────────────────────
function setupInput() {
  document.getElementById('cmdInput').addEventListener('keydown', async e => {
    if (e.key !== 'Enter') return;
    const val = e.target.value.trim().toLowerCase();
    e.target.value = '';
    if (val === 'scan')  runScan();
    if (val === 'clear') {
      await chrome.runtime.sendMessage({ action: 'clearHistory' });
      loadHistory(); loadStats();
    }
    if (val === 'help') {
      // echo help into history area briefly
      const list = document.getElementById('historyList');
      const msg = document.createElement('div');
      msg.className = 'empty-msg';
      msg.style.color = 'var(--muted)';
      msg.textContent = 'commands: scan · clear · help';
      list.prepend(msg);
      setTimeout(() => msg.remove(), 3000);
    }
  });
}

// ── helpers ────────────────────────────────────────────────────────────────
function esc(t) {
  const d = document.createElement('div');
  d.textContent = t;
  return d.innerHTML;
}

function formatTime(ts) {
  if (!ts) return '--:--';
  const diff = Date.now() - ts;
  if (diff < 60000)    return 'now';
  if (diff < 3600000)  return Math.floor(diff / 60000) + 'm';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h';
  return Math.floor(diff / 86400000) + 'd';
}
