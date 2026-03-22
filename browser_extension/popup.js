// Virus Scanner Popup Script

document.addEventListener('DOMContentLoaded', () => {
    loadHistory();
    loadStats();
    setupListeners();
});

function setupListeners() {
    document.getElementById('quickScan').addEventListener('click', quickScan);
    document.getElementById('scanAll').addEventListener('click', scanAll);
    document.getElementById('clearHistory').addEventListener('click', clearHistory);
}

async function loadHistory() {
    const history = await chrome.runtime.sendMessage({ action: 'getHistory' }) || [];
    const listEl = document.getElementById('historyList');
    
    if (history.length === 0) {
        listEl.innerHTML = '<div class="empty">no files scanned</div>';
        return;
    }
    
    listEl.innerHTML = '';
    
    history.forEach(item => {
        const result = item.result || {};
        const riskScore = result.risk_score || 0;
        const time = item.timestamp ? formatTime(item.timestamp) : '';
        
        let safetyClass;
        if (riskScore >= 60) safetyClass = 'danger';
        else if (riskScore >= 30) safetyClass = 'warning';
        else safetyClass = 'safe';
        
        const div = document.createElement('div');
        div.className = `history-item ${safetyClass}`;
        
        div.innerHTML = `
            <div class="filename">${escapeHtml(item.filename || 'unknown')}</div>
            <div class="meta">
                <span>[${safetyClass.toUpperCase()}] ${riskScore}%</span>
                <span>${time}</span>
            </div>
        `;
        
        listEl.appendChild(div);
    });
}

async function loadStats() {
    const stats = await chrome.runtime.sendMessage({ action: 'getStats' }) || { total: 0, clean: 0, threats: 0 };
    document.getElementById('totalCount').textContent = stats.total;
    document.getElementById('cleanCount').textContent = stats.clean;
    document.getElementById('threatCount').textContent = stats.threats;
}

async function quickScan() {
    const btn = document.getElementById('quickScan');
    btn.textContent = 'scanning...';
    btn.disabled = true;
    
    await chrome.runtime.sendMessage({ action: 'quickScan' });
    
    setTimeout(() => {
        btn.textContent = 'scan --latest';
        btn.disabled = false;
        loadHistory();
        loadStats();
    }, 1000);
}

async function scanAll() {
    const btn = document.getElementById('scanAll');
    btn.textContent = 'scanning...';
    btn.disabled = true;
    
    await chrome.runtime.sendMessage({ action: 'scanAll' });
    
    setTimeout(() => {
        btn.textContent = 'scan --all';
        btn.disabled = false;
        loadHistory();
        loadStats();
    }, 2000);
}

async function clearHistory() {
    await chrome.runtime.sendMessage({ action: 'clearHistory' });
    loadHistory();
    loadStats();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h';
    return Math.floor(diff / 86400000) + 'd';
}