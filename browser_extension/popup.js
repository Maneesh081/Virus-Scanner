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
    
    document.getElementById('autoScan').addEventListener('click', (e) => {
        e.target.classList.toggle('active');
        saveSettings();
    });
    
    document.getElementById('notifications').addEventListener('click', (e) => {
        e.target.classList.toggle('active');
        saveSettings();
    });
}

async function loadHistory() {
    const history = await chrome.runtime.sendMessage({ action: 'getHistory' }) || [];
    const listEl = document.getElementById('historyList');
    listEl.innerHTML = '';
    
    history.slice(0, 8).forEach(item => {
        const div = document.createElement('div');
        const result = item.result || {};
        const riskScore = result.risk_score || 0;
        
        // Determine safety level based on risk score
        let safetyLevel, safetyClass, reason;
        if (riskScore >= 60) {
            safetyLevel = 'Dangerous';
            safetyClass = 'danger';
            reason = result.findings && result.findings.length > 0 
                ? result.findings.map(f => f.category).join(', ') 
                : 'High risk file type detected';
        } else if (riskScore >= 30) {
            safetyLevel = 'Moderate';
            safetyClass = 'warning';
            reason = 'Risky file extension or suspicious source';
        } else {
            safetyLevel = 'Safe';
            safetyClass = 'clean';
            reason = 'No suspicious patterns found';
        }
        
        div.className = `history-item ${safetyClass}`;
        
        const time = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '';
        
        div.innerHTML = `
            <div class="filename">${escapeHtml(item.filename || 'Unknown')}</div>
            <div class="explanation">
                <span class="safety-badge ${safetyClass}">${safetyLevel}</span>
                ${reason}
            </div>
            <div class="meta">
                <span>Risk: ${riskScore}%</span>
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
    btn.textContent = 'Scanning...';
    btn.disabled = true;
    
    await chrome.runtime.sendMessage({ action: 'quickScan' });
    
    setTimeout(() => {
        btn.textContent = 'Quick Scan';
        btn.disabled = false;
        loadHistory();
        loadStats();
    }, 1500);
}

async function scanAll() {
    const btn = document.getElementById('scanAll');
    btn.textContent = 'Scanning...';
    btn.disabled = true;
    
    await chrome.runtime.sendMessage({ action: 'scanAll' });
    
    setTimeout(() => {
        btn.textContent = 'Scan All Downloads';
        btn.disabled = false;
        loadHistory();
        loadStats();
    }, 3000);
}

async function clearHistory() {
    await chrome.runtime.sendMessage({ action: 'clearHistory' });
    await chrome.storage.local.set({ stats: { total: 0, clean: 0, threats: 0 } });
    loadHistory();
    loadStats();
}

function saveSettings() {
    const autoScan = document.getElementById('autoScan').classList.contains('active');
    const notif = document.getElementById('notifications').classList.contains('active');
    chrome.storage.local.set({ settings: { autoScan, showNotifications: notif } });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}