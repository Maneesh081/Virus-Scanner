// Virus Scanner - Background Service Worker

// Initialize
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({ 
        scanHistory: [],
        stats: { total: 0, clean: 0, threats: 0 }
    });
});

// Monitor ALL downloads
chrome.downloads.onCreated.addListener((downloadItem) => {
    scanFile(downloadItem);
});

// Main scan function
async function scanFile(downloadItem) {
    const scanResult = {
        id: Date.now(),
        filename: downloadItem.filename,
        timestamp: new Date().toISOString(),
        result: null
    };
    
    // Save to history immediately
    let history = await getHistory();
    history.unshift(scanResult);
    await saveHistory(history.slice(0, 100));
    
    // Perform scan
    const result = fastScan(downloadItem);
    scanResult.result = result;
    
    // Update history with result
    history = await getHistory();
    const idx = history.findIndex(x => x.id === scanResult.id);
    if (idx >= 0) history[idx] = scanResult;
    await saveHistory(history);
    
    // Update stats
    let stats = await getStats();
    stats.total++;
    if (result.is_malicious) {
        stats.threats++;
    } else {
        stats.clean++;
    }
    await chrome.storage.local.set({ stats });
    
    return result;
}

// Fast heuristic scan - scans ALL file types
function fastScan(downloadItem) {
    const filename = downloadItem.filename.toLowerCase();
    let riskScore = 0;
    let findings = [];
    let is_malicious = false;
    let threat_type = 'clean';
    
    // Get file extension
    const ext = filename.includes('.') ? filename.split('.').pop() : '';
    
    // Whitelist for known legitimate software
    const legitimate = ['vscode', 'visual studio', 'chrome', 'firefox', 'edge', 'discord',
                       'spotify', 'steam', 'zoom', 'teams', 'slack', 'notepad++', 'git',
                       'python', 'nodejs', 'java', 'npm', 'anaconda', 'sublime', 'atom',
                       'utorrent', 'utorr', 'bitTorrent', 'qbittorrent', 'winrar', '7zip',
                       'adobe', 'photoshop', 'illustrator', 'microsoft', 'nvidia', 'amd', 'intel'];
    
    const isLegit = legitimate.some(name => filename.includes(name));
    
    // File extension risk levels
    const extRisk = {
        'exe': 25, 'dll': 30, 'sys': 30, 'scr': 35, 'bat': 25, 'cmd': 25, 'ps1': 25,
        'vbs': 25, 'js': 20, 'jar': 25, 'msi': 20, 'com': 25, 'pif': 35,
        'apk': 20, 'ipa': 20, 'app': 15, 'deb': 15, 'rpm': 15,
        'sh': 15, 'py': 10, 'rb': 10, 'php': 15, 'pl': 10,
        'zip': 5, 'rar': 5, '7z': 5, 'tar': 5, 'gz': 5,
        'pdf': 5, 'doc': 5, 'docx': 5, 'xls': 5, 'xlsx': 5, 'ppt': 5, 'pptx': 5,
        'txt': 0, 'rtf': 0, 'csv': 0,
        'jpg': 0, 'jpeg': 0, 'png': 0, 'gif': 0, 'bmp': 0, 'svg': 0, 'webp': 0,
        'mp4': 0, 'mp3': 0, 'wav': 0, 'avi': 0, 'mkv': 0, 'mov': 0,
        'torrent': 5, 'html': 5, 'xml': 0, 'json': 0, 'css': 0,
    };
    
    // Set base risk from extension
    if (extRisk[ext] !== undefined) {
        riskScore = extRisk[ext];
        findings.push(ext + ' file');
    }
    
    // Suspicious names - ALWAYS HIGH RISK
    const suspicious = ['crack', 'patch', 'keygen', 'activator', 'modmenu', 'free hack',
                      'torrent', 'pirated', 'illegal', 'cheat engine', 'exploit'];
    suspicious.forEach(s => {
        if (filename.includes(s)) {
            riskScore = 70;
            findings.push('suspicious: ' + s);
            is_malicious = true;
            threat_type = 'malicious';
        }
    });
    
    // Known legitimate software - SAFE
    if (isLegit && riskScore < 30) {
        riskScore = 5;
        findings = ['known software'];
        threat_type = 'clean';
        is_malicious = false;
    }
    
    // Cap risk score
    riskScore = Math.min(100, riskScore);
    
    // Determine threat level
    if (riskScore >= 60) {
        is_malicious = true;
        threat_type = riskScore >= 80 ? 'high_risk' : 'suspicious';
    }
    
    return {
        is_malicious,
        threat_type,
        risk_score: riskScore,
        findings: findings.map(f => ({ category: f, severity: riskScore >= 60 ? 'high' : 'low' }))
    };
}

// Storage helpers
function getHistory() {
    return chrome.storage.local.get(['scanHistory']).then(r => r.scanHistory || []);
}

function saveHistory(history) {
    return chrome.storage.local.set({ scanHistory: history });
}

function getStats() {
    return chrome.storage.local.get(['stats']).then(r => r.stats || { total: 0, clean: 0, threats: 0 });
}

// Message handlers
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getHistory') {
        getHistory().then(h => sendResponse(h));
        return true;
    }
    if (message.action === 'getStats') {
        getStats().then(s => sendResponse(s));
        return true;
    }
    if (message.action === 'clearHistory') {
        saveHistory([]);
        chrome.storage.local.set({ stats: { total: 0, clean: 0, threats: 0 } });
        sendResponse({ success: true });
    }
    if (message.action === 'quickScan') {
        chrome.downloads.search({ limit: 1 }).then(downloads => {
            if (downloads.length > 0) {
                scanFile(downloads[0]);
            }
        });
    }
    if (message.action === 'scanAll') {
        chrome.downloads.search({ limit: 20 }).then(downloads => {
            downloads.forEach(d => scanFile(d));
        });
    }
});