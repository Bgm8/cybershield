// ==========================================================================
// CYBERSHIELD AI ENTERPRISE - APPLICATION LOGIC
// ==========================================================================

// ── CONFIGURATION ─────────────────────────────────────────────────────────
// This single variable controls where the frontend sends API requests.
// For GitHub pages deployment, this should point to your Railway URL.
// Example: const BACKEND_URL = "https://my-railway-app.up.railway.app";
const BACKEND_URL = "https://cybershield-production-2548.up.railway.app";

// State
let currentScanType = "url";
let scanHistory = [];
let totalScans = 0;
let isScanning = false;

// Theme Colors for JS rendering
const THEMES = {
    HIGH:   { main: "#FF4444", bg: "rgba(255,68,68,0.1)", label: "CRITICAL THREAT" },
    MEDIUM: { main: "#FFAA00", bg: "rgba(255,170,0,0.1)", label: "SUSPICIOUS" },
    LOW:    { main: "#FFDD00", bg: "rgba(255,221,0,0.1)", label: "LOW RISK" },
    CLEAN:  { main: "#00FF88", bg: "rgba(0,255,136,0.1)", label: "CLEAN" }
};

// ── INITIALIZATION ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initSettingsToggles();
    checkApiHealth();
    setInterval(checkApiHealth, 60000); // Check health every minute
    
    // Set Backend URL in Settings View
    document.getElementById('set-backend-url').textContent = BACKEND_URL;

    // Scan Type Tabs
    document.querySelectorAll('.scan-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            document.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
            e.target.classList.add('active');
            currentScanType = e.target.dataset.type;
            const input = document.getElementById('scan-target');
            input.placeholder = currentScanType === 'url' ? 
                "Enter URL, Domain, or Hash..." : "Enter IPv4 or IPv6 Address...";
            input.focus();
        });
    });

    // Enter key to scan
    document.getElementById('scan-target').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') executeScan();
    });
});

// ── NAVIGATION ─────────────────────────────────────────────────────────────
function initNavigation() {
    document.querySelectorAll('.nav-btn[data-target]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = btn.dataset.target;
            navigate(target);
        });
    });
}

function navigate(viewId) {
    // Update active button
    document.querySelectorAll('.nav-btn[data-target]').forEach(b => {
        b.classList.toggle('active', b.dataset.target === viewId);
    });
    
    // Update active view
    document.querySelectorAll('.view').forEach(v => {
        v.classList.remove('active');
    });
    document.getElementById(`view-${viewId}`).classList.add('active');

    // Update Breadcrumb
    const names = {
        'dashboard': 'SOC DASHBOARD',
        'scanner': 'ADVANCED SCANNER',
        'investigations': 'INVESTIGATION TIMELINE',
        'map': 'GLOBAL THREAT MAP',
        'analytics': 'THREAT ANALYTICS',
        'settings': 'PLATFORM SETTINGS'
    };
    document.querySelector('#breadcrumb .current').textContent = names[viewId];
}

// ── API HEALTH MONITORING ──────────────────────────────────────────────────
async function checkApiHealth() {
    const sysDot = document.getElementById('sys-dot');
    const sysText = document.getElementById('sys-text');
    const overlay = document.getElementById('offline-overlay');
    const apiVal = document.getElementById('api-status-val');

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        
        const res = await fetch(`${BACKEND_URL}/health`, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (res.ok) {
            sysDot.className = 'dot online';
            sysText.textContent = 'SYSTEM SECURE';
            sysText.classList.replace('text-danger', 'text-muted');
            overlay.style.display = 'none';
            apiVal.textContent = '99.9%';
            apiVal.className = 'dc-value font-display text-success';
        } else {
            throw new Error('API degraded');
        }
    } catch (err) {
        sysDot.className = 'dot offline';
        sysText.textContent = 'API OFFLINE';
        sysText.classList.replace('text-muted', 'text-danger');
        overlay.style.display = 'flex';
        apiVal.textContent = 'OFFLINE';
        apiVal.className = 'dc-value font-display text-danger';
    }
}

// ── ADVANCED SCANNER LOGIC ─────────────────────────────────────────────────
async function executeScan() {
    if (isScanning) return;
    
    const targetInput = document.getElementById('scan-target');
    const target = targetInput.value.trim();
    const errBox = document.getElementById('scan-error');
    
    if (!target) {
        errBox.textContent = "Error: Target indicator cannot be empty.";
        errBox.style.display = 'block';
        return;
    }

    errBox.style.display = 'none';
    isScanning = true;
    
    // UI Reset & Loading State
    document.getElementById('scan-results').style.display = 'none';
    const progressContainer = document.getElementById('scan-progress');
    const progressBar = document.querySelector('.scan-progress-fill');
    const btn = document.getElementById('btn-scan');
    
    progressContainer.style.display = 'block';
    btn.innerHTML = 'ANALYZING...';
    btn.disabled = true;
    progressBar.style.width = '10%';

    clearLogs();
    logTerminal(`[SYSTEM] Initiating enterprise threat analysis for: ${target}`);
    logTerminal(`[ROUTER] Dispatching payload to ${currentScanType.toUpperCase()} intelligence engines...`);

    try {
        // Simulated progress jumps for UX
        setTimeout(() => { progressBar.style.width = '40%'; logTerminal('[ENGINE] Querying VirusTotal global dataset...'); }, 800);
        setTimeout(() => { if(currentScanType==='ip') logTerminal('[ENGINE] Querying AbuseIPDB telemetry...'); progressBar.style.width = '70%'; }, 1500);

        const response = await fetch(`${BACKEND_URL}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target, scan_type: currentScanType })
        });

        progressBar.style.width = '90%';

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || errData.error || `HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.error) throw new Error(data.error);

        progressBar.style.width = '100%';
        logTerminal(`[SYSTEM] Analysis complete. Risk Score computed: ${data.risk_score}`);
        
        // Update Dashboard Counters
        totalScans++;
        document.getElementById('cnt-threats').textContent = totalScans;
        if (data.threat_level === 'HIGH' || data.threat_level === 'MEDIUM') {
            const risks = document.getElementById('cnt-risks');
            risks.textContent = parseInt(risks.textContent) + 1;
        }

        setTimeout(() => {
            progressContainer.style.display = 'none';
            renderResults(data);
            addToHistory(data);
        }, 500);

    } catch (err) {
        logTerminal(`[ERROR] Analysis failed: ${err.message}`);
        errBox.textContent = `Analysis Failed: ${err.message}`;
        errBox.style.display = 'block';
        progressContainer.style.display = 'none';
    } finally {
        isScanning = false;
        btn.innerHTML = 'ANALYZE THREAT';
        btn.disabled = false;
        progressBar.style.width = '0%';
    }
}

// ── TERMINAL LOGGER ────────────────────────────────────────────────────────
function logTerminal(msg) {
    const term = document.getElementById('live-logs');
    const time = new Date().toISOString().split('T')[1].substr(0,8);
    const div = document.createElement('div');
    div.className = 'log-line';
    
    let color = "var(--text-muted)";
    if (msg.includes("[ERROR]")) color = "var(--danger)";
    if (msg.includes("complete")) color = "var(--success)";
    
    div.innerHTML = `<span class="time">[${time}]</span> <span style="color:${color}">${msg}</span>`;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
}

function clearLogs() {
    document.getElementById('live-logs').innerHTML = '';
}

// ── RESULT RENDERING ───────────────────────────────────────────────────────
function renderResults(data) {
    const theme = THEMES[data.threat_level] || THEMES.CLEAN;

    // 1. Top Verdict Card
    document.getElementById('verdict-card').style.borderLeft = `6px solid ${theme.main}`;
    document.getElementById('res-title').textContent = theme.label;
    document.getElementById('res-title').style.color = theme.main;
    document.getElementById('res-target').innerHTML = `Target: <span class="text-main">${data.target}</span>`;

    // Circular Score Animation
    document.getElementById('res-score').textContent = data.risk_score;
    document.getElementById('res-score').style.color = theme.main;
    const path = document.getElementById('score-path');
    path.style.stroke = theme.main;
    setTimeout(() => { path.style.strokeDasharray = `${data.risk_score}, 100`; }, 100);

    // 2. AI Security Analyst Copilot Simulation
    generateAiSummary(data);

    // 3. Network Data
    const nwGrid = document.getElementById('network-grid');
    nwGrid.innerHTML = '';
    if (data.geo) {
        document.getElementById('network-panel').style.display = 'block';
        const g = data.geo;
        const addRow = (k, v, warn=false) => {
            nwGrid.innerHTML += `<div class="kv-row"><span>${k}</span> <span class="font-mono ${warn?'text-danger':''}">${v}</span></div>`;
        };
        addRow("Country", g.country);
        addRow("ISP/Org", g.isp);
        addRow("ASN", g.asn);
        addRow("Datacenter/Hosting", g.is_hosting ? "YES" : "NO", g.is_hosting);
        addRow("Proxy/VPN Detected", g.is_proxy ? "YES" : "NO", g.is_proxy);
    } else if (data.domain_info) {
        document.getElementById('network-panel').style.display = 'block';
        nwGrid.innerHTML = `<div class="kv-row"><span>WHOIS Domain</span> <span class="font-mono">${data.domain_info.domain || '-'}</span></div>`;
    } else {
        document.getElementById('network-panel').style.display = 'none';
    }

    // 4. AbuseIPDB Data
    const abGrid = document.getElementById('abuse-grid');
    if (data.abuse) {
        document.getElementById('abuse-panel').style.display = 'block';
        const a = data.abuse;
        abGrid.innerHTML = `
            <div class="kv-row"><span>Confidence Score</span> <span class="font-mono ${a.abuse_score>0?'text-danger':'text-success'}">${a.abuse_score}%</span></div>
            <div class="kv-row"><span>Total Reports</span> <span class="font-mono">${a.total_reports}</span></div>
            <div class="kv-row"><span>Usage Type</span> <span class="font-mono">${a.usage_type}</span></div>
            <div class="kv-row"><span>TOR Node</span> <span class="font-mono ${a.is_tor?'text-danger':''}">${a.is_tor ? 'YES' : 'NO'}</span></div>
        `;
    } else {
        document.getElementById('abuse-panel').style.display = 'none';
    }

    // 5. Engines List
    const eList = document.getElementById('engines-list');
    const engines = data.engines || {};
    document.getElementById('engine-cnt').textContent = Object.keys(engines).length;
    
    let eHtml = '';
    
    // Sort engines: Malicious/Suspicious first, then Clean/Undetected
    const sortedEngines = Object.entries(engines).sort((a, b) => {
        const resA = a[1].toUpperCase();
        const resB = b[1].toUpperCase();
        const aClean = ["CLEAN", "HARMLESS", "UNDETECTED", "UNRATED", "TIMEOUT"].some(x => resA.includes(x));
        const bClean = ["CLEAN", "HARMLESS", "UNDETECTED", "UNRATED", "TIMEOUT"].some(x => resB.includes(x));
        
        if (aClean === bClean) return a[0].localeCompare(b[0]); // Alphabetical if same category
        return aClean ? 1 : -1; // Malicious (-1) comes before Clean (1)
    });

    for (const [name, result] of sortedEngines) {
        const resUp = result.toUpperCase();
        const isClean = ["CLEAN", "HARMLESS", "UNDETECTED", "UNRATED", "TIMEOUT"].some(x => resUp.includes(x));
        
        // Detailed coloring
        let col = THEMES.CLEAN;
        if (!isClean) {
            col = resUp.includes("SUSPICIOUS") ? THEMES.MEDIUM : THEMES.HIGH;
        }
        
        eHtml += `
            <div class="engine-item">
                <span class="e-name">${name}</span>
                <span class="e-res" style="color:${col.main}; background:${col.bg}">${resUp}</span>
            </div>
        `;
    }
    eList.innerHTML = eHtml || '<div class="text-muted">No engine data available.</div>';

    // Show Results
    document.getElementById('scan-results').style.display = 'block';
}

// ── AI SECURITY ANALYST ────────────────────────────────────────────────────
function generateAiSummary(data) {
    const aiBox = document.getElementById('ai-text');
    aiBox.innerHTML = '';
    
    let summary = `CyberShield AI has completed analysis of ${data.target}. `;
    
    if (data.threat_level === 'HIGH') {
        summary += `CRITICAL ALERT: This indicator shows strong malicious patterns. ${data.summary.malicious} security vendors flagged this as malicious. `;
        if (data.abuse && data.abuse.abuse_score > 50) {
            summary += `AbuseIPDB reports a high confidence of abuse with ${data.abuse.total_reports} recent reports. `;
        }
        summary += `Recommendation: Immediate blocklist at firewall and endpoint levels.`;
    } else if (data.threat_level === 'MEDIUM') {
        summary += `WARNING: Suspicious activity detected. ${data.summary.suspicious} vendors flagged this indicator. `;
        summary += `Recommendation: Monitor traffic closely and consider temporary isolation pending further SOC review.`;
    } else {
        summary += `No significant threats detected. Indicator appears benign across ${data.summary.total_engines} security engines. `;
        summary += `Recommendation: Safe to allow. Standard monitoring applies.`;
    }

    // Typewriter Effect with blinking cursor
    let i = 0;
    function typeWriter() {
        if (i < summary.length) {
            aiBox.innerHTML = summary.substring(0, i + 1) + '<span style="animation: pulse 1s infinite;">_</span>';
            i++;
            setTimeout(typeWriter, 15); // typing speed
        } else {
            aiBox.innerHTML = summary; // remove cursor at end
        }
    }
    typeWriter();
}

// ── INVESTIGATION HISTORY ──────────────────────────────────────────────────
function addToHistory(data) {
    const hItem = {
        target: data.target,
        type: data.type,
        level: data.threat_level,
        score: data.risk_score,
        time: new Date().toISOString().split('T')[0] + " " + new Date().toLocaleTimeString()
    };
    
    scanHistory.unshift(hItem);
    if(scanHistory.length > 50) scanHistory.pop();
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById('history-list');
    if (!scanHistory.length) {
        list.innerHTML = '<div class="text-muted text-center p-6">No investigations logged in this session.</div>';
        return;
    }

    list.innerHTML = scanHistory.map(h => {
        const theme = THEMES[h.level] || THEMES.CLEAN;
        return `
            <div class="hist-item" onclick="navigate('scanner'); document.getElementById('scan-target').value='${h.target}';">
                <div class="d-flex align-center gap-4">
                    <span style="font-size: 1.5rem; color: ${theme.main}">⚡</span>
                    <div>
                        <div class="font-mono text-main">${h.target}</div>
                        <div class="font-mono text-faint text-sm mt-1">${h.time} | ${h.type}</div>
                    </div>
                </div>
                <div class="text-right">
                    <div class="font-display" style="color: ${theme.main}">${h.level}</div>
                    <div class="font-mono text-muted text-sm mt-1">Risk: ${h.score}/100</div>
                </div>
            </div>
        `;
    }).join('');
}

function clearHistory() {
    scanHistory = [];
    renderHistory();
}

// ── SETTINGS TOGGLES ───────────────────────────────────────────────────────
function initSettingsToggles() {
    document.querySelectorAll('.toggle').forEach(t => {
        t.addEventListener('click', () => {
            t.classList.toggle('active');
        });
    });
}
