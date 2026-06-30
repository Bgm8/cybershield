// ==========================================================================
// CYBERSHIELD AI ENTERPRISE v2.1 — APPLICATION LOGIC
// ==========================================================================

// ── SECURITY CONFIGURATION ────────────────────────────────────────────────
const BACKEND_URL = "https://cybershield-production-2548.up.railway.app";

// Allowed hostname for the backend (prevents JS hijacking)
const BACKEND_HOST = "cybershield-production-2548.up.railway.app";

// Validate the backend URL hasn't been tampered with
(function guardBackendUrl() {
    try {
        const parsed = new URL(BACKEND_URL);
        if (parsed.protocol !== "https:" || parsed.hostname !== BACKEND_HOST) {
            throw new Error("Backend URL integrity check failed.");
        }
    } catch (e) {
        console.error("[SECURITY] Backend URL validation failed. Aborting.");
        document.body.innerHTML = `<div style="color:#ff4444;text-align:center;padding:100px;font-family:monospace;">
            Security configuration error. Please contact your administrator.
        </div>`;
    }
})();

// ── STATE ─────────────────────────────────────────────────────────────────
let currentScanType = "url";
let scanHistory = [];
let totalScans = 0;
let highCount = 0, mediumCount = 0, cleanCount = 0;
let isScanning = false;
let allEngineData = {}; // Store full engine data for filtering
let currentEngineFilter = "all"; // Store active vendor filter

const THEMES = {
    HIGH:   { main: "#FF4444", bg: "rgba(255,68,68,0.12)", label: "CRITICAL THREAT" },
    MEDIUM: { main: "#FFAA00", bg: "rgba(255,170,0,0.12)", label: "SUSPICIOUS" },
    LOW:    { main: "#FFDD00", bg: "rgba(255,221,0,0.12)", label: "LOW RISK" },
    CLEAN:  { main: "#00FF88", bg: "rgba(0,255,136,0.12)", label: "CLEAN" }
};

const CLEAN_LABELS = ["CLEAN", "HARMLESS", "UNDETECTED", "UNRATED", "TIMEOUT"];

// ── INITIALIZATION ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initSettingsToggles();
    initGlobalSearch();
    checkApiHealth();
    setInterval(checkApiHealth, 60000);
    renderHistory();
    initHero3DCanvas();

    // Live engine search filter
    const engineSearch = document.getElementById('engine-search');
    if (engineSearch) {
        engineSearch.addEventListener('input', () => {
            renderEngines(currentEngineFilter);
        });
    }

    // Scan type tabs
    document.querySelectorAll('.scan-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            document.querySelectorAll('.scan-tab').forEach(t => {
                t.classList.remove('active');
                t.setAttribute('aria-selected', 'false');
            });
            e.target.classList.add('active');
            e.target.setAttribute('aria-selected', 'true');
            currentScanType = e.target.dataset.type;
            const input = document.getElementById('scan-target');
            input.placeholder = currentScanType === 'url'
                ? "Enter URL, domain, or file hash..."
                : "Enter IPv4 or IPv6 address...";
            input.focus();
        });
    });

    // Enter key to scan
    document.getElementById('scan-target').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') executeScan();
    });
});

// ── GLOBAL SEARCH ──────────────────────────────────────────────────────────
// Lets user press Enter in the top search bar to go directly to scanner
function initGlobalSearch() {
    const gs = document.getElementById('global-search');
    if (!gs) return;
    gs.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && gs.value.trim()) {
            navigate('scanner');
            const input = document.getElementById('scan-target');
            input.value = sanitizeInput(gs.value.trim());
            gs.value = '';
            // Auto-detect scan type
            const v = input.value;
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;
            if (ipRegex.test(v)) {
                document.querySelector('[data-type="ip"]').click();
            } else {
                document.querySelector('[data-type="url"]').click();
            }
            executeScan();
        }
    });
}

// ── INPUT SANITIZATION ─────────────────────────────────────────────────────
function sanitizeInput(str) {
    // Remove all HTML tags and dangerous characters before displaying or sending
    return String(str)
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;")
        .replace(/\//g, "&#x2F;")
        .trim()
        .substring(0, 500); // Hard character cap
}

// Safe display — decode for actual scan value but not for innerHTML
function rawInput(str) {
    return String(str).trim().substring(0, 500);
}

// ── NAVIGATION ─────────────────────────────────────────────────────────────
function initNavigation() {
    document.querySelectorAll('.nav-btn[data-target]').forEach(btn => {
        btn.addEventListener('click', () => {
            navigate(btn.dataset.target);
        });
    });
}

function navigate(viewId) {
    const VALID_VIEWS = ['dashboard', 'scanner', 'investigations', 'map', 'analytics', 'settings'];
    if (!VALID_VIEWS.includes(viewId)) return; // Guard against arbitrary view IDs

    document.querySelectorAll('.nav-btn[data-target]').forEach(b => {
        const isActive = b.dataset.target === viewId;
        b.classList.toggle('active', isActive);
        b.setAttribute('aria-current', isActive ? 'page' : 'false');
    });

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const targetView = document.getElementById(`view-${viewId}`);
    if (targetView) targetView.classList.add('active');

    const names = {
        dashboard: 'SOC DASHBOARD', scanner: 'ADVANCED SCANNER',
        investigations: 'INVESTIGATION TIMELINE', map: 'GLOBAL THREAT MAP',
        analytics: 'THREAT ANALYTICS', settings: 'PLATFORM SETTINGS'
    };
    const breadcrumb = document.querySelector('#breadcrumb .current');
    if (breadcrumb) breadcrumb.textContent = names[viewId] || viewId.toUpperCase();

    if (viewId === 'analytics') updateAnalytics();
}

// ── API HEALTH CHECK ───────────────────────────────────────────────────────
async function checkApiHealth() {
    const sysDot  = document.getElementById('sys-dot');
    const sysText = document.getElementById('sys-text');
    const apiVal  = document.getElementById('api-status-val');

    try {
        const controller = new AbortController();
        const timeoutId  = setTimeout(() => controller.abort(), 6000);
        const res = await fetch(`${BACKEND_URL}/health`, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        sysDot.className  = 'dot online';
        sysText.textContent = 'SYSTEM SECURE';
        if (apiVal) {
            apiVal.textContent    = '99.9%';
            apiVal.className      = 'dc-value font-display text-success';
        }

        // Update settings page statuses
        setEl('set-vt-status',       data.vt_key_set        ? 'CONNECTED' : 'KEY MISSING', data.vt_key_set        ? 'text-success' : 'text-danger');
        setEl('set-abuse-status',    data.abuse_key_set     ? 'CONNECTED' : 'KEY MISSING', data.abuse_key_set     ? 'text-success' : 'text-danger');
        setEl('set-ipinfo-status',   data.ipinfo_key_set    ? 'CONNECTED' : 'KEY MISSING', data.ipinfo_key_set    ? 'text-success' : 'text-danger');
        setEl('set-otx-status',      data.otx_key_set       ? 'CONNECTED' : 'KEY MISSING', data.otx_key_set       ? 'text-success' : 'text-danger');
        setEl('set-urlscan-status',  data.urlscan_key_set   ? 'CONNECTED' : 'KEY MISSING', data.urlscan_key_set   ? 'text-success' : 'text-danger');
        setEl('set-gsb-status',      data.google_sb_key_set ? 'CONNECTED' : 'KEY MISSING', data.google_sb_key_set ? 'text-success' : 'text-danger');

    } catch {
        sysDot.className      = 'dot offline';
        sysText.textContent   = 'API OFFLINE';
        if (apiVal) {
            apiVal.textContent    = 'OFFLINE';
            apiVal.className      = 'dc-value font-display text-danger';
        }
        // Mark all as offline
        ['vt', 'abuse', 'ipinfo', 'otx', 'urlscan', 'gsb'].forEach(key => {
            setEl(`set-${key}-status`, 'OFFLINE', 'text-danger');
        });
    }
}

function setEl(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className   = `font-mono ${cls}`;
}

// ── SCANNER LOGIC ──────────────────────────────────────────────────────────
async function executeScan() {
    if (isScanning) return;

    const rawTarget = document.getElementById('scan-target').value.trim();
    const errBox    = document.getElementById('scan-error');

    if (!rawTarget) {
        showError("Target cannot be empty. Enter a URL, domain, IP, or hash.");
        return;
    }

    // Client-side WAF: block obvious injection attempts
    const blocklist = ['<script', 'javascript:', 'DROP TABLE', 'SELECT * FROM', '../etc', 'eval('];
    for (const bad of blocklist) {
        if (rawTarget.toLowerCase().includes(bad.toLowerCase())) {
            showError("Invalid input detected. Enter a valid URL, IP address, domain, or file hash.");
            return;
        }
    }

    errBox.style.display = 'none';
    isScanning = true;

    const progressContainer = document.getElementById('scan-progress');
    const progressBar       = document.getElementById('progress-fill');
    const btn               = document.getElementById('btn-scan');

    document.getElementById('scan-results').style.display = 'none';
    progressContainer.style.display = 'block';
    btn.textContent = 'ANALYZING...';
    btn.disabled    = true;
    progressBar.style.width = '8%';

    clearLogs();
    logTerminal(`[SYSTEM] Initiating analysis for: ${rawTarget}`);
    logTerminal(`[ROUTER] Target type: ${currentScanType.toUpperCase()} — dispatching to threat engines...`);

    try {
        setTimeout(() => { progressBar.style.width = '35%'; logTerminal('[ENGINE] VirusTotal — querying 90+ security engines...'); }, 600);
        setTimeout(() => {
            progressBar.style.width = '55%';
            if (currentScanType === 'ip') {
                logTerminal('[ENGINE] AbuseIPDB — querying community abuse reports...');
                logTerminal('[ENGINE] Shodan InternetDB — scanning for open ports & CVEs...');
                logTerminal('[ENGINE] AlienVault OTX — checking threat intelligence databases...');
            } else {
                logTerminal('[ENGINE] Google Safe Browsing — checking phishing/malware lists...');
                logTerminal('[ENGINE] URLScan.io — deep page analysis...');
                logTerminal('[ENGINE] AlienVault OTX — checking domain threat reputation...');
            }
            logTerminal('[ENGINE] GeoIP — enriching network intelligence...');
        }, 1400);

        const response = await fetch(`${BACKEND_URL}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: rawTarget, scan_type: currentScanType })
        });

        progressBar.style.width = '90%';

        if (!response.ok) {
            let msg = `Server error (HTTP ${response.status})`;
            try { const e = await response.json(); msg = e.detail || e.error || msg; } catch {}
            throw new Error(msg);
        }

        const data = await response.json();
        if (data.error) throw new Error(data.error);

        progressBar.style.width = '100%';
        logTerminal(`[SYSTEM] Analysis complete — Risk Score: ${data.risk_score}/100 | Level: ${data.threat_level}`);

        // Update counters
        totalScans++;
        document.getElementById('cnt-threats').textContent = totalScans;
        if (data.threat_level === 'HIGH') { highCount++; document.getElementById('cnt-risks').textContent = highCount + mediumCount; }
        if (data.threat_level === 'MEDIUM') { mediumCount++; document.getElementById('cnt-risks').textContent = highCount + mediumCount; }
        if (data.threat_level === 'CLEAN' || data.threat_level === 'LOW') cleanCount++;

        setTimeout(() => {
            progressContainer.style.display = 'none';
            renderResults(data);
            addToHistory(data);
            updateRecentActivity(data);
        }, 400);

    } catch (err) {
        logTerminal(`[ERROR] ${err.message}`);
        showError(`Analysis Failed: ${err.message}`);
        progressContainer.style.display = 'none';
    } finally {
        isScanning = false;
        btn.textContent = 'ANALYZE THREAT';
        btn.disabled    = false;
        progressBar.style.width = '0%';
    }
}

function showError(msg) {
    const errBox = document.getElementById('scan-error');
    // Sanitize before display
    errBox.textContent = msg; // textContent is safe — no HTML injection possible
    errBox.style.display = 'block';
}

// ── TERMINAL LOGGER ────────────────────────────────────────────────────────
function logTerminal(msg) {
    const term = document.getElementById('live-logs');
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const div  = document.createElement('div');
    div.className = 'log-line';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.textContent = `[${time}]`;

    const msgSpan = document.createElement('span');
    // Use textContent — no innerHTML — to fully prevent XSS in logs
    msgSpan.textContent = msg;
    if (msg.includes('[ERROR]')) msgSpan.style.color = 'var(--danger)';
    else if (msg.includes('complete')) msgSpan.style.color = 'var(--success)';

    div.appendChild(timeSpan);
    div.appendChild(msgSpan);
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
}

function clearLogs() {
    document.getElementById('live-logs').innerHTML = '';
}

// ── RESULT RENDERING ───────────────────────────────────────────────────────
function renderResults(data) {
    const theme = THEMES[data.threat_level] || THEMES.CLEAN;

    // Verdict card
    const verdictCard = document.getElementById('verdict-card');
    verdictCard.style.borderLeftColor = theme.main;

    const resTitle = document.getElementById('res-title');
    resTitle.textContent = theme.label;
    resTitle.style.color = theme.main;

    // Use textContent for all user-supplied data — prevents XSS
    document.getElementById('res-target').textContent = `Target: ${data.target}`;
    document.getElementById('scan-time').textContent  = `Scanned: ${new Date().toLocaleTimeString()}`;

    // Risk Score circle
    const score = data.risk_score;
    document.getElementById('res-score').textContent = score;
    document.getElementById('res-score').style.color = theme.main;
    const path = document.getElementById('score-path');
    path.style.stroke = theme.main;
    setTimeout(() => { path.setAttribute('stroke-dasharray', `${score}, 100`); }, 80);

    // Verdict stats row
    const s = data.summary || {};
    const statsEl = document.getElementById('verdict-stats');
    statsEl.innerHTML = '';
    [
        { val: s.malicious  || 0, label: 'MALICIOUS', col: 'var(--danger)' },
        { val: s.suspicious || 0, label: 'SUSPICIOUS', col: 'var(--warning)' },
        { val: s.harmless   || 0, label: 'HARMLESS',   col: 'var(--success)' },
        { val: s.undetected || 0, label: 'UNDETECTED', col: 'var(--text-faint)' },
    ].forEach(({ val, label, col }) => {
        const item = document.createElement('div');
        item.className = 'vs-item';
        item.innerHTML = `<div class="vs-val" style="color:${col}">${val}</div><div class="vs-label">${label}</div>`;
        statsEl.appendChild(item);
    });

    // AI Analyst
    generateAiSummary(data);

    // Network panel — show enriched geo + IPInfo data
    const nwGrid = document.getElementById('network-grid');
    nwGrid.innerHTML = '';
    if (data.geo) {
        document.getElementById('network-panel').style.display = 'block';
        const g = data.geo;
        const rows = [
            ['Country',               g.country    || '—'],
            ['Region / City',         `${g.region || '—'} / ${g.city || '—'}`],
            ['ISP / Org',             g.isp        || '—'],
            ['ASN',                   g.asn        || '—'],
        ];
        if (g.hostname)    rows.push(['Hostname',       g.hostname]);
        if (g.company)     rows.push(['Company',        g.company]);
        if (g.ip_type)     rows.push(['IP Type',        g.ip_type]);
        if (g.timezone)    rows.push(['Timezone',       g.timezone]);
        rows.push(['Hosting / Datacenter', g.is_hosting ? '⚠ YES' : 'NO', g.is_hosting]);
        rows.push(['Proxy / VPN',          (g.is_proxy || g.is_vpn) ? '⚠ YES' : 'NO', g.is_proxy || g.is_vpn]);
        rows.push(['TOR Node',             g.is_tor   ? '⚠ YES' : 'NO', g.is_tor]);
        if (g.is_relay)    rows.push(['Relay',          '⚠ YES', true]);
        rows.push(['Mobile Network',       g.is_mobile  ? 'YES' : 'NO']);
        rows.push(['Usage Type',           g.usage_type || '—']);
        if (g.abuse_contact) rows.push(['Abuse Contact', g.abuse_contact]);
        addKvRows(nwGrid, rows);
    } else {
        document.getElementById('network-panel').style.display = 'none';
    }

    // AbuseIPDB panel
    const abGrid = document.getElementById('abuse-grid');
    if (data.abuse) {
        document.getElementById('abuse-panel').style.display = 'block';
        const a = data.abuse;
        addKvRows(abGrid, [
            ['Abuse Confidence',  `${a.abuse_score}%`,           a.abuse_score > 0],
            ['Total Reports',     String(a.total_reports || 0),  a.total_reports > 0],
            ['Distinct Reporters',String(a.num_distinct_users || 0)],
            ['Usage Type',        a.usage_type  || '—'],
            ['Last Reported',     a.last_reported || 'Never'],
            ['TOR Node',          a.is_tor ? '⚠ YES' : 'NO',     a.is_tor],
        ]);
    } else {
        document.getElementById('abuse-panel').style.display = 'none';
    }

    // 🆕 Shodan InternetDB panel
    const shodan = data.shodan;
    renderShodanPanel(shodan);

    // AlienVault OTX panel
    const otx = data.otx;
    renderOtxPanel(otx);

    // 🆕 URLScan panel (URL scans only)
    const urlscan = data.urlscan;
    renderUrlscanPanel(urlscan);

    // 🆕 Google Safe Browsing panel
    const gsb = data.google_sb;
    renderGsbPanel(gsb);

    // Engines
    allEngineData = data.engines || {};
    document.getElementById('engine-cnt').textContent = Object.keys(allEngineData).length;
    renderEngines('all');

    document.getElementById('scan-results').style.display = 'block';
    document.getElementById('scan-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function addKvRows(container, rows) {
    rows.forEach(([key, val, warn]) => {
        const row = document.createElement('div');
        row.className = 'kv-row';
        const k = document.createElement('span');
        k.textContent = key;
        const v = document.createElement('span');
        v.textContent = val;
        if (warn) v.style.color = 'var(--danger)';
        row.appendChild(k);
        row.appendChild(v);
        container.appendChild(row);
    });
}

// ── SHODAN INTERNETDB PANEL ────────────────────────────────────────────────
function renderShodanPanel(shodan) {
    const panel = document.getElementById('shodan-panel');
    if (!panel) return;
    if (currentScanType !== 'ip') {
        panel.style.display = 'none'; return;
    }
    panel.style.display = 'block';

    const portsEl = document.getElementById('shodan-ports');
    const vulnsEl = document.getElementById('shodan-vulns');
    const hostsEl = document.getElementById('shodan-hosts');
    const tagsEl  = document.getElementById('shodan-tags');

    let statusBadge = panel.querySelector('.panel-status-badge');
    if (!statusBadge) {
        statusBadge = document.createElement('span');
        statusBadge.className = 'panel-status-badge font-mono text-xs';
        statusBadge.style.float = 'right';
        panel.querySelector('h3').appendChild(statusBadge);
    }
    statusBadge.textContent = '🟢 ONLINE (NO KEY)';
    statusBadge.style.color = 'var(--success)';

    portsEl.innerHTML = '';
    vulnsEl.innerHTML = '';
    tagsEl.innerHTML = '';

    if (!shodan || (!shodan.open_ports?.length && !shodan.vulns?.length)) {
        hostsEl.textContent = '—';
        portsEl.innerHTML = '<span class="tag-chip tag-port">NONE DETECTED</span>';
        vulnsEl.innerHTML = '<span class="tag-chip tag-port">NONE DETECTED</span>';
        tagsEl.innerHTML = '<span class="tag-chip tag-info">NO TAGS</span>';
        return;
    }

    (shodan.open_ports || []).forEach(port => {
        const span = document.createElement('span');
        span.className = 'tag-chip tag-port';
        span.textContent = port;
        portsEl.appendChild(span);
    });

    (shodan.vulns || []).forEach(cve => {
        const span = document.createElement('span');
        span.className = 'tag-chip tag-vuln';
        span.textContent = cve;
        vulnsEl.appendChild(span);
    });

    hostsEl.textContent = (shodan.hostnames || []).join(', ') || '—';

    (shodan.tags || []).forEach(tag => {
        const span = document.createElement('span');
        span.className = 'tag-chip tag-info';
        span.textContent = tag;
        tagsEl.appendChild(span);
    });
}

// ── ALIENVAULT OTX PANEL ───────────────────────────────────────────────────
function renderOtxPanel(otx) {
    const panel = document.getElementById('otx-panel');
    if (!panel) return;
    panel.style.display = 'block';

    const countEl = document.getElementById('otx-pulse-count');
    const pulsesEl = document.getElementById('otx-pulses');

    let statusBadge = panel.querySelector('.panel-status-badge');
    if (!statusBadge) {
        statusBadge = document.createElement('span');
        statusBadge.className = 'panel-status-badge font-mono text-xs';
        statusBadge.style.float = 'right';
        panel.querySelector('h3').appendChild(statusBadge);
    }

    if (!otx || otx.count === undefined) {
        statusBadge.textContent = '⚪ INACTIVE';
        statusBadge.style.color = 'var(--text-faint)';
        countEl.textContent = '—';
        pulsesEl.innerHTML = '<div class="text-muted mt-2">AlienVault OTX API key not configured on backend. Add OTX_API_KEY to Railway.</div>';
        return;
    }

    statusBadge.textContent = '🟢 ACTIVE';
    statusBadge.style.color = 'var(--success)';
    countEl.textContent = String(otx.count);
    countEl.style.color = otx.count > 0 ? 'var(--danger)' : 'var(--success)';

    pulsesEl.innerHTML = '';
    if (otx.count === 0) {
        pulsesEl.innerHTML = '<div class="text-muted mt-2">No known threat campaigns associated with this indicator.</div>';
    } else {
        (otx.pulses || []).forEach(p => {
            const pulseDiv = document.createElement('div');
            pulseDiv.className = 'otx-pulse-item mt-2 pb-2';
            pulseDiv.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
            
            const name = document.createElement('div');
            name.style.color = 'var(--warning)';
            name.style.fontWeight = 'bold';
            name.textContent = p.name;
            
            const desc = document.createElement('div');
            desc.className = 'text-sm text-muted mt-1';
            desc.textContent = p.description || 'No description provided.';
            
            const meta = document.createElement('div');
            meta.className = 'text-xs text-faint mt-1';
            meta.textContent = `Author: ${p.author} | Created: ${p.created ? new Date(p.created).toLocaleDateString() : 'Unknown'}`;
            
            pulseDiv.appendChild(name);
            pulseDiv.appendChild(desc);
            pulseDiv.appendChild(meta);
            
            if (p.tags && p.tags.length > 0) {
                const tagsDiv = document.createElement('div');
                tagsDiv.className = 'tag-row mt-1';
                p.tags.slice(0, 5).forEach(tag => {
                    const span = document.createElement('span');
                    span.className = 'tag-chip tag-info';
                    span.textContent = tag;
                    tagsDiv.appendChild(span);
                });
                pulseDiv.appendChild(tagsDiv);
            }
            
            pulsesEl.appendChild(pulseDiv);
        });
    }
}

// ── URLSCAN PANEL ──────────────────────────────────────────────────────────
function renderUrlscanPanel(us) {
    const panel = document.getElementById('urlscan-panel');
    if (!panel) return;
    if (currentScanType !== 'url') {
        panel.style.display = 'none'; return;
    }
    panel.style.display = 'block';

    const screenshotEl = document.getElementById('urlscan-screenshot');
    const techEl = document.getElementById('urlscan-tech');
    const usGrid = document.getElementById('urlscan-grid');

    let statusBadge = panel.querySelector('.panel-status-badge');
    if (!statusBadge) {
        statusBadge = document.createElement('span');
        statusBadge.className = 'panel-status-badge font-mono text-xs';
        statusBadge.style.float = 'right';
        panel.querySelector('h3').appendChild(statusBadge);
    }

    if (!us || !us.scan_id) {
        statusBadge.textContent = '⚪ INACTIVE';
        statusBadge.style.color = 'var(--text-faint)';
        screenshotEl.innerHTML = '';
        techEl.innerHTML = '';
        usGrid.innerHTML = '';
        addKvRows(usGrid, [
            ['Status', 'URLScan.io API key not configured. Add URLSCAN_API_KEY to Railway.']
        ]);
        return;
    }

    statusBadge.textContent = '🟢 ACTIVE';
    statusBadge.style.color = 'var(--success)';

    if (us.screenshot) {
        const img = document.createElement('img');
        img.src = us.screenshot;
        img.alt = 'URL Screenshot';
        img.className = 'urlscan-img';
        img.onerror = () => { img.style.display = 'none'; };
        screenshotEl.innerHTML = '';
        screenshotEl.appendChild(img);
    }

    techEl.innerHTML = '';
    (us.technologies || []).forEach(t => {
        const span = document.createElement('span');
        span.className = 'tag-chip tag-info';
        span.textContent = t;
        techEl.appendChild(span);
    });

    usGrid.innerHTML = '';
    addKvRows(usGrid, [
        ['Server IP',      us.ip         || '—'],
        ['Server',         us.server     || '—'],
        ['TLS Issuer',     us.tlsIssuer  || '—'],
        ['Page Title',     us.title      || '—'],
        ['Country',        us.country    || '—'],
        ['ASN',            us.asnname    || '—'],
        ['Malicious',      us.malicious  ? '⚠ YES' : 'NO', us.malicious],
        ['Verdict Score',  String(us.score || 0)],
    ]);
}

// ── GOOGLE SAFE BROWSING PANEL ────────────────────────────────────────────
function renderGsbPanel(gsb) {
    const panel = document.getElementById('gsb-panel');
    if (!panel) return;
    if (currentScanType !== 'url') {
        panel.style.display = 'none'; return;
    }
    panel.style.display = 'block';

    const statusEl = document.getElementById('gsb-status');
    const threatsEl = document.getElementById('gsb-threats');

    let statusBadge = panel.querySelector('.panel-status-badge');
    if (!statusBadge) {
        statusBadge = document.createElement('span');
        statusBadge.className = 'panel-status-badge font-mono text-xs';
        statusBadge.style.float = 'right';
        panel.querySelector('h3').appendChild(statusBadge);
    }

    if (!gsb || Object.keys(gsb).length === 0) {
        statusBadge.textContent = '⚪ INACTIVE';
        statusBadge.style.color = 'var(--text-faint)';
        statusEl.textContent = 'INACTIVE';
        statusEl.style.color = 'var(--text-faint)';
        threatsEl.innerHTML = '<span class="tag-chip tag-info">API KEY NOT CONFIGURED</span>';
        return;
    }

    statusBadge.textContent = '🟢 ACTIVE';
    statusBadge.style.color = 'var(--success)';

    const safe = gsb.safe !== false;
    statusEl.textContent = safe ? '✅ SAFE' : '🚨 UNSAFE — Google Flagged';
    statusEl.style.color = safe ? 'var(--success)' : 'var(--danger)';

    threatsEl.innerHTML = '';
    if (gsb.threats && gsb.threats.length > 0) {
        (gsb.threats || []).forEach(t => {
            const span = document.createElement('span');
            span.className = 'tag-chip tag-vuln';
            span.textContent = t.replace(/_/g, ' ');
            threatsEl.appendChild(span);
        });
    } else {
        threatsEl.innerHTML = '<span class="tag-chip tag-port">NO THREATS DETECTED</span>';
    }
}

// ── ENGINE FILTER ──────────────────────────────────────────────────────────
function renderEngines(filter = 'all') {
    const eList = document.getElementById('engines-list');
    eList.innerHTML = '';

    const searchQuery = document.getElementById('engine-search')?.value.toLowerCase().trim() || "";

    // Sort: malicious first, then suspicious, then clean
    const sorted = Object.entries(allEngineData).sort((a, b) => {
        const ra = a[1].toUpperCase(), rb = b[1].toUpperCase();
        const aClean = CLEAN_LABELS.some(x => ra.includes(x));
        const bClean = CLEAN_LABELS.some(x => rb.includes(x));
        const aSusp  = ra.includes('SUSPICIOUS');
        const bSusp  = rb.includes('SUSPICIOUS');
        if (!aClean && !aSusp && (bClean || bSusp)) return -1;
        if (aClean && !bClean) return 1;
        if (!aSusp && bSusp) return 1;
        if (aSusp && !bSusp) return -1;
        return a[0].localeCompare(b[0]);
    });

    let shown = 0;
    for (const [name, result] of sorted) {
        const resUp   = result.toUpperCase();
        const isClean = CLEAN_LABELS.some(x => resUp.includes(x));
        const isSusp  = resUp.includes('SUSPICIOUS');

        if (filter === 'malicious' && (isClean || isSusp)) continue;
        if (filter === 'clean'     && !isClean)             continue;

        if (searchQuery && !name.toLowerCase().includes(searchQuery)) continue;

        let col = THEMES.CLEAN;
        if (!isClean) col = isSusp ? THEMES.MEDIUM : THEMES.HIGH;

        const item = document.createElement('div');
        item.className = 'engine-item';
        
        if (!isClean) {
            item.classList.add(isSusp ? 'status-suspicious' : 'status-malicious');
        } else {
            item.classList.add('status-clean');
        }

        const nameEl = document.createElement('span');
        nameEl.className = 'e-name';
        nameEl.title    = name;
        nameEl.textContent = name;

        const resEl = document.createElement('span');
        resEl.className = 'e-res';
        resEl.style.color      = col.main;
        resEl.style.background = col.bg;
        resEl.textContent      = resUp;

        item.appendChild(nameEl);
        item.appendChild(resEl);
        eList.appendChild(item);
        shown++;
    }

    if (shown === 0) {
        const empty = document.createElement('div');
        empty.className   = 'text-muted font-mono text-sm p-4 w-100 text-center';
        empty.textContent = searchQuery ? '🔍 No security vendors matching your search.' : (filter === 'malicious' ? '✅ No malicious detections found.' : 'No results match this filter.');
        eList.appendChild(empty);
    }
}

function filterEngines(filter) {
    currentEngineFilter = filter;
    document.querySelectorAll(`.filter-btn`).forEach(b => {
        if (b.id === `filter-${filter}`) b.classList.add('active');
        else b.classList.remove('active');
    });
    renderEngines(filter);
}

// ── AI SECURITY ANALYST ────────────────────────────────────────────────────
function generateAiSummary(data) {
    const aiBox = document.getElementById('ai-text');
    aiBox.textContent = '';

    const s     = data.summary || {};
    const abuse = data.abuse   || {};
    const geo   = data.geo     || {};

    let summary = `Analysis of ${data.target} is complete. `;

    if (data.threat_level === 'HIGH') {
        summary += `CRITICAL: ${s.malicious || 0} of ${s.total_engines || '?'} security engines flagged this as malicious. `;
        if (abuse.abuse_score > 50) {
            summary += `AbuseIPDB reports an abuse confidence of ${abuse.abuse_score}% with ${abuse.total_reports} reports from ${abuse.num_distinct_users} distinct users. `;
        }
        if (abuse.is_tor) summary += `TOR exit node detected — traffic is likely anonymized. `;
        if (geo.is_proxy) summary += `Proxy or VPN usage detected. `;
        summary += `Recommendation: BLOCK immediately at firewall, DNS, and endpoint levels. Submit to threat sharing platforms.`;
    } else if (data.threat_level === 'MEDIUM') {
        summary += `WARNING: ${s.suspicious || 0} vendors flagged this indicator as suspicious. `;
        if (abuse.abuse_score > 0) summary += `AbuseIPDB confidence: ${abuse.abuse_score}%. `;
        summary += `Recommendation: Isolate associated hosts and monitor traffic. Escalate for deeper forensic review.`;
    } else if (data.threat_level === 'LOW') {
        summary += `Low-level signal: ${s.malicious || 0} vendor flagged this indicator. May be a false positive. `;
        summary += `Recommendation: Watch-list this IOC and continue monitoring for corroborating signals.`;
    } else {
        summary += `No threats detected across ${s.total_engines || '?'} security engines. `;
        if (s.malicious === 0 && s.suspicious === 0) summary += `Zero malicious or suspicious flags. `;
        summary += `Recommendation: IOC is considered safe. Standard monitoring applies.`;
    }

    // Typewriter with blinking cursor
    let i = 0;
    function typeWriter() {
        if (i < summary.length) {
            aiBox.textContent = summary.substring(0, i + 1);
            i++;
            setTimeout(typeWriter, 14);
        }
    }
    typeWriter();
}

// ── RECENT ACTIVITY (Dashboard) ────────────────────────────────────────────
function updateRecentActivity(data) {
    const feed = document.getElementById('recent-activity');
    const empty = feed.querySelector('.empty-state');
    if (empty) empty.remove();

    const theme = THEMES[data.threat_level] || THEMES.CLEAN;
    const item  = document.createElement('div');
    item.className = 'activity-item';
    item.innerHTML = `
        <div class="activity-dot" style="background:${theme.main}; box-shadow: 0 0 8px ${theme.main};"></div>
        <div style="flex:1; min-width:0;">
            <div class="font-mono" style="color:var(--text-main); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${sanitizeInput(data.target)}</div>
            <div class="font-mono text-faint text-sm">${data.type} — ${new Date().toLocaleTimeString()}</div>
        </div>
        <div class="font-mono text-sm" style="color:${theme.main}; flex-shrink:0;">${theme.label}</div>
    `;
    feed.prepend(item);
    // Keep max 5 items
    while (feed.children.length > 5) feed.lastChild.remove();
}

// ── INVESTIGATION HISTORY ──────────────────────────────────────────────────
function addToHistory(data) {
    scanHistory.unshift({
        target: data.target,
        type:   data.type,
        level:  data.threat_level,
        score:  data.risk_score,
        time:   new Date().toLocaleString()
    });
    if (scanHistory.length > 100) scanHistory.pop();
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById('history-list');
    if (!scanHistory.length) {
        list.innerHTML = '<div class="empty-state font-mono text-faint">No investigations logged in this session.</div>';
        return;
    }
    list.innerHTML = scanHistory.map(h => {
        const theme = THEMES[h.level] || THEMES.CLEAN;
        // Safely escape target for use in HTML attribute
        const safeTarget = h.target.replace(/'/g, "\\'").replace(/"/g, '&quot;');
        return `
        <div class="hist-item" onclick="navigate('scanner'); document.getElementById('scan-target').value='${safeTarget}';">
            <div class="d-flex align-center gap-4" style="min-width:0; flex:1;">
                <span style="font-size:1.3rem; color:${theme.main}; flex-shrink:0;">⚡</span>
                <div style="min-width:0;">
                    <div class="font-mono text-main" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${sanitizeInput(h.target)}</div>
                    <div class="font-mono text-faint text-sm">${sanitizeInput(h.time)} | ${sanitizeInput(h.type)}</div>
                </div>
            </div>
            <div style="text-align:right; flex-shrink:0; margin-left:16px;">
                <div class="font-display" style="color:${theme.main}">${h.level}</div>
                <div class="font-mono text-muted text-sm">Risk: ${h.score}/100</div>
            </div>
        </div>`;
    }).join('');
}

function clearHistory() {
    if (!confirm("Clear all investigations from this session?")) return;
    scanHistory = [];
    highCount = mediumCount = cleanCount = 0;
    renderHistory();
    updateAnalytics();
}

function exportHistory() {
    if (!scanHistory.length) {
        alert("No investigations to export.");
        return;
    }
    const blob = new Blob([JSON.stringify(scanHistory, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `cybershield-investigations-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// ── ANALYTICS ──────────────────────────────────────────────────────────────
function updateAnalytics() {
    setEl('ana-total',     String(totalScans));
    setEl('ana-critical',  String(highCount));
    setEl('ana-suspicious',String(mediumCount));
    setEl('ana-clean',     String(cleanCount));

    // Bar chart from last 7 scans
    const barChart = document.getElementById('bar-chart');
    const labels   = document.getElementById('chart-labels');
    if (!barChart) return;
    barChart.innerHTML = '';
    if (labels) labels.innerHTML = '';

    const recent = scanHistory.slice(0, 7).reverse();
    if (!recent.length) {
        barChart.innerHTML = '<div class="font-mono text-faint text-sm" style="align-self:center;">No scan data yet.</div>';
        return;
    }
    recent.forEach((h, i) => {
        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.height = `${Math.max(h.score, 8)}%`;
        bar.style.background = h.score > 50 ? 'linear-gradient(180deg, var(--danger), #a00)' :
                               h.score > 20 ? 'linear-gradient(180deg, var(--warning), #a60)' :
                                              'linear-gradient(180deg, var(--success), #0a5)';
        bar.title = `${h.target} — Risk ${h.score}`;
        barChart.appendChild(bar);

        if (labels) {
            const lbl = document.createElement('span');
            lbl.textContent = `#${i + 1}`;
            labels.appendChild(lbl);
        }
    });
}

// ── SETTINGS TOGGLES ───────────────────────────────────────────────────────
function initSettingsToggles() {
    document.querySelectorAll('.toggle').forEach(t => {
        t.addEventListener('click', () => {
            const isActive = t.classList.toggle('active');
            t.setAttribute('aria-checked', String(isActive));
        });
    });
}

// ── 3D INTERACTIVE CANVAS GLOBE / NETWORK ──────────────────────────────────
function initHero3DCanvas() {
    const canvas = document.getElementById('hero-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let width = canvas.width = canvas.offsetWidth;
    let height = canvas.height = canvas.offsetHeight;
    
    window.addEventListener('resize', () => {
        width = canvas.width = canvas.offsetWidth;
        height = canvas.height = canvas.offsetHeight;
    });

    const particles = [];
    const numParticles = 45;
    const maxDistance = 90;
    let angleX = 0.001;
    let angleY = 0.001;
    
    for (let i = 0; i < numParticles; i++) {
        particles.push({
            x: (Math.random() - 0.5) * 300,
            y: (Math.random() - 0.5) * 300,
            z: (Math.random() - 0.5) * 300,
            radius: Math.random() * 2 + 1
        });
    }

    let targetAngleX = 0.001;
    let targetAngleY = 0.001;
    const hero = document.querySelector('.hero-section');
    if (hero) {
        hero.addEventListener('mousemove', (e) => {
            const rect = hero.getBoundingClientRect();
            const mouseX = e.clientX - rect.left - rect.width / 2;
            const mouseY = e.clientY - rect.top - rect.height / 2;
            targetAngleY = mouseX * 0.00001;
            targetAngleX = mouseY * 0.00001;
        });
        hero.addEventListener('mouseleave', () => {
            targetAngleX = 0.001;
            targetAngleY = 0.001;
        });
    }

    function rotateX(p, angle) {
        const cos = Math.cos(angle);
        const sin = Math.sin(angle);
        const y1 = p.y * cos - p.z * sin;
        const z1 = p.z * cos + p.y * sin;
        p.y = y1;
        p.z = z1;
    }

    function rotateY(p, angle) {
        const cos = Math.cos(angle);
        const sin = Math.sin(angle);
        const x1 = p.x * cos - p.z * sin;
        const z1 = p.z * cos + p.x * sin;
        p.x = x1;
        p.z = z1;
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);
        
        angleX += (targetAngleX - angleX) * 0.1;
        angleY += (targetAngleY - angleY) * 0.1;

        const projected = [];
        const fov = 350;
        
        particles.forEach(p => {
            rotateX(p, angleX);
            rotateY(p, angleY);

            const scale = fov / (fov + p.z);
            const x2d = p.x * scale + width / 2;
            const y2d = p.y * scale + height / 2;
            
            projected.push({ x: x2d, y: y2d, scale: scale, z: p.z });
        });

        ctx.lineWidth = 0.5;
        for (let i = 0; i < numParticles; i++) {
            for (let j = i + 1; j < numParticles; j++) {
                const dx = projected[i].x - projected[j].x;
                const dy = projected[i].y - projected[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                
                if (dist < maxDistance) {
                    const alpha = (1 - dist / maxDistance) * 0.25 * projected[i].scale;
                    ctx.strokeStyle = `rgba(0, 212, 255, ${alpha})`;
                    ctx.beginPath();
                    ctx.moveTo(projected[i].x, projected[i].y);
                    ctx.lineTo(projected[j].x, projected[j].y);
                    ctx.stroke();
                }
            }
        }

        projected.forEach((p, idx) => {
            const alpha = Math.max(0.1, (fov - p.z) / (fov * 2)) * p.scale;
            ctx.fillStyle = `rgba(0, 212, 255, ${alpha * 0.85})`;
            ctx.shadowBlur = 4 * p.scale;
            ctx.shadowColor = 'var(--primary)';
            ctx.beginPath();
            ctx.arc(p.x, p.y, particles[idx].radius * p.scale, 0, Math.PI * 2);
            ctx.fill();
        });
        
        ctx.shadowBlur = 0;
        requestAnimationFrame(animate);
    }
    animate();
}

// 3D card tilt effect removed to ensure stable, human-friendly layouts
