from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
import base64
import asyncio
from dotenv import load_dotenv
from datetime import datetime

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load API keys from .env file
load_dotenv()
VT_API_KEY        = os.getenv("VIRUSTOTAL_API_KEY", "").replace("VIRUSTOTAL_API_KEY=", "").strip()
ABUSE_API_KEY     = os.getenv("ABUSEIPDB_API_KEY", "").replace("ABUSEIPDB_API_KEY=", "").strip()
IPINFO_API_KEY    = os.getenv("IPINFO_API_KEY", "").strip()
OTX_API_KEY       = os.getenv("OTX_API_KEY", "").strip()
URLSCAN_API_KEY   = os.getenv("URLSCAN_API_KEY", "").strip()
GOOGLE_SB_KEY     = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip()

# FRONTEND_URL defines exactly which website is allowed to call this API.
# It defaults to allowing localhost for development if not set.
FRONTEND_URL  = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500")

# Create the app
app = FastAPI(
    title="CyberShield AI Enterprise API",
    description="Enterprise Threat Intelligence Platform Backend",
    version="2.0.0"
)

# Set up Rate Limiter (50 requests per minute per IP for enterprise tier)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Enterprise CORS Configuration - Only allowed origins can communicate
allowed_origins = [
    FRONTEND_URL,
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://localhost:5500"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Comprehensive Security Headers to prevent XSS, Clickjacking, and Sniffing
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Hide the fact that we are using FastAPI/Python
    response.headers["Server"] = "CyberShield-Enterprise"
    return response

# Request Payload Schema
class ScanRequest(BaseModel):
    target: str       # URL, Domain, or IP
    scan_type: str    # "url" or "ip"


# ══════════════════════════════════════════
#  VIRUSTOTAL SCAN LOGIC
# ══════════════════════════════════════════
async def vt_scan_url(url: str, client: httpx.AsyncClient) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        # Try cached report first
        response = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=20
        )

        if response.status_code == 404:
            # Submit for fresh scan
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=20
            )
            if submit.status_code != 200:
                return {"error": f"VT submission failed: {submit.status_code}"}

            analysis_id = submit.json()["data"]["id"]
            await asyncio.sleep(4)

            response = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=20
            )

        if response.status_code != 200:
            return {"error": f"VirusTotal returned: {response.status_code}"}

        data  = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats   = attrs.get("last_analysis_stats") or attrs.get("stats", {})
        results = attrs.get("last_analysis_results") or attrs.get("results", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        clean      = harmless + undetected
        total      = max(malicious + suspicious + clean, 1)

        engines = {}
        for engine, detail in list(results.items())[:50]:
            engines[engine] = detail.get("category", "undetected").upper()

        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "undetected": undetected,
            "clean":      clean,
            "total":      total,
            "engines":    engines,
            "risk_score": round((malicious + suspicious * 0.5) / total * 100),
        }

    except httpx.TimeoutException:
        return {"error": "VirusTotal timed out — try again"}
    except Exception as e:
        print(f"[SECURITY LOG] VT Engine Error: {e}") # Log internally, never to frontend
        return {"error": "Internal intelligence engine error. Request blocked."}

async def vt_scan_ip(ip: str, client: httpx.AsyncClient) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}

    try:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=20
        )

        if response.status_code != 200:
            return {"error": f"VirusTotal returned: {response.status_code}"}

        data    = response.json()
        attrs   = data.get("data", {}).get("attributes", {})
        stats   = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        clean      = harmless + undetected
        total      = max(malicious + suspicious + clean, 1)

        engines = {}
        for engine, detail in list(results.items())[:50]:
            engines[engine] = detail.get("category", "undetected").upper()

        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "undetected": undetected,
            "clean":      clean,
            "total":      total,
            "engines":    engines,
            "risk_score": round((malicious + suspicious * 0.5) / total * 100),
            "country":    attrs.get("country", "Unknown"),
            "asn":        attrs.get("asn", "Unknown"),
            "as_owner":   attrs.get("as_owner", "Unknown"),
            "tags":       attrs.get("tags", []),
        }

    except httpx.TimeoutException:
        return {"error": "VirusTotal timed out — try again"}
    except Exception as e:
        print(f"[SECURITY LOG] VT Engine Error: {e}") # Log internally
        return {"error": "Internal intelligence engine error. Request blocked."}


# ══════════════════════════════════════════
#  ABUSEIPDB
# ══════════════════════════════════════════
async def check_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    if not ABUSE_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}

    try:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=15
        )

        if response.status_code != 200:
            return {"error": f"AbuseIPDB returned: {response.status_code}"}

        d = response.json().get("data", {})
        return {
            "abuse_score":        d.get("abuseConfidenceScore", 0),
            "country":            d.get("countryCode", "Unknown"),
            "isp":                d.get("isp", "Unknown"),
            "domain":             d.get("domain", "Unknown"),
            "total_reports":      d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "is_tor":             d.get("isTor", False),
            "is_public":          d.get("isPublic", True),
            "usage_type":         d.get("usageType", "Unknown"),
            "last_reported":      d.get("lastReportedAt", "Never"),
        }

    except httpx.TimeoutException:
        return {"error": "AbuseIPDB timed out — try again"}
    except Exception as e:
        print(f"[SECURITY LOG] AbuseIPDB Engine Error: {e}") # Log internally
        return {"error": "Internal intelligence engine error. Request blocked."}


# ══════════════════════════════════════════
#  IP-API (Geolocation)
# ══════════════════════════════════════════
async def get_ip_geo(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        response = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,isp,org,as,hosting,proxy,mobile"},
            timeout=10
        )
        return response.json()
    except Exception:
        return {}


# ══════════════════════════════════════════
#  SHODAN InternetDB (No API key needed!)
#  Adds: open ports, CVEs, hostnames, tags
# ══════════════════════════════════════════
async def get_shodan_internetdb(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        response = await client.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return {}
    except Exception:
        return {}


# ══════════════════════════════════════════
#  ALIENVAULT OTX (Open Threat Exchange)
#  Adds: threat pulses/campaigns
# ══════════════════════════════════════════
async def check_alienvault_otx(indicator: str, indicator_type: str, client: httpx.AsyncClient) -> dict:
    if not OTX_API_KEY:
        return {}
    
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = await client.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            d = response.json()
            pulse_info = d.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            
            pulse_list = []
            for p in pulses[:5]:  # Return top 5 pulses
                pulse_list.append({
                    "name": p.get("name", "Unknown Threat Campaign"),
                    "description": p.get("description", ""),
                    "author": p.get("author_name", "Anonymous"),
                    "created": p.get("created", ""),
                    "tags": p.get("tags", [])
                })
            
            return {
                "count": pulse_info.get("count", 0),
                "pulses": pulse_list
            }
        return {}
    except Exception as e:
        print(f"[SECURITY LOG] AlienVault OTX error: {e}")
        return {}


# ══════════════════════════════════════════
#  URLSCAN.IO
#  Adds: screenshot, technologies, DNS, IPs
# ══════════════════════════════════════════
async def get_urlscan(url: str, client: httpx.AsyncClient) -> dict:
    if not URLSCAN_API_KEY:
        return {}
    try:
        # Submit scan
        submit = await client.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"},
            json={"url": url, "visibility": "public"},
            timeout=15
        )
        if submit.status_code not in (200, 201):
            return {}
        scan_id = submit.json().get("uuid", "")
        if not scan_id:
            return {}

        # Wait briefly then fetch result
        await asyncio.sleep(10)
        result = await client.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            timeout=15
        )
        if result.status_code != 200:
            return {"scan_id": scan_id, "screenshot": f"https://urlscan.io/screenshots/{scan_id}.png"}

        d = result.json()
        page = d.get("page", {})
        meta = d.get("meta", {})
        verdicts = d.get("verdicts", {}).get("overall", {})
        technologies = [t.get("name") for t in d.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])]

        return {
            "scan_id":      scan_id,
            "screenshot":   f"https://urlscan.io/screenshots/{scan_id}.png",
            "final_url":    page.get("url", url),
            "server":       page.get("server", "Unknown"),
            "country":      page.get("country", "Unknown"),
            "ip":           page.get("ip", "Unknown"),
            "asn":          page.get("asn", "Unknown"),
            "asnname":      page.get("asnname", "Unknown"),
            "title":        page.get("title", ""),
            "tlsIssuer":    page.get("tlsIssuer", "Unknown"),
            "malicious":    verdicts.get("malicious", False),
            "score":        verdicts.get("score", 0),
            "technologies": technologies[:10],  # Top 10 detected tech
        }
    except Exception as e:
        print(f"[SECURITY LOG] URLScan error: {e}")
        return {}


# ══════════════════════════════════════════
#  GOOGLE SAFE BROWSING
#  Adds: Google's phishing/malware verdict
# ══════════════════════════════════════════
async def check_google_safe_browsing(url: str, client: httpx.AsyncClient) -> dict:
    if not GOOGLE_SB_KEY:
        return {}
    try:
        payload = {
            "client": {"clientId": "cybershield-ai", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}",
            json=payload,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            return {
                "safe":      len(matches) == 0,
                "threats":   [m.get("threatType", "Unknown") for m in matches],
                "platform":  [m.get("platformType", "") for m in matches],
            }
        return {}
    except Exception as e:
        print(f"[SECURITY LOG] Google SB error: {e}")
        return {}


# ══════════════════════════════════════════
#  IPINFO.IO
#  Adds: hostname, company, privacy flags
# ══════════════════════════════════════════
async def get_ipinfo(ip: str, client: httpx.AsyncClient) -> dict:
    if not IPINFO_API_KEY:
        return {}
    try:
        response = await client.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"Authorization": f"Bearer {IPINFO_API_KEY}"},
            timeout=10
        )
        if response.status_code == 200:
            d = response.json()
            privacy = d.get("privacy", {})
            return {
                "hostname":   d.get("hostname", ""),
                "org":        d.get("org", ""),
                "timezone":   d.get("timezone", ""),
                "company":    d.get("company", {}).get("name", ""),
                "type":       d.get("company", {}).get("type", ""),
                "vpn":        privacy.get("vpn", False),
                "proxy":      privacy.get("proxy", False),
                "tor":        privacy.get("tor", False),
                "relay":      privacy.get("relay", False),
                "hosting":    privacy.get("hosting", False),
                "abuse_contact": d.get("abuse", {}).get("email", ""),
            }
        return {}
    except Exception:
        return {}


async def get_domain_info(url: str, client: httpx.AsyncClient) -> dict:
    try:
        domain = url.replace("https://","").replace("http://","").split("/")[0].split("?")[0]
        response = await client.get(f"https://api.whois.vu/?q={domain}", timeout=10)
        return response.json()
    except Exception:
        return {}


# ══════════════════════════════════════════
#  API ROUTES (Endpoints MUST NOT Change)
# ══════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "status":  "CyberShield Enterprise API is ONLINE",
        "version": "2.0.0",
        "health":  "/health",
        "time":    datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    """System heartbeat endpoint used by the frontend SOC dashboard"""
    return {
        "status":        "online",
        "vt_key_set":    bool(VT_API_KEY),
        "abuse_key_set": bool(ABUSE_API_KEY),
        "time":          datetime.now().isoformat()
    }

@app.post("/scan")
@limiter.limit("50/minute")
async def scan(request: Request, req: ScanRequest):
    """Core Threat Intelligence Engine endpoint"""
    target    = req.target.strip()
    scan_type = req.scan_type.strip().lower()

    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    if len(target) > 500:
        raise HTTPException(status_code=400, detail="Target too long")
    if scan_type not in ["url", "ip"]:
        raise HTTPException(status_code=400, detail="scan_type must be url or ip")

    # WAF - Block basic injection attempts
    for bad in ["<script", "javascript:", "DROP TABLE", "../etc"]:
        if bad.lower() in target.lower():
            raise HTTPException(status_code=400, detail="Malicious input detected by WAF")

    async with httpx.AsyncClient() as client:

        # ── URL/DOMAIN INTELLIGENCE ──────────────────────────────────────────
        if scan_type == "url":
            domain = target.replace("https://","").replace("http://","").split("/")[0].split("?")[0]
            vt_data, domain_data, gsb_data, urlscan_data, otx_data = await asyncio.gather(
                vt_scan_url(target, client),
                get_domain_info(target, client),
                check_google_safe_browsing(target, client),
                get_urlscan(target, client),
                check_alienvault_otx(domain, "domain", client)
            )

            malicious = vt_data.get("malicious", 0)
            threat_level = (
                "HIGH"   if malicious >= 5 else
                "MEDIUM" if malicious >= 2 else
                "LOW"    if malicious >= 1 else
                "CLEAN"
            )

            # Upgrade threat level if Google flags it or OTX finds threat pulses
            if gsb_data.get("threats"):
                if threat_level in ("CLEAN", "LOW"):
                    threat_level = "MEDIUM"
            if otx_data.get("count", 0) > 0:
                if threat_level in ("CLEAN", "LOW"):
                    threat_level = "MEDIUM"

            return {
                "type":         "URL Analysis",
                "target":       target,
                "threat_level": threat_level,
                "risk_score":   vt_data.get("risk_score", 0),
                "summary": {
                    "malicious":     vt_data.get("malicious", 0),
                    "suspicious":    vt_data.get("suspicious", 0),
                    "harmless":      vt_data.get("harmless", 0),
                    "undetected":    vt_data.get("undetected", 0),
                    "clean":         vt_data.get("clean", 0),
                    "total_engines": vt_data.get("total", 0),
                },
                "engines":       vt_data.get("engines", {}),
                "domain_info":   domain_data,
                "google_sb":     gsb_data,
                "urlscan":       urlscan_data,
                "otx":           otx_data,
                "error":         vt_data.get("error"),
                "scanned_at":    datetime.now().isoformat(),
            }

        # ── IP INTELLIGENCE ───────────────────────────────────────────
        elif scan_type == "ip":
            vt_data, abuse_data, geo_data, shodan_data, otx_data, ipinfo_data = await asyncio.gather(
                vt_scan_ip(target, client),
                check_abuseipdb(target, client),
                get_ip_geo(target, client),
                get_shodan_internetdb(target, client),
                check_alienvault_otx(target, "IPv4", client),
                get_ipinfo(target, client)
            )

            malicious_vt = vt_data.get("malicious", 0)
            abuse_score  = abuse_data.get("abuse_score", 0)
            vt_score     = vt_data.get("risk_score", 0)

            threat_level = (
                "HIGH"   if malicious_vt >= 5 or abuse_score >= 50 else
                "MEDIUM" if malicious_vt >= 2 or abuse_score >= 25 else
                "LOW"    if malicious_vt >= 1 or abuse_score >= 10 else
                "CLEAN"
            )

            # Upgrade threat level based on Shodan/OTX signals
            if shodan_data.get("vulns"):  # Has known CVEs
                if threat_level == "CLEAN":
                    threat_level = "LOW"
            if otx_data.get("count", 0) > 0:
                if threat_level in ("CLEAN", "LOW"):
                    threat_level = "MEDIUM"

            return {
                "type":         "IP Reputation",
                "target":       target,
                "threat_level": threat_level,
                "risk_score":   round((vt_score + abuse_score) / 2),
                "summary": {
                    "malicious":     vt_data.get("malicious", 0),
                    "suspicious":    vt_data.get("suspicious", 0),
                    "harmless":      vt_data.get("harmless", 0),
                    "undetected":    vt_data.get("undetected", 0),
                    "clean":         vt_data.get("clean", 0),
                    "total_engines": vt_data.get("total", 0),
                    "abuse_score":   abuse_score,
                    "abuse_reports": abuse_data.get("total_reports", 0),
                },
                "engines": vt_data.get("engines", {}),
                "geo": {
                    "country":    geo_data.get("country",    vt_data.get("country", "Unknown")),
                    "city":       geo_data.get("city",       "Unknown"),
                    "region":     geo_data.get("regionName", "Unknown"),
                    "isp":        geo_data.get("isp",        abuse_data.get("isp", "Unknown")),
                    "org":        geo_data.get("org",        "Unknown"),
                    "asn":        geo_data.get("as",         "Unknown"),
                    "is_hosting": geo_data.get("hosting",    ipinfo_data.get("hosting", False)),
                    "is_proxy":   geo_data.get("proxy",      ipinfo_data.get("proxy", False)),
                    "is_mobile":  geo_data.get("mobile",     False),
                    "usage_type": abuse_data.get("usage_type", "Unknown"),
                    "hostname":   ipinfo_data.get("hostname", ""),
                    "timezone":   ipinfo_data.get("timezone", ""),
                    "company":    ipinfo_data.get("company", ""),
                    "ip_type":    ipinfo_data.get("type", ""),
                    "is_vpn":     ipinfo_data.get("vpn", False),
                    "is_tor":     ipinfo_data.get("tor",  abuse_data.get("is_tor", False)),
                    "is_relay":   ipinfo_data.get("relay", False),
                    "abuse_contact": ipinfo_data.get("abuse_contact", ""),
                },
                "abuse": {
                    "abuse_score":        abuse_data.get("abuse_score", 0),
                    "total_reports":      abuse_data.get("total_reports", 0),
                    "num_distinct_users": abuse_data.get("num_distinct_users", 0),
                    "isp":                abuse_data.get("isp", "Unknown"),
                    "domain":             abuse_data.get("domain", "Unknown"),
                    "usage_type":         abuse_data.get("usage_type", "Unknown"),
                    "is_tor":             abuse_data.get("is_tor", False),
                    "is_public":          abuse_data.get("is_public", True),
                    "last_reported":      abuse_data.get("last_reported", "Never"),
                },
                # 🆕 Shodan InternetDB data (open ports + CVEs)
                "shodan": {
                    "open_ports": shodan_data.get("ports", []),
                    "vulns":      shodan_data.get("vulns", []),
                    "hostnames":  shodan_data.get("hostnames", []),
                    "tags":       shodan_data.get("tags", []),
                    "cpes":       shodan_data.get("cpes", []),
                },
                # 🆕 AlienVault OTX pulses
                "otx": otx_data,
                "vt_extra": {
                    "as_owner": vt_data.get("as_owner", "Unknown"),
                    "tags":     vt_data.get("tags", []),
                },
                "error":      vt_data.get("error") or abuse_data.get("error"),
                "scanned_at": datetime.now().isoformat(),
            }
