"""
╔══════════════════════════════════════════════════════════╗
║           CYBERSHIELD BACKEND — FastAPI Server           ║
║  🧠 LESSON: This is your Python backend. It does 3 things:║
║  1. Hides your API keys (never exposed to frontend)      ║
║  2. Calls VirusTotal, AbuseIPDB, WHOIS APIs              ║
║  3. Returns clean JSON results to your React frontend    ║
╚══════════════════════════════════════════════════════════╝
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx          # like Python's requests library but async
import os
import base64
import asyncio
from dotenv import load_dotenv
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# 🧠 LESSON: load_dotenv() reads your .env file and loads
# API keys as environment variables. This way keys are NEVER
# hardcoded in your code. Safe for GitHub, safe for production.
# ─────────────────────────────────────────────────────────────
load_dotenv()

VT_API_KEY    = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# ─────────────────────────────────────────────────────────────
# 🧠 LESSON: FastAPI() creates your web server.
# Think of it like: "I'm opening a shop that accepts requests"
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="CyberShield API", version="1.0.0")

# ─────────────────────────────────────────────────────────────
# 🧠 LESSON: CORS lets your React frontend (on a different port)
# talk to this backend. Without this, the browser blocks it.
# ─────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: specify your domain
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# 🧠 LESSON: BaseModel = data validation. If frontend sends
# wrong data, FastAPI auto-rejects it with a clear error.
# Like Python type hints but with automatic checking.
# ─────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    scan_type: str  # "url" or "ip"


# ══════════════════════════════════════════════════════════════
#  VIRUSTOTAL FUNCTIONS
# ══════════════════════════════════════════════════════════════

async def vt_scan_url(url: str, client: httpx.AsyncClient) -> dict:
    """
    🧠 LESSON: This is an ASYNC function — it runs without
    blocking other requests. While waiting for VirusTotal,
    your server can handle other users simultaneously.
    
    VirusTotal URL scan has 2 steps:
    Step 1: Submit URL → get analysis ID
    Step 2: Use ID to fetch the full report
    """
    headers = {"x-apikey": VT_API_KEY}

    # Step 1: Submit URL for scanning
    # VirusTotal needs the URL base64-encoded (their requirement)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        # First check if URL already has a report (saves API quota)
        response = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            # URL not in cache — submit it for fresh scan
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )
            if submit.status_code != 200:
                return {"error": "VirusTotal submission failed"}

            analysis_id = submit.json()["data"]["id"]

            # Wait a moment then fetch results
            await asyncio.sleep(3)

            response = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15
            )

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("stats", {}) or \
                data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        results = data.get("data", {}).get("attributes", {}).get("results", {}) or \
                  data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        clean      = stats.get("harmless", 0) + stats.get("undetected", 0)
        total      = malicious + suspicious + clean or 1

        # Build engine results dict (top 20 engines)
        engines = {}
        for engine, detail in list(results.items())[:20]:
            cat = detail.get("category", "undetected")
            engines[engine] = cat.upper()

        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "clean":      clean,
            "total":      total,
            "engines":    engines,
            "risk_score": round((malicious + suspicious * 0.5) / total * 100) if total > 0 else 0,

        }

    except Exception as e:
        return {"error": str(e)}


async def vt_scan_ip(ip: str, client: httpx.AsyncClient) -> dict:
    """Fetch IP report from VirusTotal"""
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers, timeout=15
        )
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        results = data.get("last_analysis_results", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        clean      = stats.get("harmless", 0) + stats.get("undetected", 0)
        total      = malicious + suspicious + clean or 1

        engines = {}
        for engine, detail in list(results.items())[:20]:
            engines[engine] = detail.get("category", "undetected").upper()

        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "clean":      clean,
            "total":      total,
            "engines":    engines,
            "risk_score": round((malicious + suspicious * 0.5) / total * 100) if total > 0 else 0,

            "country":    data.get("country", "Unknown"),
            "asn":        data.get("asn", "Unknown"),
            "as_owner":   data.get("as_owner", "Unknown"),
        }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════
#  ABUSEIPDB FUNCTION
# ══════════════════════════════════════════════════════════════

async def check_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    """
    🧠 LESSON: AbuseIPDB tracks IPs reported for malicious 
    activity. We pass our API key in the header (not in URL).
    This is standard API authentication practice.
    """
    try:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=15
        )
        d = response.json().get("data", {})
        return {
            "abuse_score":    d.get("abuseConfidenceScore", 0),
            "country":        d.get("countryCode", "Unknown"),
            "isp":            d.get("isp", "Unknown"),
            "domain":         d.get("domain", "Unknown"),
            "total_reports":  d.get("totalReports", 0),
            "is_tor":         d.get("isTor", False),
            "is_public":      d.get("isPublic", True),
            "usage_type":     d.get("usageType", "Unknown"),
            "last_reported":  d.get("lastReportedAt", "Never"),
        }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════
#  WHOIS / IP-API FUNCTION (free, no key needed)
# ══════════════════════════════════════════════════════════════

async def get_ip_geo(ip: str, client: httpx.AsyncClient) -> dict:
    """Get geolocation and ISP info — ip-api.com is free"""
    try:
        response = await client.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,hosting",
            timeout=10
        )
        return response.json()
    except:
        return {}


async def get_domain_info(url: str, client: httpx.AsyncClient) -> dict:
    """Extract domain details using free whois API"""
    try:
        # Extract domain from URL
        domain = url.replace("https://","").replace("http://","").split("/")[0]
        response = await client.get(
            f"https://api.whois.vu/?q={domain}",
            timeout=10
        )
        return response.json()
    except:
        return {}


# ══════════════════════════════════════════════════════════════
#  API ROUTES — These are the endpoints your React app calls
# ══════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    """Health check — visit http://localhost:8000 to confirm running"""
    return {
        "status": "🛡️ CyberShield API is ONLINE",
        "version": "1.0.0",
        "endpoints": ["/scan", "/health"],
        "time": datetime.now().isoformat()
    }


@app.get("/health")
async def health():
    return {
        "status": "online",
        "vt_key_set":    bool(VT_API_KEY),
        "abuse_key_set": bool(ABUSE_API_KEY),
        "time": datetime.now().isoformat()
    }


@app.post("/scan")
async def scan(req: ScanRequest):
    """
    🧠 LESSON: This is the MAIN endpoint.
    React sends: { "target": "google.com", "scan_type": "url" }
    We call all APIs in PARALLEL (asyncio.gather) — much faster
    than calling one by one.
    """
    target    = req.target.strip()
    scan_type = req.scan_type

    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    # ─────────────────────────────────────────────────────────
    # 🧠 LESSON: httpx.AsyncClient is like the requests library
    # but async. We open one connection pool for all API calls.
    # ─────────────────────────────────────────────────────────
    async with httpx.AsyncClient() as client:

        if scan_type == "url":
            # Run VirusTotal + domain info IN PARALLEL
            vt_data, domain_data = await asyncio.gather(
                vt_scan_url(target, client),
                get_domain_info(target, client)
            )
            malicious = vt_data.get("malicious", 0)
            threat_level = (
                "HIGH"   if malicious >= 5  else
                "MEDIUM" if malicious >= 2  else
                "LOW"    if malicious >= 1  else
                "CLEAN"
            )

            return {
                "type":         "URL Analysis",
                "target":       target,
                "threat_level": threat_level,
                "risk_score":   vt_data.get("risk_score", 0),
                "summary": {
                    "malicious":  vt_data.get("malicious", 0),
                    "suspicious": vt_data.get("suspicious", 0),
                    "clean":      vt_data.get("clean", 0),
                    "total_engines": vt_data.get("total", 0),
                },
                "engines":  vt_data.get("engines", {}),
                "domain_info": domain_data,
                "scanned_at":   datetime.now().isoformat(),
            }

        elif scan_type == "ip":
            # Run VirusTotal + AbuseIPDB + GeoIP ALL IN PARALLEL
            vt_data, abuse_data, geo_data = await asyncio.gather(
                vt_scan_ip(target, client),
                check_abuseipdb(target, client),
                get_ip_geo(target, client)
            )

            # Combine risk scores from both sources
            vt_score    = vt_data.get("risk_score", 0)
            abuse_score = abuse_data.get("abuse_score", 0)
            combined    = round((vt_score + abuse_score) / 2)

            threat_level = (
                "HIGH"   if combined >= 30 or abuse_score >= 50 else
                "MEDIUM" if combined >= 10 or abuse_score >= 20 else
                "CLEAN"
            )

            return {
                "type":         "IP Reputation",
                "target":       target,
                "threat_level": threat_level,
                "risk_score":   combined,
                "summary": {
                    "malicious":     vt_data.get("malicious", 0),
                    "abuse_reports": abuse_data.get("total_reports", 0),
                    "abuse_score":   abuse_score,
                    "is_tor":        abuse_data.get("is_tor", False),
                },
                "engines":    vt_data.get("engines", {}),
                "geo": {
                    "country":    geo_data.get("country", vt_data.get("country", "Unknown")),
                    "city":       geo_data.get("city", "Unknown"),
                    "region":     geo_data.get("regionName", "Unknown"),
                    "isp":        geo_data.get("isp", abuse_data.get("isp", "Unknown")),
                    "org":        geo_data.get("org", "Unknown"),
                    "is_hosting": geo_data.get("hosting", False),
                    "usage_type": abuse_data.get("usage_type", "Unknown"),
                },
                "abuse": abuse_data,
                "scanned_at": datetime.now().isoformat(),
            }

        else:
            raise HTTPException(status_code=400, detail="scan_type must be 'url' or 'ip'")
