from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
import base64
import asyncio
from dotenv import load_dotenv
from datetime import datetime

# Load API keys from .env file
load_dotenv()
VT_API_KEY    = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Create the app
app = FastAPI(
    title="CyberShield API",
    description="AI-powered threat intelligence platform",
    version="1.0.0"
)

# CORS — lets your frontend talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://bgm8.github.io/cybershield/"
                   "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# What the frontend sends us
class ScanRequest(BaseModel):
    target: str       # the URL or IP to scan
    scan_type: str    # "url" or "ip"


# ══════════════════════════════════════════
#  VIRUSTOTAL — SCAN A URL
# ══════════════════════════════════════════
async def vt_scan_url(url: str, client: httpx.AsyncClient) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not set in .env file"}

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
        return {"error": str(e)}


# ══════════════════════════════════════════
#  VIRUSTOTAL — SCAN AN IP
# ══════════════════════════════════════════
async def vt_scan_ip(ip: str, client: httpx.AsyncClient) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not set in .env file"}

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
        return {"error": str(e)}


# ══════════════════════════════════════════
#  ABUSEIPDB — IP REPUTATION
# ══════════════════════════════════════════
async def check_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    if not ABUSE_API_KEY:
        return {"error": "AbuseIPDB API key not set in .env file"}

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
        return {"error": str(e)}


# ══════════════════════════════════════════
#  IP-API — FREE GEOLOCATION (no key needed)
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
#  WHOIS — DOMAIN INFO (free, no key needed)
# ══════════════════════════════════════════
async def get_domain_info(url: str, client: httpx.AsyncClient) -> dict:
    try:
        domain = url.replace("https://","").replace("http://","").split("/")[0].split("?")[0]
        response = await client.get(f"https://api.whois.vu/?q={domain}", timeout=10)
        return response.json()
    except Exception:
        return {}


# ══════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════

@app.get("/")
async def root():
    """Open http://localhost:8080 in browser to confirm server is running"""
    return {
        "status":  "CyberShield API is ONLINE",
        "version": "1.0.0",
        "docs":    "/docs",
        "health":  "/health",
        "time":    datetime.now().isoformat()
    }


@app.get("/health")
async def health():
    """Open http://localhost:8080/health — checks if API keys are loaded"""
    return {
        "status":        "online",
        "vt_key_set":    bool(VT_API_KEY),
        "abuse_key_set": bool(ABUSE_API_KEY),
        "time":          datetime.now().isoformat()
    }


@app.post("/scan")
async def scan(req: ScanRequest):
    """Main scan endpoint — called by the frontend"""
    target    = req.target.strip()
    scan_type = req.scan_type.strip().lower()

    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    if len(target) > 500:
        raise HTTPException(status_code=400, detail="Target too long")
    if scan_type not in ["url", "ip"]:
        raise HTTPException(status_code=400, detail="scan_type must be url or ip")

    # Block obvious injection attempts
    for bad in ["<script", "javascript:", "DROP TABLE", "../etc"]:
        if bad.lower() in target.lower():
            raise HTTPException(status_code=400, detail="Invalid input")

    async with httpx.AsyncClient() as client:

        # ── URL SCAN ──────────────────────────────────────────
        if scan_type == "url":
            vt_data, domain_data = await asyncio.gather(
                vt_scan_url(target, client),
                get_domain_info(target, client)
            )

            malicious = vt_data.get("malicious", 0)
            threat_level = (
                "HIGH"   if malicious >= 5 else
                "MEDIUM" if malicious >= 2 else
                "LOW"    if malicious >= 1 else
                "CLEAN"
            )

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
                "engines":     vt_data.get("engines", {}),
                "domain_info": domain_data,
                "error":       vt_data.get("error"),
                "scanned_at":  datetime.now().isoformat(),
            }

        # ── IP SCAN ───────────────────────────────────────────
        elif scan_type == "ip":
            vt_data, abuse_data, geo_data = await asyncio.gather(
                vt_scan_ip(target, client),
                check_abuseipdb(target, client),
                get_ip_geo(target, client)
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
                    "is_hosting": geo_data.get("hosting",    False),
                    "is_proxy":   geo_data.get("proxy",      False),
                    "is_mobile":  geo_data.get("mobile",     False),
                    "usage_type": abuse_data.get("usage_type", "Unknown"),
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
                "vt_extra": {
                    "as_owner": vt_data.get("as_owner", "Unknown"),
                    "tags":     vt_data.get("tags", []),
                },
                "error":      vt_data.get("error") or abuse_data.get("error"),
                "scanned_at": datetime.now().isoformat(),
            }
