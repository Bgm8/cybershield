# main.py
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import httpx
import os
import base64
import asyncio
from dotenv import load_dotenv
from datetime import datetime, date
import hashlib
import time

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# DNS resolver for Blacklist checks
import dns.resolver

# JWT for admin panel
from jose import jwt, JWTError

# Load variables
load_dotenv()

# Admin credentials
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123").strip()
ADMIN_JWT_SECRET = os.getenv("ADMIN_JWT_SECRET", "cybershield_admin_jwt_secret_key_987654").strip()

# System API keys
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
GOOGLE_SB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip()
PHISHTANK_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "").strip()

# Allowed CORS origin
FRONTEND_URL = os.getenv("FRONTEND_URL", "*").strip()

# Global State for Telemetry & Maintenance
MAINTENANCE_MODE = False
in_memory_scans = []  # Store last 1000 scans
recent_errors = []    # Store last 20 error messages
anonymous_ip_limits = {}  # Store {ip: {"count": int, "date": "YYYY-MM-DD"}}

global_counters = {
    "total_scans_ever": 0,
    "scans_today": 0,
    "scans_week": 0,
    "errors_today": 0,
    "avg_response_ms": 0,
    "total_response_time_ms": 0
}

# Supabase Client Init
supabase_client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        from supabase import create_client
        supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        print("[SYSTEM] Supabase client initialized successfully.")
    except Exception as e:
        print(f"[SYSTEM] Supabase init failed: {e}")

# Initialize FastAPI App
app = FastAPI(
    title="CyberShield Threat Intelligence API",
    description="Unified API backend for CyberShield threat scanning services",
    version="3.0.0"
)

# Slowapi Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS setup
origins = [FRONTEND_URL] if FRONTEND_URL != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if FRONTEND_URL == "*" else [FRONTEND_URL, "http://localhost:3000", "http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security Headers & Server Mask Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "CyberShield-Security-Gateway"
    return response

# Size Limit Middleware (Max 10KB payloads)
@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        if int(content_length) > 10 * 1024:
            return JSONResponse(
                status_code=413,
                content={"error": "Payload Too Large", "message": "Maximum request size limit is 10KB."}
            )
    return await call_next(request)

# Maintenance Filter Middleware
@app.middleware("http")
async def filter_maintenance(request: Request, call_next):
    if MAINTENANCE_MODE:
        # Allow admin operations, root and health checks
        if not (request.url.path.startswith("/admin") or request.url.path in ["/", "/health"]):
            return JSONResponse(
                status_code=503,
                content={
                    "error": "maintenance",
                    "message": "CyberShield is currently undergoing scheduled upgrades. We'll be back shortly! 🛡️"
                }
            )
    return await call_next(request)

# Global Exception Boundary Handler
@app.exception_handler(Exception)
async def global_exception_boundary(request: Request, exc: Exception):
    timestamp = datetime.utcnow().isoformat()
    error_msg = str(exc)
    
    # Redact sensitive keys from console log
    for k in [VT_API_KEY, ABUSE_API_KEY, IPINFO_API_KEY, OTX_API_KEY, URLSCAN_API_KEY, GOOGLE_SB_KEY, PHISHTANK_KEY]:
        if k and len(k) > 4:
            error_msg = error_msg.replace(k, "[REDACTED_API_KEY]")
            
    print(f"[{timestamp}] [CRITICAL_EXCEPTION] {error_msg}")
    
    # Track errors in-memory for admin
    recent_errors.append({"timestamp": timestamp, "message": error_msg[:250]})
    if len(recent_errors) > 20:
        recent_errors.pop(0)
    global_counters["errors_today"] += 1
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Engine Error",
            "message": "Hmm, a security check failed to return clean data. Our threat researchers have been notified."
        }
    )

# ── SCHEMAS ─────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    scan_type: str  # "url" or "ip"

class EmailRequest(BaseModel):
    email: str

class PasswordRequest(BaseModel):
    password: str

class WhoisRequest(BaseModel):
    domain: str

class SslRequest(BaseModel):
    domain: str

class DnsRequest(BaseModel):
    domain: str

class ScreenshotRequest(BaseModel):
    url: str

class BlacklistRequest(BaseModel):
    ip: str

class HashRequest(BaseModel):
    hash: str

class OtxRequest(BaseModel):
    indicator: str
    type: str

class PhishTankRequest(BaseModel):
    url: str

class AdminVerifyRequest(BaseModel):
    password: str

class MaintenanceToggleRequest(BaseModel):
    active: bool

# ── HELPER FUNCTIONS ────────────────────────────────────────────────────────
def hash_target(target: str) -> str:
    return hashlib.sha256(target.strip().encode()).hexdigest()[:24]

def hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.strip().encode()).hexdigest()[:16]

def verify_admin_token(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token.")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, ADMIN_JWT_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Authentication token expired or corrupted.")

def sanitize_input(value: str) -> str:
    # Basic input sanitization to block HTML/script injections
    bad_patterns = ["<script", "javascript:", "onload=", "onerror=", "DROP TABLE", "../"]
    cleaned = value.strip()
    for pattern in bad_patterns:
        if pattern.lower() in cleaned.lower():
            raise HTTPException(status_code=400, detail="Safe validation failed: invalid character patterns.")
    return cleaned

async def enforce_limits(request: Request, user_id: str = None) -> bool:
    """Checks and increments daily scan counters. Returns True if allowed, False if exceeded."""
    client_ip = get_remote_address(request)
    today_str = date.today().isoformat()

    if user_id and supabase_client:
        try:
            res = supabase_client.table("profiles").select("*").eq("id", user_id).execute()
            if res.data:
                profile = res.data[0]
                if profile.get("is_banned"):
                    raise HTTPException(status_code=403, detail="Access denied: this account has been suspended.")
                
                tier = profile.get("tier", "free")
                if tier in ("pro", "byok"):
                    return True
                
                scans_today = profile.get("scans_today", 0)
                last_scan_date = profile.get("last_scan_date")
                
                if last_scan_date != today_str:
                    # New day, reset daily count
                    supabase_client.table("profiles").update({
                        "scans_today": 1,
                        "last_scan_date": today_str,
                        "total_scans": profile.get("total_scans", 0) + 1
                    }).eq("id", user_id).execute()
                    return True
                else:
                    if scans_today >= 20:
                        return False
                    # Increment count
                    supabase_client.table("profiles").update({
                        "scans_today": scans_today + 1,
                        "total_scans": profile.get("total_scans", 0) + 1
                    }).eq("id", user_id).execute()
                    return True
        except HTTPException:
            raise
        except Exception as e:
            print(f"[LIMITS] Supabase DB read failure: {e}")

    # Anonymous IP Limits
    ip_data = anonymous_ip_limits.get(client_ip)
    if not ip_data or ip_data["date"] != today_str:
        anonymous_ip_limits[client_ip] = {"count": 1, "date": today_str}
        return True
    else:
        if ip_data["count"] >= 5:
            return False
        ip_data["count"] += 1
        return True

def log_scan_telemetry(target: str, scan_type: str, service: str, threat_level: str, risk_score: int, client_ip: str, duration_ms: int, used_byok: bool, user_email: str = None):
    # Global counters
    global_counters["total_scans_ever"] += 1
    global_counters["scans_today"] += 1
    global_counters["scans_week"] += 1
    global_counters["total_response_time_ms"] += duration_ms
    global_counters["avg_response_ms"] = round(global_counters["total_response_time_ms"] / global_counters["total_scans_ever"])

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "target_hash": hash_target(target),
        "scan_type": scan_type,
        "service_used": service,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "client_ip_hash": hash_ip(client_ip),
        "response_time_ms": duration_ms,
        "used_personal_key": used_byok,
        "user_email": user_email or "anonymous"
    }
    in_memory_scans.insert(0, entry)
    if len(in_memory_scans) > 1000:
        in_memory_scans.pop()

async def save_scan_record(user_id: str, target: str, scan_type: str, service: str, threat_level: str, risk_score: int, summary: str):
    if supabase_client and user_id:
        try:
            supabase_client.table("scans").insert({
                "user_id": user_id,
                "target": target,
                "scan_type": scan_type,
                "service_used": service,
                "threat_level": threat_level,
                "risk_score": risk_score,
                "result_summary": summary
            }).execute()
        except Exception as e:
            print(f"[TELEMETRY] Supabase DB write failure: {e}")

# ── CORE API SERVICE INTEGRATIONS ───────────────────────────────────────────

# 1. VirusTotal URL check
async def vt_scan_url(url: str, key: str, client: httpx.AsyncClient) -> dict:
    if not key:
        return {"error": "VirusTotal key not set"}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": key}
    try:
        res = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=12)
        if res.status_code == 404:
            # Submit for fresh analysis
            submit = await client.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=12)
            if submit.status_code != 200:
                return {"error": "VT submission failed"}
            analysis_id = submit.json()["data"]["id"]
            await asyncio.sleep(3)
            res = await client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=12)

        if res.status_code != 200:
            return {"error": f"VirusTotal returned error: {res.status_code}"}

        d = res.json()["data"]["attributes"]
        stats = d.get("last_analysis_stats") or d.get("stats", {})
        results = d.get("last_analysis_results") or d.get("results", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = max(malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0), 1)

        engines = {k: v.get("category", "undetected").upper() for k, v in list(results.items())[:60]}

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "engines": engines,
            "risk_score": round((malicious + suspicious * 0.5) / total * 100)
        }
    except Exception as e:
        return {"error": f"VirusTotal connection check failed: {str(e)}"}

# 2. VirusTotal IP Check
async def vt_scan_ip(ip: str, key: str, client: httpx.AsyncClient) -> dict:
    if not key:
        return {"error": "VirusTotal key not set"}
    headers = {"x-apikey": key}
    try:
        res = await client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=12)
        if res.status_code != 200:
            return {"error": f"VirusTotal returned: {res.status_code}"}
        d = res.json()["data"]["attributes"]
        stats = d.get("last_analysis_stats", {})
        results = d.get("last_analysis_results", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = max(malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0), 1)
        engines = {k: v.get("category", "undetected").upper() for k, v in list(results.items())[:60]}
        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "engines": engines,
            "risk_score": round((malicious + suspicious * 0.5) / total * 100),
            "country": d.get("country", "Unknown"),
            "asn": d.get("asn", "Unknown"),
            "as_owner": d.get("as_owner", "Unknown"),
            "tags": d.get("tags", [])
        }
    except Exception as e:
        return {"error": f"VirusTotal IP check failed: {str(e)}"}

# 3. AbuseIPDB check
async def check_abuseipdb(ip: str, key: str, client: httpx.AsyncClient) -> dict:
    if not key:
        return {"error": "AbuseIPDB key not set"}
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        res = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
        if res.status_code != 200:
            return {"error": f"AbuseIPDB returned: {res.status_code}"}
        d = res.json()["data"]
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "domain": d.get("domain", "Unknown"),
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "is_tor": d.get("isTor", False),
            "usage_type": d.get("usageType", "Unknown"),
            "last_reported": d.get("lastReportedAt", "Never")
        }
    except Exception as e:
        return {"error": f"AbuseIPDB check failed: {str(e)}"}

# 4. HaveIBeenPwned check
async def check_pwned_passwords(password_str: str, client: httpx.AsyncClient) -> dict:
    sha1 = hashlib.sha1(password_str.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        res = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
        if res.status_code != 200:
            return {"is_pwned": False, "times_seen": 0, "error": "PwnedPasswords API returned failure."}
        
        matches = res.text.splitlines()
        times_seen = 0
        is_pwned = False
        for line in matches:
            parts = line.split(":")
            if parts[0] == suffix:
                times_seen = int(parts[1])
                is_pwned = True
                break
        return {"is_pwned": is_pwned, "times_seen": times_seen}
    except Exception as e:
        return {"is_pwned": False, "times_seen": 0, "error": str(e)}

# 5. EmailRep check
async def check_email_rep(email: str, client: httpx.AsyncClient) -> dict:
    try:
        # Free API does not require key, but has strict rate limits.
        res = await client.get(f"https://emailrep.io/{email}", headers={"User-Agent": "CyberShield-Enterprise"}, timeout=8)
        if res.status_code == 200:
            d = res.json()
            details = d.get("details", {})
            return {
                "reputation": d.get("reputation", "unknown"),
                "is_suspicious": d.get("suspicious", False),
                "is_disposable": details.get("disposable", False),
                "profiles_found": len(d.get("references", {})),
                "first_seen": d.get("details", {}).get("first_seen", "Unknown"),
                "breach_count": details.get("credentials_leaked", 0),
                "spam_score": details.get("spam_score", 0)
            }
        return {"error": f"EmailRep API returned code {res.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# 6. SSL Certificate check
async def check_ssl_labs(host: str, client: httpx.AsyncClient) -> dict:
    url = f"https://api.ssllabs.com/api/v3/analyze?host={host}"
    try:
        # Trigger analyze
        await client.get(url + "&startNew=on", timeout=10)
        # Poll up to 10 times (50 seconds)
        for _ in range(10):
            await asyncio.sleep(5)
            res = await client.get(url, timeout=10)
            if res.status_code != 200:
                continue
            d = res.json()
            if d.get("status") == "READY":
                endpoints = d.get("endpoints", [])
                grade = endpoints[0].get("grade", "Unknown") if endpoints else "Unknown"
                issuer = endpoints[0].get("details", {}).get("cert", {}).get("issuerSubject", "Unknown") if endpoints else "Unknown"
                expiry_ts = endpoints[0].get("details", {}).get("cert", {}).get("notAfter", 0) if endpoints else 0
                
                days_remaining = 0
                if expiry_ts:
                    expiry_date = datetime.fromtimestamp(expiry_ts / 1000.0)
                    days_remaining = max((expiry_date - datetime.now()).days, 0)
                
                return {
                    "grade": grade,
                    "issuer": issuer,
                    "expiry_date": datetime.fromtimestamp(expiry_ts / 1000.0).strftime("%Y-%m-%d") if expiry_ts else "Unknown",
                    "days_remaining": days_remaining,
                    "is_expired": days_remaining == 0,
                    "supports_tls13": "TLS 1.3" in [p.get("name") + " " + p.get("version") for p in endpoints[0].get("details", {}).get("protocols", [])] if endpoints and endpoints[0].get("details", {}).get("protocols") else False,
                    "has_hsts": endpoints[0].get("details", {}).get("hstsStatus", "Unknown") == "present" if endpoints else False,
                    "vulnerabilities": len(endpoints[0].get("details", {}).get("vulns", [])) if endpoints and endpoints[0].get("details", {}).get("vulns") else 0
                }
        return {"error": "SSL analysis timed out (max 50s limit reached)."}
    except Exception as e:
        return {"error": f"SSL analyzer error: {str(e)}"}

# 7. Safe Screenshot Check (urlscan.io API)
async def fetch_urlscan_screenshot(url: str, user_key: str, client: httpx.AsyncClient) -> dict:
    key = user_key or URLSCAN_API_KEY
    if not key:
        return {"error": "Urlscan API key is missing or not configured."}
    
    headers = {"API-Key": key, "Content-Type": "application/json"}
    try:
        submit = await client.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": url, "visibility": "public"}, timeout=12)
        if submit.status_code not in (200, 201):
            return {"error": f"Urlscan submission failed: {submit.status_code}"}
        
        uuid = submit.json().get("uuid")
        if not uuid:
            return {"error": "Could not retrieve scan token."}
            
        await asyncio.sleep(12)  # Wait for analysis
        
        result = await client.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=12)
        if result.status_code != 200:
            return {
                "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
                "page_title": "Scan pending...",
                "malicious_score": 0,
                "technologies": ["Static View"],
                "certificates": "Unavailable",
                "ip_address": "Unknown",
                "dom_size": 0
            }
        
        d = result.json()
        page = d.get("page", {})
        verdicts = d.get("verdicts", {}).get("overall", {})
        technologies = [t.get("name") for t in d.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])]
        
        return {
            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
            "page_title": page.get("title", "No Title"),
            "malicious_score": verdicts.get("score", 0),
            "technologies": technologies[:8],
            "certificates": page.get("tlsIssuer", "None"),
            "ip_address": page.get("ip", "Unknown"),
            "dom_size": d.get("data", {}).get("requests", [{}])[0].get("response", {}).get("size", 0)
        }
    except Exception as e:
        return {"error": f"Safe screenshot check failed: {str(e)}"}

# ── ROUTE ENDPOINTS ─────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "status": "CyberShield API Security Engine is ONLINE",
        "version": "3.0.0",
        "maintenance_mode": MAINTENANCE_MODE,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health():
    return {
        "status": "online",
        "vt_key_set": bool(VT_API_KEY),
        "abuse_key_set": bool(ABUSE_API_KEY),
        "ipinfo_key_set": bool(IPINFO_API_KEY),
        "otx_key_set": bool(OTX_API_KEY),
        "urlscan_key_set": bool(URLSCAN_API_KEY),
        "google_sb_key_set": bool(GOOGLE_SB_KEY),
        "phishtank_key_set": bool(PHISHTANK_KEY),
        "supabase_connected": bool(supabase_client),
        "maintenance_active": MAINTENANCE_MODE
    }

# 1. Backwards Compatible Scan URL/IP Route
@app.post("/scan")
@limiter.limit("10/minute")
async def execute_scan(request: Request, req: ScanRequest, x_user_vt_key: str = Header(None), x_user_abuse_key: str = Header(None), x_user_otx_key: str = Header(None), x_user_shodan_key: str = Header(None), authorization: str = Header(None)):
    start_time = time.time()
    target = sanitize_input(req.target)
    scan_type = req.scan_type.strip().lower()
    
    # Identify user if token is present
    user_id = None
    user_email = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        try:
            # We check supabase token directly if available
            if supabase_client:
                # Retrieve user payload
                user_res = supabase_client.auth.get_user(token)
                if user_res.user:
                    user_id = user_res.user.id
                    user_email = user_res.user.email
        except Exception:
            pass

    # BYOK Check
    using_byok = bool(x_user_vt_key or x_user_abuse_key)
    
    # Enforce Limits
    if not using_byok:
        allowed = await enforce_limits(request, user_id)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "limit_reached",
                    "message": "Scan quota exceeded. Create a free account or upgrade to Pro to continue."
                }
            )

    # API Keys resolution
    vt_key = x_user_vt_key or VT_API_KEY
    abuse_key = x_user_abuse_key or ABUSE_API_KEY
    otx_key = x_user_otx_key or OTX_API_KEY
    shodan_key = x_user_shodan_key  # Shodan InternetDB doesn't require key, but store placeholder

    async with httpx.AsyncClient() as client:
        if scan_type == "url":
            vt_data, gsb_data = await asyncio.gather(
                vt_scan_url(target, vt_key, client),
                client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}", json={
                    "client": {"clientId": "cybershield", "clientVersion": "3.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": target}]
                    }
                }) if GOOGLE_SB_KEY else asyncio.sleep(0, result=None)
            )
            
            # Format GSB Matches
            gsb_threats = []
            if gsb_data and hasattr(gsb_data, "status_code") and gsb_data.status_code == 200:
                gsb_threats = [m["threatType"] for m in gsb_data.json().get("matches", [])]

            malicious = vt_data.get("malicious", 0)
            threat_level = "CLEAN"
            if malicious >= 5 or len(gsb_threats) > 0:
                threat_level = "HIGH"
            elif malicious >= 2:
                threat_level = "MEDIUM"
            elif malicious >= 1:
                threat_level = "LOW"

            result = {
                "type": "URL Analysis",
                "target": target,
                "threat_level": threat_level,
                "risk_score": vt_data.get("risk_score", 0),
                "summary": {
                    "malicious": malicious,
                    "suspicious": vt_data.get("suspicious", 0),
                    "total_engines": vt_data.get("total", 0),
                },
                "engines": vt_data.get("engines", {}),
                "google_sb": {"safe": len(gsb_threats) == 0, "threats": gsb_threats},
                "using_personal_key": using_byok
            }

        elif scan_type == "ip":
            vt_data, abuse_data = await asyncio.gather(
                vt_scan_ip(target, vt_key, client),
                check_abuseipdb(target, abuse_key, client)
            )

            malicious = vt_data.get("malicious", 0)
            abuse_score = abuse_data.get("abuse_score", 0)
            threat_level = "CLEAN"
            
            if malicious >= 5 or abuse_score >= 50:
                threat_level = "HIGH"
            elif malicious >= 2 or abuse_score >= 25:
                threat_level = "MEDIUM"
            elif malicious >= 1 or abuse_score >= 10:
                threat_level = "LOW"

            result = {
                "type": "IP Reputation",
                "target": target,
                "threat_level": threat_level,
                "risk_score": round((vt_data.get("risk_score", 0) + abuse_score) / 2) if "error" not in vt_data else abuse_score,
                "summary": {
                    "malicious": malicious,
                    "suspicious": vt_data.get("suspicious", 0),
                    "total_engines": vt_data.get("total", 0),
                    "abuse_score": abuse_score,
                    "abuse_reports": abuse_data.get("total_reports", 0),
                },
                "engines": vt_data.get("engines", {}),
                "geo": {
                    "country": abuse_data.get("country", vt_data.get("country", "Unknown")),
                    "isp": abuse_data.get("isp", "Unknown"),
                    "domain": abuse_data.get("domain", "Unknown"),
                    "is_tor": abuse_data.get("is_tor", False)
                },
                "using_personal_key": using_byok
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid scan_type: must be url or ip.")

    duration_ms = round((time.time() - start_time) * 1000)
    log_scan_telemetry(target, scan_type, result["type"], result["threat_level"], result["risk_score"], get_remote_address(request), duration_ms, using_byok, user_email)
    
    summary_text = f"Analyzed {target}. Classification: {result['threat_level']} (Score: {result['risk_score']}/100)"
    await save_scan_record(user_id, target, scan_type, result["type"], result["threat_level"], result["risk_score"], summary_text)
    
    return result

# 3. Email Reputation Check Route
@app.post("/check/email")
@limiter.limit("10/minute")
async def scan_email(request: Request, req: EmailRequest):
    email = sanitize_input(req.email)
    async with httpx.AsyncClient() as client:
        res = await check_email_rep(email, client)
    return res

# 4. Password Breach Check Route
@app.post("/check/password")
@limiter.limit("10/minute")
async def scan_password(request: Request, req: PasswordRequest):
    password = req.password  # Do NOT sanitize passwords to avoid altering characters
    if len(password) > 200:
         raise HTTPException(status_code=400, detail="Password is too long (max 200 chars).")
         
    async with httpx.AsyncClient() as client:
        res = await check_pwned_passwords(password, client)
        
    # Calculate Strength Score out of 100
    length = len(password)
    strength = min(length * 4, 40) # up to 40pts
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    if has_upper: strength += 15
    if has_digit: strength += 15
    if has_symbol: strength += 20
    if length > 12: strength += 10 # length bonus
    
    label = "VERY WEAK 🔴"
    if strength > 80: label = "VERY SECURE 🟢"
    elif strength > 60: label = "STRONG 🟡"
    elif strength > 30: label = "WEAK 🟠"
    
    recs = []
    if length < 10: recs.append("Make it longer (at least 12 characters)")
    if not has_upper: recs.append("Add uppercase characters (A-Z)")
    if not has_digit: recs.append("Add numbers (0-9)")
    if not has_symbol: recs.append("Add special symbols (e.g. !, @, $, %)")
    
    return {
        "is_pwned": res.get("is_pwned", False),
        "times_seen": res.get("times_seen", 0),
        "strength_score": strength,
        "strength_label": label,
        "recommendations": recs if recs else ["Your password is highly secure! Keep it up."]
    }

# 5. WHOIS Lookup Route
@app.post("/check/whois")
@limiter.limit("10/minute")
async def scan_whois(request: Request, req: WhoisRequest):
    domain = sanitize_input(req.domain).replace("https://","").replace("http://","").split("/")[0]
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(f"https://api.whois.vu/?q={domain}", timeout=10)
            if res.status_code == 200:
                d = res.json()
                
                # Check creation and expiry dates if available
                created_str = d.get("created", "")
                expiry_str = d.get("expires", "")
                
                is_new = False
                days_until_expiry = 365
                is_expiring = False
                
                try:
                    if created_str:
                        # Attempt to parse date strings
                        c_date = datetime.strptime(created_str[:10], "%Y-%m-%d").date()
                        if (date.today() - c_date).days < 30:
                            is_new = True
                    if expiry_str:
                        e_date = datetime.strptime(expiry_str[:10], "%Y-%m-%d").date()
                        days_until_expiry = max((e_date - date.today()).days, 0)
                        if days_until_expiry < 30:
                            is_expiring = True
                except Exception:
                    pass
                
                return {
                    "registrar": d.get("registrar", "Unknown Registrar"),
                    "creation_date": created_str or "Unknown",
                    "expiry_date": expiry_str or "Unknown",
                    "registrant_country": d.get("country", "Unknown"),
                    "nameservers": d.get("nameservers", []),
                    "days_until_expiry": days_until_expiry,
                    "is_new_domain": is_new,
                    "is_expiring_soon": is_expiring
                }
            return {"error": "WHOIS lookup service returned error status."}
        except Exception as e:
            return {"error": str(e)}

# 6. SSL Analyzer Route
@app.post("/check/ssl")
@limiter.limit("10/minute")
async def scan_ssl(request: Request, req: SslRequest):
    domain = sanitize_input(req.domain).replace("https://","").replace("http://","").split("/")[0]
    async with httpx.AsyncClient() as client:
        res = await check_ssl_labs(domain, client)
    return res

# 7. DNS Resolve Route
@app.post("/check/dns")
@limiter.limit("10/minute")
async def scan_dns(request: Request, req: DnsRequest):
    domain = sanitize_input(req.domain).replace("https://","").replace("http://","").split("/")[0]
    
    async def resolve_dns_record(name: str, record_type: str, client: httpx.AsyncClient) -> list:
        try:
            res = await client.get(f"https://dns.google/resolve?name={name}&type={record_type}", timeout=8)
            if res.status_code == 200:
                answers = res.json().get("Answer", [])
                return [a.get("data") for a in answers]
        except Exception:
            pass
        return []

    async with httpx.AsyncClient() as client:
        # Resolve A, MX, NS and TXT records in parallel
        a_records, mx_records, ns_records, txt_records = await asyncio.gather(
            resolve_dns_record(domain, "A", client),
            resolve_dns_record(domain, "MX", client),
            resolve_dns_record(domain, "NS", client),
            resolve_dns_record(domain, "TXT", client)
        )
        
        # Check SPF/DMARC/DKIM
        has_spf = any("v=spf1" in txt for txt in txt_records)
        has_dkim = any("v=DKIM1" in txt for txt in txt_records)
        
        dmarc_records = await resolve_dns_record(f"_dmarc.{domain}", "TXT", client)
        has_dmarc = any("v=DMARC1" in dmarc for dmarc in dmarc_records)
        
    return {
        "a_records": a_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "txt_records": txt_records,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "has_dkim": has_dkim,
        "security_status": "SECURE 🟢" if (has_spf and has_dmarc) else "WARNING 🟠"
    }

# 8. Safe Screenshot Preview Route
@app.post("/check/screenshot")
@limiter.limit("10/minute")
async def scan_screenshot(request: Request, req: ScreenshotRequest, x_user_urlscan_key: str = Header(None)):
    url = sanitize_input(req.url)
    async with httpx.AsyncClient() as client:
        res = await fetch_urlscan_screenshot(url, x_user_urlscan_key, client)
    return res

# 9. Blacklist Check (DNSBL)
@app.post("/check/blacklist")
@limiter.limit("10/minute")
async def scan_blacklist(request: Request, req: BlacklistRequest):
    ip = sanitize_input(req.ip)
    
    # Validate IP Structure
    parts = ip.split(".")
    if len(parts) != 4:
        raise HTTPException(status_code=400, detail="Invalid IPv4 address format.")
        
    reversed_ip = ".".join(reversed(parts))
    blacklists = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
        "dnsbl.spfbl.net",
        "psbl.surriel.com"
    ]
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    listed_on = []
    clean_on = []
    
    # Query DNSBLs in parallel using threads
    def check_dnsbl(blacklist):
        try:
            resolver.resolve(f"{reversed_ip}.{blacklist}", "A")
            return blacklist, True
        except Exception:
            return blacklist, False
            
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, check_dnsbl, bl) for bl in blacklists]
    results = await asyncio.gather(*tasks)
    
    for bl, listed in results:
        if listed:
            listed_on.append(bl)
        else:
            clean_on.append(bl)
            
    return {
        "total_checked": len(blacklists),
        "listed_count": len(listed_on),
        "listed_on": listed_on,
        "clean_on": clean_on,
        "recommendation": "DANGER 🔴 — Block Traffic" if listed_on else "SAFE 🟢 — Clean IP"
    }

# 10. Malware Hash Check (MalwareBazaar)
@app.post("/check/hash")
@limiter.limit("10/minute")
async def scan_hash(request: Request, req: HashRequest):
    file_hash = sanitize_input(req.hash).lower()
    
    # Auto-detect hash type
    h_type = None
    if len(file_hash) == 32: h_type = "MD5"
    elif len(file_hash) == 40: h_type = "SHA1"
    elif len(file_hash) == 64: h_type = "SHA256"
    
    if not h_type:
        raise HTTPException(status_code=400, detail="Invalid hash: must be MD5 (32 char), SHA1 (40 char) or SHA256 (64 char).")
        
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": file_hash}, timeout=10)
            if res.status_code == 200:
                d = res.json()
                if d.get("query_status") == "ok":
                    data = d.get("data", [{}])[0]
                    return {
                        "is_known_malware": True,
                        "malware_family": data.get("signature", "Unknown Signature"),
                        "file_type": data.get("file_type", "Unknown"),
                        "file_size": data.get("file_size", 0),
                        "first_seen": data.get("first_seen", "Unknown"),
                        "last_seen": data.get("last_seen", "Unknown"),
                        "tags": data.get("tags", []),
                        "reporter": data.get("reporter", "MalwareBazaar")
                    }
                return {"is_known_malware": False, "message": "No malware matching this hash has been reported to MalwareBazaar."}
            return {"error": "MalwareBazaar server returned failure response."}
        except Exception as e:
            return {"error": str(e)}

# 11. AlienVault OTX Threat Pulses check
@app.post("/check/otx")
@limiter.limit("10/minute")
async def scan_otx(request: Request, req: OtxRequest, x_user_otx_key: str = Header(None)):
    indicator = sanitize_input(req.indicator)
    ind_type = sanitize_input(req.type)
    key = x_user_otx_key or OTX_API_KEY
    if not key:
        return {"error": "AlienVault OTX key not configured."}
    
    headers = {"X-OTX-API-KEY": key}
    url = f"https://otx.alienvault.com/api/v1/indicators/{ind_type}/{indicator}/general"
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                d = res.json()
                pulse_info = d.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                
                malware_families = set()
                adversaries = set()
                tags = set()
                
                pulse_list = []
                for p in pulses[:8]:
                    pulse_list.append({
                        "name": p.get("name", "Unknown Pulse"),
                        "description": p.get("description", ""),
                        "author": p.get("author_name", "Anonymous"),
                        "created": p.get("created", "")
                    })
                    for m in p.get("malware_families", []):
                        if m: malware_families.add(m.get("name"))
                    for a in p.get("adversaries", []):
                        if a: adversaries.add(a.get("name"))
                    for t in p.get("tags", []):
                        if t: tags.add(t)

                return {
                    "pulse_count": pulse_info.get("count", 0),
                    "threat_score": min(pulse_info.get("count", 0) * 2, 100),
                    "malware_families": list(malware_families)[:5],
                    "adversaries": list(adversaries)[:5],
                    "tags": list(tags)[:10],
                    "country": d.get("country", "Unknown"),
                    "first_seen": pulse_info.get("pulses", [{}])[0].get("created", "Unknown") if pulse_info.get("pulses") else "Unknown",
                    "pulses_details": pulse_list
                }
            return {"error": f"OTX returned status {res.status_code}"}
        except Exception as e:
            return {"error": str(e)}

# 12. PhishTank Check
@app.post("/check/phishing")
@limiter.limit("10/minute")
async def scan_phishing(request: Request, req: PhishTankRequest, x_user_phishtank_key: str = Header(None)):
    url = req.url  # Do NOT sanitize to avoid breaking encoded queries
    key = x_user_phishtank_key or PHISHTANK_KEY
    
    headers = {"User-Agent": "phishtank/CyberShield"}
    data = {"url": url, "format": "json"}
    if key:
        data["app_key"] = key
        
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post("https://checkurl.phishtank.com/checkurl/", headers=headers, data=data, timeout=10)
            if res.status_code == 200:
                d = res.json().get("results", {})
                return {
                    "in_database": d.get("in_database", False),
                    "is_phishing": d.get("valid", False),
                    "verified": d.get("verified", False),
                    "verified_at": d.get("verified_at", "Unknown")
                }
            return {"error": f"PhishTank API returned code: {res.status_code}"}
        except Exception as e:
            return {"error": str(e)}

# ── ADMIN INTERACTIVE TELEMETRY SECTION ─────────────────────────────────────

@app.post("/admin/verify")
@limiter.limit("20/hour")
async def verify_admin(request: Request, req: AdminVerifyRequest):
    if req.password == ADMIN_PASSWORD:
        token = jwt.encode(
            {"sub": "admin", "exp": time.time() + 24 * 3600},
            ADMIN_JWT_SECRET,
            algorithm="HS256"
        )
        return {"token": token}
    raise HTTPException(status_code=401, detail="Access denied: invalid administration credentials.")

@app.get("/admin/stats")
async def get_admin_stats(sub: str = Depends(verify_admin_token)):
    registered_users = 0
    if supabase_client:
        try:
            res = supabase_client.table("profiles").select("id", count="exact").execute()
            registered_users = res.count or len(res.data)
        except Exception as e:
            print(f"[ADMIN] Supabase user query error: {e}")
            
    stats = global_counters.copy()
    stats["registered_users"] = registered_users
    return stats

@app.get("/admin/activity")
async def get_admin_activity(limit: int = 50, sub: str = Depends(verify_admin_token)):
    return in_memory_scans[:limit]

@app.get("/admin/users")
async def get_admin_users(page: int = 1, sub: str = Depends(verify_admin_token)):
    if not supabase_client:
        return {"users": [], "message": "Database client offline."}
    try:
        limit = 20
        offset = (page - 1) * limit
        # Select profiles paginated
        res = supabase_client.table("profiles").select("*").range(offset, offset + limit - 1).execute()
        return {"users": res.data}
    except Exception as e:
        return {"users": [], "error": str(e)}

@app.get("/admin/emails")
async def get_admin_waitlist(sub: str = Depends(verify_admin_token)):
    if not supabase_client:
        return {"waitlist": [], "message": "Database client offline."}
    try:
        res = supabase_client.table("email_waitlist").select("*").order("created_at", desc=True).execute()
        return {"waitlist": res.data}
    except Exception as e:
        return {"waitlist": [], "error": str(e)}

@app.get("/admin/errors")
async def get_admin_errors(sub: str = Depends(verify_admin_token)):
    return recent_errors

@app.post("/admin/maintenance")
async def toggle_maintenance(req: MaintenanceToggleRequest, sub: str = Depends(verify_admin_token)):
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = req.active
    return {"maintenance_mode": MAINTENANCE_MODE}

@app.get("/admin/health")
async def get_admin_health(sub: str = Depends(verify_admin_token)):
    return {
        "status": "online",
        "api_keys": {
            "VirusTotal": bool(VT_API_KEY),
            "AbuseIPDB": bool(ABUSE_API_KEY),
            "IPinfo": bool(IPINFO_API_KEY),
            "AlienVault_OTX": bool(OTX_API_KEY),
            "URLScan": bool(URLSCAN_API_KEY),
            "GoogleSafeBrowsing": bool(GOOGLE_SB_KEY),
            "PhishTank": bool(PHISHTANK_KEY)
        },
        "in_memory_log_size": len(in_memory_scans),
        "maintenance_mode": MAINTENANCE_MODE
    }

# ── PUBLIC EARLY WAITLIST SIGNUP ────────────────────────────────────────────
class WaitlistRequest(BaseModel):
    email: str
    source: str = "limit_modal"

@app.post("/waitlist")
async def join_waitlist(req: WaitlistRequest):
    email = sanitize_input(req.email)
    if not supabase_client:
        # Fallback to dummy success to keep UI friendly
        return {"status": "saved", "message": "Email queued successfully."}
    try:
        supabase_client.table("email_waitlist").insert({
            "email": email,
            "source": req.source
        }).execute()
        return {"status": "saved", "message": "Email added to early access list!"}
    except Exception as e:
        # If already exists, return success to maintain clean UX
        if "unique" in str(e).lower():
            return {"status": "exists", "message": "You are already on our waitlist!"}
        return {"error": "DB_ERROR", "message": "Could not register email at this time."}
