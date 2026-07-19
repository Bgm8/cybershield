# CyberShield Deployment and Configuration Setup Guide

This guide details the step-by-step process to deploy and configure the CyberShield platform (FastAPI backend + HTML/JS frontend) from scratch.

---

## 1. Prerequisites and Backend Environments

### Environment Variables (.env / Railway Config)
Configure these variables in your deployment dashboard or local `.env` file:

| Variable | Description | Source / How to get it |
|---|---|---|
| `PORT` | Local binding port (default: 8000) | Automatically provided by Railway. |
| `ADMIN_PASSWORD` | Security password for the admin panel | Set to a strong custom string (e.g. `p@ssw0rdSecureAdmin!`). |
| `ADMIN_JWT_SECRET` | Secret key used to sign Admin access tokens | Set to a random 64-character hex sequence. |
| `VIRUSTOTAL_API_KEY` | Key for VirusTotal domain reputation scanning | Get a free developer key at [VirusTotal Community](https://www.virustotal.com/gui/my-apikey). |
| `ABUSEIPDB_API_KEY` | Key for AbuseIPDB reputation scanning | Get a free developer key at [AbuseIPDB Dashboard](https://www.abuseipdb.com/account/api). |
| `OTX_API_KEY` | Key for AlienVault threat pulses lookup | Get a free API key at [AlienVault OTX API](https://otx.alienvault.com/api). |
| `URLSCAN_API_KEY` | Key for Urlscan website preview checks | Get a free API key at [Urlscan.io Profiles](https://urlscan.io/user/profile/). |
| `GOOGLE_SAFE_BROWSING_KEY` | Key for Safe Browsing URL matching | Get a key in [Google Cloud Console](https://console.cloud.google.com/) under APIs. |
| `PHISHTANK_API_KEY` | Key for PhishTank confirmed fishing index lookup | Register for an app key at [PhishTank Developers](https://www.phishtank.com/api_register.php). |
| `SUPABASE_URL` | Endpoint url for user session auth | Copy from project settings in the [Supabase Dashboard](https://supabase.com). |
| `SUPABASE_SERVICE_KEY` | Secure service role key for API operations | Copy from API section under Supabase settings (keep safe). |
| `ALLOWED_ORIGINS` | CORS Whitelist origins array | e.g. `["https://bgm8.github.io", "http://localhost:3000"]`. |

---

## 2. Supabase Database Initialization
1. Log in to the [Supabase Dashboard](https://supabase.com) and create a new project.
2. Navigate to the **SQL Editor** in the sidebar.
3. Open a new query window and paste the contents of `supabase_setup.sql`.
4. Click **Run** to generate the tables, indexes, Row-Level Security (RLS) policies, and triggers.

---

## 3. Razorpay Subscription Configuration
1. Register an account at [Razorpay Dashboard](https://razorpay.com).
2. Switch to **Test Mode** (or Live Mode if deploying for production).
3. Navigate to **API Keys** under Settings and copy your `YOUR_RAZORPAY_KEY_ID`.
4. Paste this key into the frontend checkout script block inside `index.html` at the `checkoutProPlan()` function.
5. Create a Webhook matching `/payment/verify` in Razorpay if you want automated backend verification.

---

## 4. Admin Panel Access
- The Admin Console is located on the frontend router hash segment: `https://yourdomain.com/#admin`.
- Because the router checks location hash segments locally, the `#admin` route is never sent to the server, protecting the administrative entrance from active scanners.
- **Login Flow**:
  1. Input your configured `ADMIN_PASSWORD`.
  2. The server signs and returns a secure JWT (8-hour expiration ceiling) with rotated session JTI IDs.
  3. The token is saved in `sessionStorage` and automatically appended to verification headers.

---

## 5. Pre-deployment Checklist
- [ ] Confirm `ADMIN_PASSWORD` is updated from defaults.
- [ ] Verify `ALLOWED_ORIGINS` CORS origins match target hosts.
- [ ] Ensure clickjacking protection (`window !== window.top`) block is active.
- [ ] Confirm DOMPurify is loading with valid Subresource Integrity hashes.
- [ ] Ensure uvicorn runs with standard smuggling boundary constraints.

---

## 6. How to Test Each of the 16 Scan Services

Launch the backend local server (`python -m uvicorn main:app --port 8000`) and test using the following guidelines:

1. **URL Safety**: Submit `https://google.com` to `/scan` (type: `url`).
2. **IP Reputation**: Submit `8.8.8.8` to `/scan` (type: `ip`).
3. **Email Breach**: Submit `test@example.com` to `/check/email` (check spam score & breach count).
4. **Password check**: Submit a weak password to `/check/password` (check strength count & breach indices).
5. **WHOIS Lookup**: Submit `github.com` to `/check/whois` (check registration details).
6. **SSL Certificate**: Submit `github.com` to `/check/ssl` (check certificate grade).
7. **DNS Records**: Submit `google.com` to `/check/dns` (verify SPF status).
8. **Safe Screenshot**: Submit `https://github.com` to `/check/screenshot`.
9. **Blacklist Check**: Submit `1.1.1.1` to `/check/blacklist` (spam listing records).
10. **Malware Hash**: Submit a known malware hash (like a test EICAR string) to `/check/hash`.
11. **OTX Threat Intel**: Submit `google.com` to `/check/otx`.
12. **PhishTank Check**: Submit a phishing URL to `/check/phishing`.
13. **UPI Fraud Check**: Submit `scamwinner@ybl` to `/check/upi` (look for warning indicators).
14. **WhatsApp link**: Submit a shortened domain containing `free-reward` to `/check/whatsapp`.
15. **Job Offer check**: Submit `google-careers.com` to `/check/joboffer` (should flag as lookalike).
16. **QR Code Scanner**: Upload an image containing a decoded URL via multi-part form to `/check/qrcode`.
