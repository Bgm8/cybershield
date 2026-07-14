# CyberShield AI Setup and Deployment Guide

This guide walks you through the step-by-step process of setting up and deploying the updated CyberShield AI threat intelligence platform.

---

## Step 1: Set Up Supabase Project

1. Go to [Supabase](https://supabase.com) and sign in.
2. Click **New Project** and select your organization.
3. Configure your project name (`CyberShield`), a strong database password, and choose your region. Click **Create new project**.
4. Wait a couple of minutes for your project database to provision.
5. In the left navigation bar, click the **SQL Editor** (icon looking like `SQL`).
6. Click **New query**, paste the entire contents of your [supabase_setup.sql](file:///C:/Users/sidda/cybershield/supabase_setup.sql) file into the text area, and click **Run**.
7. In the left menu, go to **Project Settings** -> **API**. Note down the following credentials:
   - **Project URL** (e.g., `https://xxxxxx.supabase.co`)
   - **Project API Keys** -> `service_role` (Secret, bypasses RLS - for Railway backend)
   - **Project API Keys** -> `anon` (Public - for index.html client initialization)

---

## Step 2: Get Security Threat Intel API Keys

Register for free developer accounts at the following links to obtain your scanning API keys:
1. **VirusTotal Key**: Sign up at [VirusTotal](https://www.virustotal.com/gui/my-apikey).
2. **AbuseIPDB Key**: Sign up at [AbuseIPDB API](https://www.abuseipdb.com/account/api).
3. **URLScan Key**: Sign up at [URLScan Profile API](https://urlscan.io/user/profile/).
4. **AlienVault OTX Key**: Sign up at [OTX Alienvault API](https://otx.alienvault.com/api).
5. **PhishTank Key**: Register an application at [PhishTank API Registry](https://www.phishtank.com/api_register.php).
6. **Shodan Key**: Sign up at [Shodan Account](https://account.shodan.io).

---

## Step 3: Configure Railway Environment Variables

1. Go to your [Railway Dashboard](https://railway.app).
2. Select your `cybershield` service.
3. Navigate to the **Variables** tab.
4. Click **New Variable** and configure the following:

| Variable Name | Description / Source |
|---|---|
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API Key |
| `ABUSEIPDB_API_KEY` | Your AbuseIPDB API Key |
| `IPINFO_API_KEY` | Your IPInfo token (optional) |
| `OTX_API_KEY` | Your AlienVault OTX API Key |
| `URLSCAN_API_KEY` | Your URLScan.io API Key |
| `GOOGLE_SAFE_BROWSING_KEY` | Your Google Cloud Safe Browsing API Key |
| `PHISHTANK_API_KEY` | Your PhishTank App Key (optional) |
| `SUPABASE_URL` | Your Supabase Project URL from Step 1 |
| `SUPABASE_SERVICE_KEY` | Your Supabase `service_role` key from Step 1 |
| `ADMIN_PASSWORD` | Choose a strong password for Admin panel access (e.g. `SecretPassword123`) |
| `ADMIN_JWT_SECRET` | Any random 32-character string for signing JWT tokens |
| `FRONTEND_URL` | Your GitHub Pages URL (e.g., `https://yourusername.github.io`) |

---

## Step 4: Deploy the Backend to Railway

1. Open your terminal in the workspace root.
2. Initialize or link your Railway project:
   ```bash
   railway link
   ```
3. Deploy the project using the Railway CLI:
   ```bash
   railway up
   ```
4. Verify that the build succeeds. Once online, copy the production endpoint URL (e.g., `https://cybershield-production-xxxx.up.railway.app`).

---

## Step 5: Configure the Frontend

1. Open [index.html](file:///C:/Users/sidda/cybershield/index.html).
2. Go to the start of the `<script>` block (around line 987).
3. Update the constants with your Supabase anonymous credentials and Railway URL:
   ```javascript
   const SUPABASE_URL = 'YOUR_SUPABASE_URL';
   const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';
   const BACKEND_URL = 'YOUR_RAILWAY_BACKEND_URL';
   ```
4. Commit and push the frontend files to your GitHub repository to trigger the GitHub Pages deployment:
   ```bash
   git add .
   git commit -m "Upgrade CyberShield features, BYOK, and Admin Dashboard"
   git push origin main
   ```

---

## Step 6: Verify and Test Features

### 1. Main Scanner Tab
- Input a valid domain (e.g., `google.com`) or IP (e.g., `8.8.8.8`) and click **Analyze**.
- Verify that results load showing the **Threat Verdict** circle and **AI Analyst Copilot** report card at the top, the **Security Vendor Audit** list second (try typing into the search bar or clicking the status filters), and the details stacks third.

### 2. Authentication Modal
- Click **Sign Up Free** in the header. Fill in email/password details and verify that a verification email is sent, and the user profile is successfully registered under the `profiles` table in Supabase.
- Log in and verify that your dashboard tab becomes accessible, showing your historic scans and status badge.

### 3. Bring Your Own Key (BYOK) Tab
- Go to the **⚙️ My API Keys** tab.
- Enter a VirusTotal API key and click **Save**.
- Verify that status changes to **SAVED**. Run a scan and verify the "⚡ Using your personal API key" banner appears at the scanner tab.

### 4. Admin Panel Access
- Navigate to your frontend site with the `#admin` hash appended (e.g., `https://yourusername.github.io/cybershield/#admin`).
- You should be prompted with a secure password modal.
- Input the `ADMIN_PASSWORD` you set in Railway.
- Verify you are redirected to the administrative panel containing scans telemetry stats, user management toggles (suspension triggers), error log diagnostic reports, and the maintenance mode toggle.
