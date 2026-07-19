# CyberShield Administrative Access Operations Manual

> [!CAUTION]
> This is a private operations manual. Do not commit this file to public version control repositories.

---

## 1. Accessing the Administrative Console
The administrative view is triggered via the URL hash parameter:
`https://yourdomain.com/#admin`

The browser handles this router transition locally on the client machine. The `#admin` hash is never transmitted over HTTP request networks to hosting servers, preventing path discovery tools from identifying administrative endpoints.

---

## 2. Changing Credentials
Admin access tokens are validated using a static environment password compared using constant-time string comparisons.

To change the admin access password:
1. Log in to your hosting provider dashboard (e.g. Railway, Heroku).
2. Go to **Variables / Settings**.
3. Update the `ADMIN_PASSWORD` variable to a new strong password.
4. Regenerate the `ADMIN_JWT_SECRET` variable (this will invalidate all current active admin sessions immediately).
5. Deploy/re-run the backend application container to apply configurations.

---

## 3. Incident Response Playbook

In the event of an active scan flood, brute-force attack, or system abuse:

### Step 1: Activate Maintenance Mode
To isolate backend systems while retaining admin accessibility:
1. Log in to the Admin Panel (`#admin`).
2. Go to the **Maintenance Mode** toggle switch.
3. Toggle maintenance to **ON**.
4. The backend will return a `503 Service Unavailable` error for all public threat scan paths, while admin endpoints continue to function for diagnostic check audits.

### Step 2: Manually Block Adversarial IP Hashes
If a threat IP bypasses rate limiting checks or triggers honeypots:
1. Go to the **Security Alerts** panel.
2. Locate the attacking IP hash from logs.
3. Input the IP into the **Manually Block IP** text field.
4. Click **Block IP**. The client's IP is added to the blocked IP list, blocking all queries immediately.

### Step 3: Evict Active Admin Sessions
If an admin token is compromised:
1. Change the `ADMIN_JWT_SECRET` environment variable in Railway.
2. Restart the server process. All active tokens are immediately invalidated.
