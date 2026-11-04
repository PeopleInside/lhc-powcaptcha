# lhc-powcaptcha (v1.4.3)

A Live Helper Chat extension that adds a **local Proof-of-Work (PoW) captcha** option for:

- Admin login (`user/login`)
- Password reminder (`user/forgotpassword`)

## What this extension changes

This extension adds a new captcha provider in `site_admin/system/recaptcha`:

- `Local PoW captcha`

When selected and enabled, LHC will:

- Generate short-lived signed PoW challenges server-side
- Bind PoW challenges to current user session/context
- Solve challenge client-side in browser (Web Crypto)
- Verify PoW server-side before login/password-reminder processing
- Reject replayed proofs (session-level and APCu replay protection)
- Rate-limit challenge generation requests server-side

---

## What's New in Version 1.4.3

### 1. 24-Hour Adaptive Escalation on Failed Login Credentials (`bad_credentials`)
In previous versions, only captcha solving failures triggered difficulty escalation. In **1.4.3**, when a user enters **wrong login credentials** (incorrect username or password):
- The extension intercepts the failed authentication lifecycle via native LHC event hooks (`user.login_before_authenticate` and `user.login_after_success_authenticate`).
- The client IP is flagged and its captcha difficulty is escalated for **at least 24 hours** (configurable from 1 to 168 hours).
- Each subsequent failed attempt adds **+1 bit** (doubling the computational work required) up to the safe browser ceiling of 22 bits.
- Stored persistently in `lh_chat_config` (`powcaptcha_ip_penalties`) and cached in APCu, surviving cookie clearing and server restarts.

### 2. Limited IPs Management List in Back Office (`site_admin/system/recaptcha`)
A dedicated table now lists all IP addresses currently facing elevated difficulty:
- **IP address** and **attempted username**
- **Failed login count (24h)**
- **Penalty bits (+N bits)** and **effective difficulty** (e.g., 20 bits)
- **First failure** and **last failure timestamps**
- **Time remaining until expiration** (e.g. `23h 48m`)
- **Unblock Button ("✕ Sblocca")**: Allows administrators to immediately clear the penalty for a specific IP (with CSRF token protection).
- **Clear All Button**: Instant reset of all restricted IPs back to base difficulty.

### 3. Security Email Alert on Login from New IP Addresses
An optional security notification system:
- **Enabled/Disabled toggle** in `site_admin/system/recaptcha`.
- When an operator successfully logs into Live Helper Chat from an IP address not previously seen for that account, a security email alert is automatically dispatched.
- **Recipient option**: Can be sent directly to the operator's account email address, or overridden with a dedicated security/admin email address.
- Email contains operator username, new IP address, exact date/time, and user agent.
- Known IPs per user are stored in `lh_chat_config` (`powcaptcha_known_ips`), retaining the last 25 verified IPs per operator.

### 4. Extended Attempt & Security Log
- Logs all failed credential attempts (`bad_credentials`) with the required difficulty and username.
- Logs new IP alert dispatch events (`new_ip_login_alert_sent`).
- Includes one-click log clearance.

---

## Attempt log, adaptive difficulty and honeypot

In `site_admin/system/recaptcha` (provider `Local PoW captcha`):

- **Attempt log**: the last 50 captcha attempts (date, IP, action, OK/Failed, reason, difficulty, user agent / target user), newest first, with a **Clear log** button (POST + CSRF token). Stored in a hidden row of `lh_chat_config` (`powcaptcha_attempt_log`, JSON).
- **Short-term adaptive difficulty**: every failed attempt in the last 15 minutes adds +1 bit.
- **24-hour credential penalty**: failed login credentials add +1 bit for 24 hours.
- **Difficulty Ceiling**: Difficulty is capped at **22 bits** (base and base + extra). Above that the in-browser solver cannot finish within the TTL (26 bits = ~67M hashes). A stored value above 22 is automatically reset to 18.
- **Honeypot** (on by default): an invisible `contact_website` field in the form. If it contains anything the attempt fails immediately, is logged as `honeypot_triggered`, and counts as a penalty.

---

## Installation
1. Copy extension folder into LHC:

```bash
cd /path/to/lhc_web/extension
git clone https://github.com/PeopleInside/lhc-powcaptcha.git lhcpowcaptcha
```
If you use FTP be sure to rename the folder from `lhc-powcaptcha` to `lhcpowcaptcha`

2. Enable extension in `lhc_web/settings/settings.ini.php`:

```php
'extensions' =>
array(
    'lhcpowcaptcha'
),
```

3. Clear cache from back office (or remove cache files manually if needed).

4. Open:
- `site_admin/system/recaptcha`

5. Configure:
- **Enable** = checked
- **Captcha provider** = `Local PoW captcha`
- Set `Difficulty` (default `18`) and `Challenge TTL` (default `180`)
- Verify **Increase captcha difficulty after failed login (wrong credentials)** is checked
- Verify **Send email alert when an operator logs in from a new IP address** is configured as desired

6. Save.

---

## Extension structure used by LHC

Live Helper Chat loads extension template overrides from:

- `extension/lhcpowcaptcha/design/lhcpowcaptchatheme/tpl/...`

## Core page integration

This extension is designed to integrate directly into the core page:

- `site_admin/system/recaptcha`

You do **not** need a separate extension settings page.
Manage PoW only from: `site_admin/system/recaptcha`.

---

## Recommended secure defaults

- Difficulty: `18` (maximum allowed: `22`)
- TTL: `180`
- Failed login penalty: `Enabled`, `24 hours`
- New IP login alert: `Enabled`

---

## APCu requirement (recommended for production)

PoW works without APCu, but with reduced protections:

- per-IP challenge rate limiting is not available (session limit still applies)
- cross-session replay detection is not available (session replay detection still applies)
- 24-hour IP penalties and known IPs use database storage (`lh_chat_config`) in both modes.

The admin captcha page shows a warning when APCu is missing in PoW mode.

## License
Apache License 2.0
