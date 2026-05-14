# lhc-powcaptcha

A Live Helper Chat extension that adds a **local Proof-of-Work (PoW) captcha** option for:

- Admin login (`user/login`)
- Password reminder (`user/forgotpassword`)

## What this extension changes

This extension adds a new captcha provider in `site_admin/system/recaptcha`:

- `Local PoW captcha`

When selected and enabled, LHC will:

- Generate short-lived signed PoW challenges server-side
- Solve challenge client-side in browser (Web Crypto)
- Verify PoW server-side before login/password-reminder processing
- Reject replayed proofs (session-level replay protection)

## Disclaimer

This software is provided **"AS IS"**, without any warranty. While it has been tested and reasonable efforts are made to ensure security and reliability, no guarantees are provided. As an open project, anyone may contribute or report issues, but this does not imply endorsement or liability from the maintainers.

**You use this software entirely at your own risk.** The authors and contributors are not liable for any damages, data loss, or unexpected behavior resulting from its use, modification, or distribution. Always review and test the code independently before deploying it in critical or production environments.

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

5. Set:

- **Enable** = checked
- **Captcha provider** = `Local PoW captcha`
- Choose `Difficulty` and `Challenge TTL`

6. Save.

## Extension structure used by LHC

Live Helper Chat loads extension template overrides from:

- `extension/lhcpowcaptcha/design/lhcpowcaptchatheme/tpl/...`

If templates are placed under `design/defaulttheme/...`, LHC will not load the PoW overrides from the extension.

## Core page integration (important)

This extension is designed to integrate directly into the core page:

- `site_admin/system/recaptcha`

You do **not** need a separate extension settings page.
Manage PoW only from: `site_admin/system/recaptcha`.

## Troubleshooting when `Local PoW captcha` is not visible

1. Confirm extension path in your real LHC installation:
   - `lhc_web/extension/lhcpowcaptcha`
2. Confirm extension is enabled in `lhc_web/settings/settings.ini.php`:
   - `extensions => array('lhcpowcaptcha')`
3. Clear Live Helper Chat cache from back office.
4. Reset PHP OPcache (or restart PHP-FPM/Apache service).
5. Check for conflicts:
    - another extension overriding `modules/lhsystem/recaptcha.php`
    - another extension/theme overriding `extension/lhcpowcaptcha/design/lhcpowcaptchatheme/tpl/lhsystem/recaptcha.tpl.php`
6. Reopen `site_admin/system/recaptcha` and verify provider list contains:
   - `Local PoW captcha`
7. If provider is still missing, extension override is not active.
   Re-check extension path/enablement and clear cache/OPcache again.

If a hard override conflict cannot be resolved, resolve the override conflict before enabling PoW.

## Recommended secure defaults

- Difficulty: `18`
- TTL: `180`

For stronger protection (with more client CPU cost):

- Difficulty: `20-22`

## Rollback / emergency disable (if something breaks)

### Fastest safe recovery

1. Edit `lhc_web/settings/settings.ini.php`
2. Remove or comment out extension `lhcpowcaptcha` from `extensions`
3. Clear LHC cache
4. Login page and forgot password revert to LHC core behavior

### Keep extension enabled but disable PoW

1. Go to `site_admin/system/recaptcha`
2. Uncheck **Enable**
3. Save

Or switch provider back to `google` / `turnstile`.

## Resume extension after recovery

1. Re-add `lhcpowcaptcha` into `extensions` list
2. Clear cache
3. Reconfigure in `site_admin/system/recaptcha`
4. Test login and forgot-password flows

## Notes

- This extension uses existing LHC recaptcha config storage with additional PoW keys.
- PoW challenge signing uses LHC `site.secrethash` internally.
- No third-party captcha service is required in PoW mode.
