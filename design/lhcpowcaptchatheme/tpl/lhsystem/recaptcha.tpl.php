<h1><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Captcha settings');?></h1>

<p class="text-muted small">
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','PoW captcha integrates in this core page; a separate extension settings page is not required.');?>
</p>

<?php if (isset($updated) && $updated == 'done') : $msg = erTranslationClassLhTranslation::getInstance()->getTranslation('system/smtp','Settings updated'); ?>
    <?php include(erLhcoreClassDesign::designtpl('lhkernel/alert_success.tpl.php'));?>
<?php endif; ?>

<form action="" method="post" autocomplete="off" ng-non-bindable>

    <div class="form-group">
        <label><input type="checkbox" value="on" name="enabled" <?php (isset($rc_data['enabled']) && $rc_data['enabled'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/timezone','Enable');?></label>
    </div>

    <div class="form-group">
        <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Captcha provider');?></label>
        <select class="form-control" name="provider" id="id-captcha-provider">
            <option value="google" <?php (isset($rc_data['provider']) && $rc_data['provider'] === 'google') ? print 'selected="selected"' : ''?>><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Google reCAPTCHA v3');?></option>
            <option value="turnstile" <?php (isset($rc_data['provider']) && $rc_data['provider'] === 'turnstile') ? print 'selected="selected"' : ''?>><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Cloudflare Turnstile');?></option>
            <option value="pow" <?php (isset($rc_data['provider']) && $rc_data['provider'] === 'pow') ? print 'selected="selected"' : ''?>><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Local PoW captcha');?></option>
        </select>
    </div>

    <div id="provider-settings-google" class="provider-settings">
        <p>
            <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','This works with Google reCAPTCHA v3.');?>
            <a href="https://www.google.com/recaptcha/admin#v3signup" target="_blank"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Get Google reCAPTCHA keys');?></a>
        </p>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Site key');?></label>
            <input type="text" class="form-control" name="site_key" value="<?php isset($rc_data['site_key']) ? print htmlspecialchars($rc_data['site_key']) : ''?>" />
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Secret key');?></label>
            <input type="text" class="form-control" name="secret_key" value="" />
            <p><i><small><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Secret key is not shown!');?></small></i></p>
        </div>
    </div>

    <div id="provider-settings-turnstile" class="provider-settings">
        <p>
            <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','This works with Cloudflare Turnstile.');?>
            <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Get Cloudflare Turnstile keys');?></a>
        </p>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Site key');?></label>
            <input type="text" class="form-control" name="turnstile_site_key" value="<?php isset($rc_data['turnstile_site_key']) ? print htmlspecialchars($rc_data['turnstile_site_key']) : ''?>" />
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Secret key');?></label>
            <input type="text" class="form-control" name="turnstile_secret_key" value="" />
            <p><i><small><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Secret key is not shown!');?></small></i></p>
        </div>
    </div>

    <div id="provider-settings-pow" class="provider-settings">
        <p>
            <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','This uses a local Proof-of-Work captcha and does not require third-party services.');?>
        </p>
        <?php if (!erLhcoreClassPowCaptcha::isApcuAvailable()) : ?>
            <div class="alert alert-warning">
                <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','APCu is not available. PoW will still work, but per-IP challenge rate limiting and APCu cross-session replay detection are reduced to database/session protections.');?>
            </div>
        <?php endif; ?>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Difficulty (12-22 leading zero bits)');?></label>
            <input type="number" min="12" max="22" step="1" class="form-control" name="pow_difficulty" value="<?php echo isset($rc_data['pow_difficulty']) ? (int)$rc_data['pow_difficulty'] : 18?>" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Default: 18 bits (~262k hashes, ~0.2s in modern browser).');?></small>
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Challenge TTL in seconds (60-600)');?></label>
            <input type="number" min="60" max="600" step="1" class="form-control" name="pow_ttl" value="<?php echo isset($rc_data['pow_ttl']) ? (int)$rc_data['pow_ttl'] : 180?>" />
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Allowed captcha actions');?></label>
            <input type="text" class="form-control" name="pow_allowed_actions" value="<?php echo htmlspecialchars(implode(',', erLhcoreClassPowCaptcha::getAllowedActions()))?>" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Comma-separated action names (letters, numbers, underscore).');?></small>
        </div>

        <div class="form-group">
            <label><input type="checkbox" value="on" name="pow_honeypot" <?php (!isset($rc_data['pow_honeypot']) || $rc_data['pow_honeypot'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Honeypot field (hidden trap for bots)');?></label>
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Adds an invisible field to the form. Humans never see it; bots that fill every field fail the captcha.');?></small>
        </div>

        <div class="form-group">
            <label><input type="checkbox" value="on" name="pow_adaptive" <?php (!isset($rc_data['pow_adaptive']) || $rc_data['pow_adaptive'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Increase difficulty after failed captcha attempts');?></label>
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Each failed captcha attempt in the last 15 minutes adds 1 bit.');?></small>
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Maximum extra difficulty bits (0-8)');?></label>
            <input type="number" min="0" max="8" step="1" class="form-control" name="pow_adaptive_max_bonus" value="<?php echo isset($rc_data['pow_adaptive_max_bonus']) ? (int)$rc_data['pow_adaptive_max_bonus'] : 4?>" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','The total difficulty is always capped at 22 bits.');?></small>
        </div>

        <hr />
        <h5 class="text-primary"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Failed login protection (wrong credentials)');?></h5>

        <div class="form-group">
            <label><input type="checkbox" value="on" name="pow_cred_penalty" <?php (!isset($rc_data['pow_cred_penalty']) || $rc_data['pow_cred_penalty'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Increase captcha difficulty after failed login (wrong credentials)');?></label>
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','When an operator login fails due to incorrect credentials, the captcha difficulty automatically increases for that IP address for at least 24 hours. Each failed attempt adds +1 bit (doubling the work).');?></small>
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','IP penalty duration (hours, 1-168)');?></label>
            <input type="number" min="1" max="168" step="1" class="form-control" name="pow_cred_penalty_hours" value="<?php echo isset($rc_data['pow_cred_penalty_hours']) ? (int)$rc_data['pow_cred_penalty_hours'] : 24?>" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Default: 24 hours. During this period, the IP must solve higher difficulty challenges.');?></small>
        </div>

        <hr />
        <h5 class="text-primary"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','New IP login security alerts');?></h5>

        <div class="form-group">
            <label><input type="checkbox" value="on" name="pow_new_ip_alert" <?php (!isset($rc_data['pow_new_ip_alert']) || $rc_data['pow_new_ip_alert'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Send email alert when an operator logs in from a new IP address');?></label>
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Detects when an account signs in from an IP not previously associated with it and dispatches an immediate security alert email.');?></small>
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Notification recipient email (optional)');?></label>
            <input type="email" class="form-control" name="pow_new_ip_email" value="<?php echo isset($rc_data['pow_new_ip_email']) ? htmlspecialchars($rc_data['pow_new_ip_email']) : ''?>" placeholder="admin@example.com" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','If left blank, the alert is sent directly to the email of the operator whose account was accessed.');?></small>
        </div>
        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Maximum difficulty after penalties (14-22 bits)');?></label>
            <input type="number" min="14" max="22" step="1" class="form-control" name="pow_max_difficulty" value="<?php echo isset($rc_data['pow_max_difficulty']) ? (int)$rc_data['pow_max_difficulty'] : 20?>" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Failed logins and captcha failures raise the difficulty, but never above this value. Each extra bit doubles the solving time: 22 bits can take minutes in a browser, 20 bits is about four times faster.');?></small>
        </div>
    </div>

    <hr />
    <h5 class="text-primary"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Two-factor authentication (e-mail code)');?></h5>

    <div class="form-group">
        <label><input type="checkbox" value="on" name="pow_2fa" <?php (!empty($rc_data['pow_2fa'])) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Require an e-mail code when an operator logs in from a new IP address');?></label>
        <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','The code is requested only after a correct username and password, and only from an IP not yet known for that account. Known IPs are learned after each successful login. If SMTP fails or the operator has no valid e-mail, login proceeds without 2FA.');?></small>
    </div>

    <div class="row">
        <div class="col-md-4 form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Code validity in minutes (3-30)');?></label>
            <input type="number" min="3" max="30" class="form-control" name="pow_2fa_ttl" value="<?php echo isset($rc_data['pow_2fa_ttl']) ? (int)$rc_data['pow_2fa_ttl'] : 10?>" />
        </div>
        <div class="col-md-4 form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Max wrong codes before restart (3-10)');?></label>
            <input type="number" min="3" max="10" class="form-control" name="pow_2fa_attempts" value="<?php echo isset($rc_data['pow_2fa_attempts']) ? (int)$rc_data['pow_2fa_attempts'] : 5?>" />
        </div>
        <div class="col-md-4 form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Known IP expiration (1-12 months)');?></label>
            <input type="number" min="1" max="12" step="1" class="form-control" name="pow_2fa_ip_ttl" value="<?php echo isset($rc_data['pow_2fa_ip_ttl']) ? (int)$rc_data['pow_2fa_ip_ttl'] : 6?>" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Default: 6 months (configurable up to 12). Expired IPs require 2FA again.');?></small>
        </div>
    </div>

    <hr />
    <h5 class="text-primary"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','HTML e-mails');?></h5>
    <div class="form-group">
        <label><input type="checkbox" value="on" name="pow_html_mail" <?php (!isset($rc_data['pow_html_mail']) || $rc_data['pow_html_mail'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Send Live Helper Chat e-mails (password reminder, chat transcript, notifications) as formatted HTML');?></label>
        <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Plain-text version is always attached as fallback. A few core notifications that fill the body after SMTP setup (unaccepted chat, visitor returned) stay as they are.');?></small>
    </div>

    <hr />
    <h5 class="text-primary"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Operator login history');?></h5>
    <div class="form-group">
        <label><input type="checkbox" value="on" name="pow_clear_loginhistory" <?php (!empty($rc_data['pow_clear_loginhistory'])) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Enable button to clear logs in operator login history (audit/loginhistory)');?></label>
        <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','When enabled, a button to clear the entire login history will appear on the audit/loginhistory page.');?></small>
    </div>

    <script>
        (function() {
            function toggleCaptchaProviderSettings() {
                var provider = document.getElementById('id-captcha-provider').value;
                document.getElementById('provider-settings-google').style.display = provider === 'google' ? 'block' : 'none';
                document.getElementById('provider-settings-turnstile').style.display = provider === 'turnstile' ? 'block' : 'none';
                document.getElementById('provider-settings-pow').style.display = provider === 'pow' ? 'block' : 'none';
            }

            document.getElementById('id-captcha-provider').addEventListener('change', toggleCaptchaProviderSettings);
            toggleCaptchaProviderSettings();
        })();
    </script>

    <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>

    <input type="submit" class="btn btn-secondary" name="StoreRecaptchaSettings" value="<?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/buttons','Update'); ?>" />

</form>

<?php if ((isset($rc_data['provider']) && $rc_data['provider'] === 'pow') || !empty($limited_ips) || !empty($pow_log)) : ?>
<hr />

<!-- =========================================================================
     Limited IPs Section (v1.4.3)
     ========================================================================= -->
<h2><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Limited IPs (Increased Captcha Difficulty)');?></h2>

<?php if (isset($ip_removed)) : ?>
    <div class="alert alert-success">
        <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','IP restriction removed for');?>: <b><?php echo htmlspecialchars($ip_removed)?></b>
    </div>
<?php endif; ?>

<?php if (isset($all_ips_cleared) && $all_ips_cleared === true) : ?>
    <div class="alert alert-success">
        <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','All IP restrictions have been cleared successfully.');?>
    </div>
<?php endif; ?>

<p class="text-muted small">
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','List of IP addresses currently facing increased captcha difficulty due to failed login credentials. Penalties automatically expire after 24 hours or can be cleared manually below.');?>
</p>

<?php if (empty($limited_ips)) : ?>
    <p class="text-muted"><i><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','No IPs are currently restricted.');?></i></p>
<?php else : ?>
    <p>
        <span class="badge badge-warning bg-warning text-dark"><?php echo count($limited_ips)?> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','IP address(es) limited');?></span>
    </p>

    <div class="table-responsive">
    <table class="table table-sm table-striped">
        <thead>
        <tr>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','IP Address');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Failed Logins');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Penalty');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Effective Difficulty');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Last Failure');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Expires In');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Attempted User');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Action');?></th>
        </tr>
        </thead>
        <tbody>
        <?php $now = time(); ?>
        <?php foreach ($limited_ips as $limited) : ?>
            <?php
                $remainingSec = max(0, (int)$limited['expires_at'] - $now);
                $remHours = intdiv($remainingSec, 3600);
                $remMins = intdiv($remainingSec % 3600, 60);
                $effDiff = erLhcoreClassPowCaptcha::getEffectiveDifficulty($rc_data, $limited['ip']);
            ?>
            <tr>
                <td><code><?php echo htmlspecialchars($limited['ip'])?></code></td>
                <td><span class="badge badge-danger bg-danger"><?php echo (int)$limited['count']?></span></td>
                <td>+<?php echo (int)($limited['bonus'] ?? 1)?> bits</td>
                <td><b><?php echo (int)$effDiff?> bits</b></td>
                <td class="text-nowrap"><?php echo htmlspecialchars(date('Y-m-d H:i:s', $limited['last_at']))?></td>
                <td class="text-nowrap"><?php echo sprintf('%02dh %02dm', $remHours, $remMins)?></td>
                <td><small><?php echo htmlspecialchars($limited['user'] ?? '—')?></small></td>
                <td>
                    <form action="" method="post" style="display:inline;" ng-non-bindable onsubmit="return confirm('<?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Remove restriction for this IP?');?>');">
                        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>
                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($limited['ip'])?>" />
                        <button type="submit" name="RemoveIpRestriction" class="btn btn-outline-danger btn-xs btn-sm py-0 px-2" title="<?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Unblock IP');?>">
                            ✕ <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Unblock');?>
                        </button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>

    <form action="" method="post" ng-non-bindable onsubmit="return confirm('<?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Clear all IP restrictions? All IPs will return to base difficulty.');?>');" class="mb-3">
        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>
        <input type="submit" class="btn btn-warning btn-sm" name="ClearAllIpRestrictions" value="<?php echo htmlspecialchars(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Clear all limited IPs'))?>" />
    </form>
<?php endif; ?>

<hr />

<!-- =========================================================================
     Known IPs Section for 2FA
     ========================================================================= -->
<h2><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Known IPs (Two-Factor Authentication)');?></h2>

<?php if (isset($known_ip_removed)) : ?>
    <div class="alert alert-success">
        <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Known IP removed successfully');?>: <b><?php echo htmlspecialchars($known_ip_removed)?></b>
    </div>
<?php endif; ?>

<?php if (isset($known_ips_cleared)) : $msg = erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Known IPs cleared. Every operator will receive a 2FA code at the next login.'); ?>
    <?php include(erLhcoreClassDesign::designtpl('lhkernel/alert_success.tpl.php'));?>
<?php endif; ?>

<p class="text-muted small">
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','List of IP addresses recognized for operator 2-Factor Authentication. Known IPs expire after');?>
    <b><?php echo (int)($rc_data['pow_2fa_ip_ttl'] ?? 6)?> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','month(s)');?></b>.
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','When an IP expires or is removed, the operator will be prompted for an email 2FA verification code on their next login.');?>
</p>

<?php if (empty($known_ips_list)) : ?>
    <p class="text-muted"><i><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','No known 2FA IPs currently recorded.');?></i></p>
<?php else : ?>
    <p>
        <span class="badge badge-info bg-info text-white"><?php echo count($known_ips_list)?> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','known IP(s) recorded');?></span>
        <span class="badge badge-secondary bg-secondary text-white"><?php echo (int)$known_ips_users?> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','operator account(s)');?></span>
    </p>

    <div class="table-responsive">
    <table class="table table-sm table-striped">
        <thead>
        <tr>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Operator');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','IP Address');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Learned At');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Expires / Status');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Action');?></th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($known_ips_list as $kIp) : ?>
            <tr>
                <td><b><?php echo htmlspecialchars($kIp['username'])?></b> <small class="text-muted">(ID: <?php echo (int)$kIp['user_id']?>)</small></td>
                <td><code><?php echo htmlspecialchars($kIp['ip'])?></code></td>
                <td class="text-nowrap"><?php echo htmlspecialchars(date('Y-m-d H:i:s', $kIp['recorded_at']))?></td>
                <td class="text-nowrap">
                    <?php if ($kIp['is_expired']) : ?>
                        <span class="badge badge-danger bg-danger"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Expired');?></span>
                    <?php else : ?>
                        <?php
                            $remDays = intdiv($kIp['remaining'], 86400);
                            $remHours = intdiv($kIp['remaining'] % 86400, 3600);
                        ?>
                        <span class="badge badge-success bg-success"><?php echo sprintf('%dd %02dh', $remDays, $remHours)?></span>
                        <small class="text-muted">(<?php echo htmlspecialchars(date('Y-m-d', $kIp['expires_at']))?>)</small>
                    <?php endif; ?>
                </td>
                <td>
                    <form action="" method="post" style="display:inline;" ng-non-bindable onsubmit="return confirm('<?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Forget this known IP? The operator will need 2FA verification on next login.');?>');">
                        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>
                        <input type="hidden" name="user_id" value="<?php echo (int)$kIp['user_id']?>" />
                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($kIp['ip'])?>" />
                        <button type="submit" name="RemoveKnownIp" class="btn btn-outline-danger btn-xs btn-sm py-0 px-2" title="<?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Forget this IP');?>">
                            ✕ <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Forget IP');?>
                        </button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>

    <form action="" method="post" ng-non-bindable class="mb-4" onsubmit="return confirm(<?php echo htmlspecialchars(json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Forget all known IPs? Every operator will be asked for a 2FA code at the next login.')), ENT_QUOTES)?>);">
        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>
        <input type="submit" class="btn btn-warning btn-sm" name="ResetKnownIps" value="<?php echo htmlspecialchars(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Reset all known IPs (2FA)'))?>" />
    </form>
<?php endif; ?>

<!-- =========================================================================
     Last Captcha Attempts Log Section
     ========================================================================= -->
<h2><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Last PoW captcha attempts');?></h2>

<?php if (isset($log_cleared) && $log_cleared === true) : $msg = erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Attempt log cleared'); ?>
    <?php include(erLhcoreClassDesign::designtpl('lhkernel/alert_success.tpl.php'));?>
<?php endif; ?>

<div class="alert alert-info small">
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','This log only contains captcha / 2FA events of this extension. Clearing it does not touch the core operators login history, which is a separate page:');?>
    <a href="<?php echo erLhcoreClassDesign::baseurl('audit/loginhistory')?>"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Login history');?></a>.
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','To reset IP restrictions use "Clear all limited IPs" above; to make 2FA ask for the code again use "Reset known IPs (2FA)".');?>
    <?php if (!empty($rc_data['pow_clear_loginhistory'])) : ?>
        <br /><span class="badge badge-success bg-success text-white mt-1">✓ <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Clear button enabled on audit/loginhistory page');?></span>
    <?php endif; ?>
</div>

<?php if (!empty($rc_data['pow_clear_loginhistory'])) : ?>
    <?php if (isset($loginhistory_cleared)) : $msg = erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Login history logs have been cleared successfully.'); ?>
        <?php include(erLhcoreClassDesign::designtpl('lhkernel/alert_success.tpl.php'));?>
    <?php endif; ?>
    <form action="" method="post" ng-non-bindable class="mb-3" onsubmit="return confirm(<?php echo htmlspecialchars(json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Clear all records in operator login history? This action cannot be undone.')), ENT_QUOTES)?>);">
        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>
        <button type="submit" class="btn btn-outline-danger btn-sm" name="ClearLoginHistory">
            ✕ <?php echo htmlspecialchars(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Clear login history now'))?>
        </button>
    </form>
<?php endif; ?>

<p class="text-muted small">
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Shows the last attempts (newest first) including bad credentials and security alert dispatches. IP address and user agent are stored for security purposes only; use the button below to delete them.');?>
    <?php if (isset($rc_data['pow_adaptive']) && (int)$rc_data['pow_adaptive'] === 1) : ?>
        &bull; <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Recent short-term failures for your current IP/session:');?> <b><?php echo (int)$pow_failures_now?></b>
    <?php endif; ?>
</p>

<?php if (empty($pow_log)) : ?>
    <p><i><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','No attempts recorded.');?></i></p>
<?php else : ?>
    <?php $powOk = 0; foreach ($pow_log as $powRow) { $powOk += $powRow['ok']; } ?>
    <p>
        <span class="badge badge-success bg-success"><?php echo (int)$powOk?> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','passed');?></span>
        <span class="badge badge-danger bg-danger"><?php echo count($pow_log) - (int)$powOk?> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','failed');?></span>
    </p>
    <div class="table-responsive">
    <table class="table table-sm">
        <thead>
        <tr>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Date');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','IP');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Action');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Result');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Reason');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Difficulty');?></th>
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','User / Agent');?></th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($pow_log as $powRow) : ?>
        <tr>
            <td class="text-nowrap"><?php echo htmlspecialchars(date('Y-m-d H:i:s', $powRow['t']))?></td>
            <td><code><?php echo htmlspecialchars($powRow['ip'])?></code></td>
            <td><?php echo htmlspecialchars($powRow['a'])?></td>
            <td>
                <?php if ($powRow['ok'] === 1) : ?>
                    <span class="badge badge-success bg-success"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','OK');?></span>
                <?php else : ?>
                    <span class="badge badge-danger bg-danger"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Failed');?></span>
                <?php endif; ?>
            </td>
            <td>
                <?php if ($powRow['r'] === 'bad_credentials') : ?>
                    <span class="badge badge-warning bg-warning text-dark">bad_credentials (login failed)</span>
                <?php elseif ($powRow['r'] === 'new_ip_login_alert_sent') : ?>
                    <span class="badge badge-info bg-info text-white">new_ip_alert_sent</span>
                <?php elseif (strpos($powRow['r'], 'two_factor_') === 0) : ?>
                    <span class="badge badge-primary bg-primary text-white"><?php echo htmlspecialchars($powRow['r'])?></span>
                <?php else : ?>
                    <code><?php echo htmlspecialchars($powRow['r'])?></code>
                <?php endif; ?>
            </td>
            <td><b><?php echo (int)$powRow['d']?> bits</b></td>
            <td class="small"><?php echo htmlspecialchars($powRow['ua'])?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>

    <form action="" method="post" ng-non-bindable onsubmit="return confirm(<?php echo htmlspecialchars(json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Delete all logged attempts?')), ENT_QUOTES)?>);">
        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>
        <input type="submit" class="btn btn-danger btn-sm" name="ClearPowAttemptLog" value="<?php echo htmlspecialchars(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Clear log'))?>" />
    </form>
<?php endif; ?>
<?php endif; ?>
