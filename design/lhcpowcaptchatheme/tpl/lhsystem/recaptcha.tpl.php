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
                <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','APCu is not available. PoW will still work, but per-IP challenge rate limiting, per-IP adaptive difficulty and cross-session replay detection are reduced to session-only protections.');?>
            </div>
        <?php endif; ?>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Difficulty (12-22 leading zero bits)');?></label>
            <input type="number" min="12" max="22" step="1" class="form-control" name="pow_difficulty" value="<?php echo isset($rc_data['pow_difficulty']) ? (int)$rc_data['pow_difficulty'] : 18?>" />
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
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Adds an invisible field to the form. Humans never see it; bots that fill every field fail the captcha and count as a failure.');?></small>
        </div>

        <div class="form-group">
            <label><input type="checkbox" value="on" name="pow_adaptive" <?php (!isset($rc_data['pow_adaptive']) || $rc_data['pow_adaptive'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Increase difficulty after failed attempts');?></label>
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Each failed captcha attempt in the last 15 minutes from the same IP (needs APCu) or session adds 1 bit (doubles the work), up to the maximum below.');?></small>
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Maximum extra difficulty bits (0-8)');?></label>
            <input type="number" min="0" max="8" step="1" class="form-control" name="pow_adaptive_max_bonus" value="<?php echo isset($rc_data['pow_adaptive_max_bonus']) ? (int)$rc_data['pow_adaptive_max_bonus'] : 4?>" />
            <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','The total (base + extra) is always capped at 22: above that a browser cannot solve the challenge within the TTL.');?></small>
        </div>
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

<?php if ((isset($rc_data['provider']) && $rc_data['provider'] === 'pow') || !empty($pow_log)) : ?>
<hr />

<h2><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Last PoW captcha attempts');?></h2>

<?php if (isset($log_cleared) && $log_cleared === true) : $msg = erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Attempt log cleared'); ?>
    <?php include(erLhcoreClassDesign::designtpl('lhkernel/alert_success.tpl.php'));?>
<?php endif; ?>

<p class="text-muted small">
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Shows the last 30 attempts (newest first). IP address and user agent are stored for security purposes only; use the button below to delete them.');?>
    <?php if (isset($rc_data['pow_adaptive']) && (int)$rc_data['pow_adaptive'] === 1) : ?>
        <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Recent failures counted for your current IP/session:');?> <b><?php echo (int)$pow_failures_now?></b>
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
            <th><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','User agent');?></th>
        </tr>
        </thead>
        <?php foreach ($pow_log as $powRow) : ?>
        <tr>
            <td class="text-nowrap"><?php echo htmlspecialchars(date('Y-m-d H:i:s', $powRow['t']))?></td>
            <td><?php echo htmlspecialchars($powRow['ip'])?></td>
            <td><?php echo htmlspecialchars($powRow['a'])?></td>
            <td>
                <?php if ($powRow['ok'] === 1) : ?>
                    <span class="badge badge-success bg-success"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','OK');?></span>
                <?php else : ?>
                    <span class="badge badge-danger bg-danger"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Failed');?></span>
                <?php endif; ?>
            </td>
            <td><?php echo htmlspecialchars($powRow['r'])?></td>
            <td><?php echo (int)$powRow['d']?></td>
            <td class="small"><?php echo htmlspecialchars($powRow['ua'])?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    </div>

    <form action="" method="post" ng-non-bindable onsubmit="return confirm(<?php echo htmlspecialchars(json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Delete all logged attempts?')), ENT_QUOTES)?>);">
        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>
        <input type="submit" class="btn btn-danger btn-sm" name="ClearPowAttemptLog" value="<?php echo htmlspecialchars(erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Clear log'))?>" />
    </form>
<?php endif; ?>
<?php endif; ?>
