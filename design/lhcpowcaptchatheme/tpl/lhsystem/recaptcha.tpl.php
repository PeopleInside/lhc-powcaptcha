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

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Difficulty (12-26 leading zero bits)');?></label>
            <input type="number" min="12" max="26" step="1" class="form-control" name="pow_difficulty" value="<?php echo isset($rc_data['pow_difficulty']) ? (int)$rc_data['pow_difficulty'] : 18?>" />
        </div>

        <div class="form-group">
            <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Challenge TTL in seconds (60-600)');?></label>
            <input type="number" min="60" max="600" step="1" class="form-control" name="pow_ttl" value="<?php echo isset($rc_data['pow_ttl']) ? (int)$rc_data['pow_ttl'] : 180?>" />
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
