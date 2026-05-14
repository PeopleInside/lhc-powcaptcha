<h1><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','PoW captcha settings (fallback page)');?></h1>

<div class="alert alert-info">
    <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Use this page only if `Local PoW captcha` is not visible in core captcha settings.');?>
    <a href="<?php echo erLhcoreClassDesign::baseurl('system/recaptcha')?>"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Open core captcha settings');?></a>
</div>

<?php if (isset($updated) && $updated == 'done') : $msg = erTranslationClassLhTranslation::getInstance()->getTranslation('system/smtp','Settings updated'); ?>
    <?php include(erLhcoreClassDesign::designtpl('lhkernel/alert_success.tpl.php'));?>
<?php endif; ?>

<form action="" method="post" autocomplete="off" ng-non-bindable>

    <div class="form-group">
        <label><input type="checkbox" value="on" name="enabled" <?php (isset($rc_data['enabled']) && $rc_data['enabled'] == 1) ? print 'checked="checked"' : ''?> /> <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/timezone','Enable');?></label>
    </div>

    <div class="form-group">
        <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Provider');?></label>
        <input type="text" class="form-control" value="pow" readonly />
        <small class="form-text text-muted"><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','This fallback page always stores provider as `pow`.');?></small>
    </div>

    <div class="form-group">
        <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Difficulty (12-26 leading zero bits)');?></label>
        <input type="number" min="12" max="26" step="1" class="form-control" name="pow_difficulty" value="<?php isset($rc_data['pow_difficulty']) ? print (int)$rc_data['pow_difficulty'] : 18?>" />
    </div>

    <div class="form-group">
        <label><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/recaptcha','Challenge TTL in seconds (60-600)');?></label>
        <input type="number" min="60" max="600" step="1" class="form-control" name="pow_ttl" value="<?php isset($rc_data['pow_ttl']) ? print (int)$rc_data['pow_ttl'] : 180?>" />
    </div>

    <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php'));?>

    <input type="submit" class="btn btn-secondary" name="StorePowSettings" value="<?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('system/buttons','Update'); ?>" />

</form>
