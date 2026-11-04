<?php $t = erTranslationClassLhTranslation::getInstance(); ?>
<h1><?php echo $t->getTranslation('pow/twofactor', 'Two-factor authentication'); ?></h1>

<?php if (isset($expired)) : ?>

    <div class="alert alert-warning">
        <?php echo $t->getTranslation('pow/twofactor', 'This verification has expired or is no longer valid. Please login again.'); ?>
    </div>
    <a class="btn btn-primary btn-sm" href="<?php echo erLhcoreClassDesign::baseurl('user/login') ?>"><?php echo $t->getTranslation('pow/twofactor', 'Back to login'); ?></a>

<?php else : ?>

    <?php if (isset($errors)) : ?>
        <?php include(erLhcoreClassDesign::designtpl('lhkernel/validation_error.tpl.php')); ?>
    <?php endif; ?>

    <?php if (!empty($info)) : ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($info) ?></div>
    <?php endif; ?>

    <p>
        <?php echo $t->getTranslation('pow/twofactor', 'You are signing in from a new IP address. We sent a 6-digit code to'); ?>
        <b><?php echo htmlspecialchars($masked_email) ?></b>.
    </p>

    <form method="post" action="<?php echo erLhcoreClassDesign::baseurl('powcaptcha/twofactor') ?>/<?php echo htmlspecialchars($token) ?>" autocomplete="off">
        <div class="form-group mb-3">
            <label><?php echo $t->getTranslation('pow/twofactor', 'Verification code'); ?></label>
            <input class="form-control form-control-lg text-center" type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" autofocus style="letter-spacing:8px;" />
        </div>

        <?php include(erLhcoreClassDesign::designtpl('lhkernel/csfr_token.tpl.php')); ?>

        <div class="d-flex justify-content-between align-items-center">
            <div class="btn-group btn-group-sm" role="group">
                <input type="submit" class="btn btn-primary" name="VerifyCode" value="<?php echo htmlspecialchars($t->getTranslation('pow/twofactor', 'Verify')); ?>" />
                <input type="submit" class="btn btn-outline-secondary" name="ResendCode" value="<?php echo htmlspecialchars($t->getTranslation('pow/twofactor', 'Resend code')); ?>" />
            </div>
            <a class="small" href="<?php echo erLhcoreClassDesign::baseurl('user/login') ?>"><?php echo $t->getTranslation('pow/twofactor', 'Cancel'); ?></a>
        </div>
    </form>

<?php endif; ?>
