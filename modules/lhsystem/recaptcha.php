<?php

$tpl = erLhcoreClassTemplate::getInstance('lhsystem/recaptcha.tpl.php');

$rcData = erLhcoreClassModelChatConfig::fetch('recaptcha_data');
$data = erLhcoreClassPowCaptcha::getRecaptchaSettings();

if (isset($_POST['StoreRecaptchaSettings'])) {
    $definition = array(
        'provider' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'unsafe_raw'
        ),
        'site_key' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'unsafe_raw'
        ),
        'secret_key' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'unsafe_raw'
        ),
        'turnstile_site_key' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'unsafe_raw'
        ),
        'turnstile_secret_key' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'unsafe_raw'
        ),
        'pow_difficulty' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'int'
        ),
        'pow_ttl' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'int'
        ),
        'pow_allowed_actions' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'unsafe_raw'
        ),
        'pow_honeypot' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'boolean'
        ),
        'pow_adaptive' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'boolean'
        ),
        'pow_adaptive_max_bonus' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'int'
        ),
        'pow_cred_penalty' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'boolean'
        ),
        'pow_cred_penalty_hours' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'int'
        ),
        'pow_new_ip_alert' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'boolean'
        ),
        'pow_new_ip_email' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'unsafe_raw'
        ),
        'enabled' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'boolean'
        )
    );

    if (!isset($_POST['csfr_token']) || !$currentUser->validateCSFRToken($_POST['csfr_token'])) {
        erLhcoreClassModule::redirect('system/recaptcha');
        exit;
    }

    $form = new ezcInputForm(INPUT_POST, $definition);

    if ($form->hasValidData('provider') && in_array($form->provider, array('google', 'turnstile', 'pow'))) {
        $data['provider'] = $form->provider;
    } else {
        $data['provider'] = 'google';
    }

    if ($form->hasValidData('site_key')) {
        $data['site_key'] = trim($form->site_key);
    } else {
        $data['site_key'] = '';
    }

    if ($form->hasValidData('secret_key') && $form->secret_key != '') {
        $data['secret_key'] = trim($form->secret_key);
    }

    if ($form->hasValidData('turnstile_site_key')) {
        $data['turnstile_site_key'] = trim($form->turnstile_site_key);
    } else {
        $data['turnstile_site_key'] = '';
    }

    if ($form->hasValidData('turnstile_secret_key') && $form->turnstile_secret_key != '') {
        $data['turnstile_secret_key'] = trim($form->turnstile_secret_key);
    }

    $data['pow_difficulty'] = ($form->hasValidData('pow_difficulty')) ? max(12, min(22, (int)$form->pow_difficulty)) : 18;
    $data['pow_ttl'] = ($form->hasValidData('pow_ttl')) ? max(60, min(600, (int)$form->pow_ttl)) : 180;
    if ($form->hasValidData('pow_allowed_actions')) {
        $data['pow_allowed_actions'] = erLhcoreClassPowCaptcha::parseAllowedActionsInput(trim((string)$form->pow_allowed_actions));
    } else {
        $data['pow_allowed_actions'] = erLhcoreClassPowCaptcha::getAllowedActions();
    }

    $data['pow_honeypot'] = ($form->hasValidData('pow_honeypot') && $form->pow_honeypot == 1) ? 1 : 0;
    $data['pow_adaptive'] = ($form->hasValidData('pow_adaptive') && $form->pow_adaptive == 1) ? 1 : 0;
    $data['pow_adaptive_max_bonus'] = ($form->hasValidData('pow_adaptive_max_bonus')) ? max(0, min(8, (int)$form->pow_adaptive_max_bonus)) : 4;

    // v1.4.3: 24h credential penalty and new IP email alert
    $data['pow_cred_penalty'] = ($form->hasValidData('pow_cred_penalty') && $form->pow_cred_penalty == 1) ? 1 : 0;
    $data['pow_cred_penalty_hours'] = ($form->hasValidData('pow_cred_penalty_hours')) ? max(1, min(168, (int)$form->pow_cred_penalty_hours)) : 24;

    $data['pow_new_ip_alert'] = ($form->hasValidData('pow_new_ip_alert') && $form->pow_new_ip_alert == 1) ? 1 : 0;
    $data['pow_new_ip_email'] = ($form->hasValidData('pow_new_ip_email')) ? trim((string)$form->pow_new_ip_email) : '';

    if ($form->hasValidData('enabled') && $form->enabled == 1) {
        $data['enabled'] = 1;
    } else {
        $data['enabled'] = 0;
    }

    $rcData->value = serialize($data);
    $rcData->saveThis();

    $CacheManager = erConfigClassLhCacheConfig::getInstance();
    $CacheManager->expireCache(true);

    $tpl->set('updated', 'done');
}

if (isset($_POST['ClearPowAttemptLog'])) {
    if (!isset($_POST['csfr_token']) || !$currentUser->validateCSFRToken($_POST['csfr_token'])) {
        erLhcoreClassModule::redirect('system/recaptcha');
        exit;
    }

    erLhcoreClassPowCaptcha::clearAttemptLog();
    $tpl->set('log_cleared', true);
}

// v1.4.3: Remove individual IP from limited list
if (isset($_POST['RemoveIpRestriction'])) {
    if (!isset($_POST['csfr_token']) || !$currentUser->validateCSFRToken($_POST['csfr_token'])) {
        erLhcoreClassModule::redirect('system/recaptcha');
        exit;
    }

    $ipToRemove = isset($_POST['ip']) ? trim((string)$_POST['ip']) : '';
    if ($ipToRemove !== '') {
        erLhcoreClassPowCaptcha::removeIpPenalty($ipToRemove);
        $tpl->set('ip_removed', $ipToRemove);
    }
}

// v1.4.3: Clear all limited IPs
if (isset($_POST['ClearAllIpRestrictions'])) {
    if (!isset($_POST['csfr_token']) || !$currentUser->validateCSFRToken($_POST['csfr_token'])) {
        erLhcoreClassModule::redirect('system/recaptcha');
        exit;
    }

    erLhcoreClassPowCaptcha::clearAllIpPenalties();
    $tpl->set('all_ips_cleared', true);
}

$tpl->set('rc_data', $data);
$tpl->set('pow_log', erLhcoreClassPowCaptcha::getAttemptLog());
$tpl->set('pow_failures_now', erLhcoreClassPowCaptcha::getRecentFailureCount());
$tpl->set('limited_ips', erLhcoreClassPowCaptcha::getLimitedIpsList());

$Result['content'] = $tpl->fetch();
$Result['path'] = array(
    array('url' => erLhcoreClassDesign::baseurl('system/configuration'), 'title' => erTranslationClassLhTranslation::getInstance()->getTranslation('system/htmlcode', 'System configuration')),
    array('title' => erTranslationClassLhTranslation::getInstance()->getTranslation('system/configuration', 'Captcha settings'))
);

?>
