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

    $data['pow_difficulty'] = ($form->hasValidData('pow_difficulty')) ? max(12, min(26, (int)$form->pow_difficulty)) : 18;
    $data['pow_ttl'] = ($form->hasValidData('pow_ttl')) ? max(60, min(600, (int)$form->pow_ttl)) : 180;
    if ($form->hasValidData('pow_allowed_actions')) {
        $data['pow_allowed_actions'] = erLhcoreClassPowCaptcha::parseAllowedActionsInput(trim((string)$form->pow_allowed_actions));
    } else {
        $data['pow_allowed_actions'] = erLhcoreClassPowCaptcha::getAllowedActions();
    }

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

$tpl->set('rc_data', $data);

$Result['content'] = $tpl->fetch();
$Result['path'] = array(array('url' => erLhcoreClassDesign::baseurl('system/configuration'), 'title' => erTranslationClassLhTranslation::getInstance()->getTranslation('system/htmlcode', 'System configuration')),
    array('title' => erTranslationClassLhTranslation::getInstance()->getTranslation('system/configuration', 'Captcha settings')));

?>
