<?php

$tpl = erLhcoreClassTemplate::getInstance('lhpowcaptcha/settings.tpl.php');

$currentUser = erLhcoreClassUser::instance();
$rcData = erLhcoreClassModelChatConfig::fetch('recaptcha_data');
$data = erLhcoreClassPowCaptcha::getRecaptchaSettings();

if (isset($_POST['StorePowSettings'])) {
    $definition = array(
        'pow_difficulty' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'int'
        ),
        'pow_ttl' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'int'
        ),
        'enabled' => new ezcInputFormDefinitionElement(
            ezcInputFormDefinitionElement::OPTIONAL, 'boolean'
        )
    );

    if (!isset($_POST['csfr_token']) || !$currentUser->validateCSFRToken($_POST['csfr_token'])) {
        erLhcoreClassModule::redirect('powcaptcha/settings');
        exit;
    }

    $form = new ezcInputForm(INPUT_POST, $definition);

    $data['provider'] = 'pow';
    $data['pow_difficulty'] = ($form->hasValidData('pow_difficulty')) ? max(12, min(26, (int)$form->pow_difficulty)) : 18;
    $data['pow_ttl'] = ($form->hasValidData('pow_ttl')) ? max(60, min(600, (int)$form->pow_ttl)) : 180;
    $data['enabled'] = ($form->hasValidData('enabled') && $form->enabled == 1) ? 1 : 0;

    $rcData->value = serialize($data);
    $rcData->saveThis();

    $CacheManager = erConfigClassLhCacheConfig::getInstance();
    $CacheManager->expireCache(true);

    $tpl->set('updated', 'done');
}

$tpl->set('rc_data', $data);

$Result['content'] = $tpl->fetch();
$Result['path'] = array(
    array(
        'url' => erLhcoreClassDesign::baseurl('system/configuration'),
        'title' => erTranslationClassLhTranslation::getInstance()->getTranslation('system/htmlcode', 'System configuration')
    ),
    array(
        'title' => erTranslationClassLhTranslation::getInstance()->getTranslation('system/configuration', 'PoW captcha settings (fallback)')
    )
);

?>
