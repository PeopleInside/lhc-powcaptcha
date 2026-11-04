<?php

header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate');

$currentUser = erLhcoreClassUser::instance();

if ($currentUser->isLogged()) {
    erLhcoreClassModule::redirect();
    exit;
}

$tpl = erLhcoreClassTemplate::getInstance('lhpowcaptcha/twofactor.tpl.php');
$t = erTranslationClassLhTranslation::getInstance();

$token = isset($Params['user_parameters']['token']) ? (string)$Params['user_parameters']['token'] : '';
$state = erLhcoreClassPowTwoFactor::getPending($token);

// Pop-up on the login page talks to this view through AJAX (the unguessable token is the secret)
if (isset($_POST['ajax'])) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(erLhcoreClassPowTwoFactor::handleAjax($token, $_POST));
    exit;
}

if ($state === null) {
    $tpl->set('expired', true);
} else {
    $errors = array();
    $info = '';
    $csrfOk = isset($_POST['csfr_token']) && $currentUser->validateCSFRToken($_POST['csfr_token']);

    if (isset($_POST['VerifyCode']) || isset($_POST['ResendCode'])) {
        if (!$csrfOk) {
            $errors[] = $t->getTranslation('pow/twofactor', 'Session expired, please try again.');
        } elseif (isset($_POST['ResendCode'])) {
            $err = null;
            if (erLhcoreClassPowTwoFactor::resend($token, $err)) {
                $info = $t->getTranslation('pow/twofactor', 'A new code has been sent.');
            } elseif ($err === 'cooldown') {
                $errors[] = $t->getTranslation('pow/twofactor', 'Please wait a minute before requesting another code.');
            } else {
                $errors[] = $t->getTranslation('pow/twofactor', 'Could not send the code. Please login again.');
            }
        } else {
            $err = null;
            $ok = erLhcoreClassPowTwoFactor::verify($token, isset($_POST['code']) ? (string)$_POST['code'] : '', $err);

            if ($ok !== null && erLhcoreClassPowTwoFactor::finalizeLogin($ok)) {
                $redirect = $ok['red'] !== '' ? base64_decode($ok['red']) : '';
                if ($redirect !== '' && erLhcoreClassUserUtils::isValidRedirectPath($redirect)) {
                    erLhcoreClassModule::redirect($redirect);
                } else {
                    erLhcoreClassModule::redirect();
                }
                exit;
            }

            if ($err === 'wrong') {
                erLhcoreClassPowTwoFactor::failedAttempt($state);
                $errors[] = $t->getTranslation('pow/twofactor', 'Incorrect code.');
            } else {
                $tpl->set('expired', true);
                $state = null;
            }
        }
    }

    if ($state !== null) {
        $user = erLhcoreClassModelUser::fetch((int)$state['uid']);
        $tpl->set('masked_email', $user instanceof erLhcoreClassModelUser ? erLhcoreClassPowTwoFactor::maskEmail((string)$user->email) : '');
        $tpl->set('token', $token);
        if (!empty($errors)) {
            $tpl->set('errors', $errors);
        }
        $tpl->set('info', $info);
    }
}

$Result['content'] = $tpl->fetch();
$Result['pagelayout'] = 'login';
$Result['path'] = array(array('title' => $t->getTranslation('pow/twofactor', 'Two-factor authentication')));
