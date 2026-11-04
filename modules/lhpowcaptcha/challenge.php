<?php

// 2FA pop-up endpoint. It lives in the already registered `challenge` view on purpose:
// LHC caches the view list of every module.
if (isset($_POST['pow_2fa_ajax'])) {
    ob_start();
    $pow2faResult = erLhcoreClassPowTwoFactor::handleAjax(isset($_POST['token']) ? (string)$_POST['token'] : '', $_POST);
    while (ob_get_level() > 0) { ob_end_clean(); } // drop PHP notices/warnings that would break the JSON
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    echo json_encode($pow2faResult);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

if (!erLhcoreClassPowCaptcha::isPowEnabled()) {
    http_response_code(404);
    echo json_encode(array(
        'error' => 'pow_disabled',
        'hint' => 'Enable PoW in site_admin/system/recaptcha'
    ));
    exit;
}

$action = isset($Params['user_parameters']['action']) ? (string)$Params['user_parameters']['action'] : '';

if (!erLhcoreClassPowCaptcha::isActionAllowed($action)) {
    http_response_code(400);
    echo json_encode(array('error' => 'action_invalid'));
    exit;
}

$retryAfter = null;
if (!erLhcoreClassPowCaptcha::isChallengeRequestAllowed($action, $retryAfter)) {
    http_response_code(429);
    if ($retryAfter !== null && $retryAfter > 0) {
        header('Retry-After: ' . (int)$retryAfter);
    }
    echo json_encode(array(
        'error' => 'rate_limited',
        'retry_after' => (int)($retryAfter ?? 1),
    ));
    exit;
}

$challenge = erLhcoreClassPowCaptcha::createChallenge($action);

echo json_encode(array(
    'challenge' => $challenge['challenge'],
    'difficulty' => $challenge['difficulty'],
    'expires_in' => $challenge['expires_in'],
));
exit;
