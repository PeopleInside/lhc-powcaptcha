<?php

header('Content-Type: application/json; charset=utf-8');

if (!erLhcoreClassPowCaptcha::isPowEnabled()) {
    http_response_code(404);
    echo json_encode(array('error' => 'pow_disabled'));
    exit;
}

$allowedActions = array('login_action', 'forgot_password_action');
$action = isset($Params['user_parameters']['action']) ? (string)$Params['user_parameters']['action'] : '';

if (!in_array($action, $allowedActions, true)) {
    http_response_code(400);
    echo json_encode(array('error' => 'action_invalid'));
    exit;
}

$challenge = erLhcoreClassPowCaptcha::createChallenge($action);

echo json_encode(array(
    'challenge' => $challenge['challenge'],
    'difficulty' => $challenge['difficulty'],
    'expires_in' => $challenge['expires_in'],
));
exit;
