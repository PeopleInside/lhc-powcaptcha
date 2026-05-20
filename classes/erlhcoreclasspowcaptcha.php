<?php

#[\AllowDynamicProperties]
class erLhcoreClassPowCaptcha
{
    private const DEFAULT_DIFFICULTY = 18;
    private const DEFAULT_TTL = 180;
    private const MIN_DIFFICULTY = 12;
    private const MAX_DIFFICULTY = 26;
    private const MIN_TTL = 60;
    private const MAX_TTL = 600;
    private const MAX_CHALLENGE_LENGTH = 2048;
    private const CHALLENGE_RL_WINDOW_SECONDS = 60;
    private const CHALLENGE_RL_PER_SESSION = 30;
    private const CHALLENGE_RL_PER_IP = 180;
    private const MAX_SESSION_REPLAY_ENTRIES = 256;
    private const BINDING_COOKIE_NAME = 'lhc_powcaptcha_ctx';
    private const BINDING_COOKIE_TTL = 86400;
    private const DEFAULT_ALLOWED_ACTIONS = array('login_action', 'forgot_password_action');

    private static bool $apcuMissingLogged = false;

    public static function getRecaptchaSettings(): array
    {
        $settings = array();
        $rcData = erLhcoreClassModelChatConfig::fetch('recaptcha_data');

        if ($rcData instanceof erLhcoreClassModelChatConfig && is_array($rcData->data_value)) {
            $settings = $rcData->data_value;
        }

        if (empty($settings)) {
            $settings = \LiveHelperChat\Validators\CaptchaValidator::getCaptchaSettings();
        }

        $settings['provider'] = isset($settings['provider']) ? (string)$settings['provider'] : 'google';
        if (!in_array($settings['provider'], array('google', 'turnstile', 'pow'), true)) {
            $settings['provider'] = 'google';
        }

        $settings['enabled'] = (isset($settings['enabled']) && (int)$settings['enabled'] === 1) ? 1 : 0;
        $settings['site_key'] = isset($settings['site_key']) ? (string)$settings['site_key'] : '';
        $settings['secret_key'] = isset($settings['secret_key']) ? (string)$settings['secret_key'] : '';
        $settings['turnstile_site_key'] = isset($settings['turnstile_site_key']) ? (string)$settings['turnstile_site_key'] : '';
        $settings['turnstile_secret_key'] = isset($settings['turnstile_secret_key']) ? (string)$settings['turnstile_secret_key'] : '';

        $settings['pow_difficulty'] = isset($settings['pow_difficulty']) ? (int)$settings['pow_difficulty'] : self::DEFAULT_DIFFICULTY;
        $settings['pow_ttl'] = isset($settings['pow_ttl']) ? (int)$settings['pow_ttl'] : self::DEFAULT_TTL;
        $settings['pow_allowed_actions'] = isset($settings['pow_allowed_actions']) ? $settings['pow_allowed_actions'] : self::DEFAULT_ALLOWED_ACTIONS;

        if ($settings['pow_difficulty'] < self::MIN_DIFFICULTY || $settings['pow_difficulty'] > self::MAX_DIFFICULTY) {
            $settings['pow_difficulty'] = self::DEFAULT_DIFFICULTY;
        }

        if ($settings['pow_ttl'] < self::MIN_TTL || $settings['pow_ttl'] > self::MAX_TTL) {
            $settings['pow_ttl'] = self::DEFAULT_TTL;
        }

        if (is_string($settings['pow_allowed_actions'])) {
            $settings['pow_allowed_actions'] = self::parseAllowedActionsInput($settings['pow_allowed_actions']);
        } elseif (!is_array($settings['pow_allowed_actions'])) {
            $settings['pow_allowed_actions'] = self::DEFAULT_ALLOWED_ACTIONS;
        }

        $settings['pow_allowed_actions'] = self::normalizeAllowedActions($settings['pow_allowed_actions']);

        return $settings;
    }

    public static function isPowEnabled(): bool
    {
        $settings = self::getRecaptchaSettings();
        return ((int)$settings['enabled'] === 1 && $settings['provider'] === 'pow');
    }

    public static function isApcuAvailable(): bool
    {
        return function_exists('apcu_fetch') && function_exists('apcu_store');
    }

    public static function getAllowedActions(): array
    {
        $settings = self::getRecaptchaSettings();
        return self::normalizeAllowedActions($settings['pow_allowed_actions']);
    }

    public static function isActionAllowed(string $action): bool
    {
        return in_array($action, self::getAllowedActions(), true);
    }

    public static function parseAllowedActionsInput(string $input): array
    {
        if ($input === '') {
            return self::DEFAULT_ALLOWED_ACTIONS;
        }

        $parts = preg_split('/[\s,]+/', $input, -1, PREG_SPLIT_NO_EMPTY);
        if (!is_array($parts)) {
            return self::DEFAULT_ALLOWED_ACTIONS;
        }

        return self::normalizeAllowedActions($parts);
    }

    public static function createChallenge(string $action): array
    {
        $settings = self::getRecaptchaSettings();

        $now = time();
        $ttl = (int)$settings['pow_ttl'];
        $difficulty = (int)$settings['pow_difficulty'];

        $payload = array(
            'a' => $action,
            't' => $now,
            'e' => $now + $ttl,
            'n' => bin2hex(random_bytes(16)),
            'd' => $difficulty,
            's' => self::getSessionBindingToken(),
        );

        $encodedPayload = self::base64UrlEncode(json_encode($payload));
        $signature = hash_hmac('sha256', $encodedPayload, self::getSecret());

        return array(
            'challenge' => $encodedPayload . '.' . $signature,
            'difficulty' => $difficulty,
            'expires_in' => $ttl,
        );
    }

    public static function verifySubmittedProof(array $postData, string $action, ?string &$reason = null): bool
    {
        $challenge = isset($postData['pow_challenge']) ? trim((string)$postData['pow_challenge']) : '';
        $nonce = isset($postData['pow_nonce']) ? trim((string)$postData['pow_nonce']) : '';

        return self::verifyProof($challenge, $nonce, $action, $reason);
    }

    public static function verifyProof(string $challenge, string $nonce, string $action, ?string &$reason = null): bool
    {
        $reason = 'invalid_proof';

        if ($challenge === '' || $nonce === '') {
            $reason = 'missing_input';
            return false;
        }

        if (!preg_match('/^[a-f0-9]{1,64}$/', $nonce)) {
            $reason = 'nonce_invalid';
            return false;
        }

        if (strlen($challenge) > self::MAX_CHALLENGE_LENGTH) {
            $reason = 'challenge_too_large';
            return false;
        }

        $parts = explode('.', $challenge, 2);
        if (count($parts) !== 2) {
            $reason = 'challenge_invalid';
            return false;
        }

        $encodedPayload = $parts[0];
        $providedSignature = $parts[1];

        if (!preg_match('/^[a-f0-9]{64}$/', $providedSignature)) {
            $reason = 'signature_invalid';
            return false;
        }

        $calculatedSignature = hash_hmac('sha256', $encodedPayload, self::getSecret());

        if (!hash_equals($calculatedSignature, $providedSignature)) {
            $reason = 'signature_mismatch';
            self::logSecurityEvent('signature_mismatch', ['action' => $action]);
            return false;
        }

        $payloadRaw = self::base64UrlDecode($encodedPayload);
        $payload = json_decode($payloadRaw, true);

        if (!is_array($payload)) {
            $reason = 'payload_invalid';
            return false;
        }

        $expiry = isset($payload['e']) ? (int)$payload['e'] : 0;
        $issuedAt = isset($payload['t']) ? (int)$payload['t'] : 0;
        $difficulty = isset($payload['d']) ? (int)$payload['d'] : 0;

        if (!isset($payload['a']) || !is_string($payload['a']) || $payload['a'] !== $action) {
            $reason = 'action_mismatch';
            self::logSecurityEvent('action_mismatch', ['action' => $action]);
            return false;
        }

        if (!isset($payload['s']) || !is_string($payload['s']) || !hash_equals(self::getSessionBindingToken(), $payload['s'])) {
            $reason = 'session_mismatch';
            self::logSecurityEvent('session_mismatch', ['action' => $action]);
            return false;
        }

        if ($difficulty < self::MIN_DIFFICULTY || $difficulty > self::MAX_DIFFICULTY) {
            $reason = 'difficulty_invalid';
            return false;
        }

        $now = time();

        if ($issuedAt > $now + 30) {
            $reason = 'issued_at_invalid';
            return false;
        }

        if ($expiry < $now) {
            $reason = 'challenge_expired';
            self::logSecurityEvent('challenge_expired', ['action' => $action]);
            return false;
        }

        if (($expiry - $issuedAt) > self::MAX_TTL + 30) {
            $reason = 'ttl_invalid';
            return false;
        }

        $proofHash = hash('sha256', $challenge . '|' . $nonce);

        self::cleanupReplayCache($now);

        if (!isset($_SESSION['lhc_powcaptcha_used']) || !is_array($_SESSION['lhc_powcaptcha_used'])) {
            $_SESSION['lhc_powcaptcha_used'] = array();
        }

        if (isset($_SESSION['lhc_powcaptcha_used'][$proofHash])) {
            $reason = 'replay_detected';
            self::logSecurityEvent('replay_detected', ['action' => $action, 'store' => 'session']);
            return false;
        }

        // APCu-backed cross-session replay detection (defense-in-depth when APCu is available).
        // This supplements the session check and catches replays across nodes that share APCu
        // (e.g. single-server setups) even if session storage is not shared.
        $apcuReplayKey = null;
        if (function_exists('apcu_fetch') && function_exists('apcu_store')) {
            $apcuReplayKey = 'lhc_powcaptcha_u_' . $proofHash;
            apcu_fetch($apcuReplayKey, $apcuProofExists);
            if ($apcuProofExists) {
                $reason = 'replay_detected';
                self::logSecurityEvent('replay_detected', ['action' => $action, 'store' => 'apcu']);
                return false;
            }
        }

        if (!self::hasLeadingZeroBits($proofHash, $difficulty)) {
            $reason = 'insufficient_work';
            return false;
        }

        $_SESSION['lhc_powcaptcha_used'][$proofHash] = $expiry;

        self::cleanupReplayCache($now);

        if ($apcuReplayKey !== null) {
            apcu_store($apcuReplayKey, 1, max(1, $expiry - $now));
        }

        $reason = 'validated';

        return true;
    }

    public static function isChallengeRequestAllowed(string $action, ?int &$retryAfter = null): bool
    {
        $retryAfter = null;
        $now = time();

        if (!isset($_SESSION['lhc_powcaptcha_challenge_rl']) || !is_array($_SESSION['lhc_powcaptcha_challenge_rl'])) {
            $_SESSION['lhc_powcaptcha_challenge_rl'] = array();
        }

        $sessionState = isset($_SESSION['lhc_powcaptcha_challenge_rl'][$action]) && is_array($_SESSION['lhc_powcaptcha_challenge_rl'][$action])
            ? $_SESSION['lhc_powcaptcha_challenge_rl'][$action]
            : array('w' => $now, 'c' => 0);

        $sessionWindowStart = isset($sessionState['w']) ? (int)$sessionState['w'] : $now;
        $sessionCount = isset($sessionState['c']) ? (int)$sessionState['c'] : 0;

        if (($now - $sessionWindowStart) >= self::CHALLENGE_RL_WINDOW_SECONDS) {
            $sessionWindowStart = $now;
            $sessionCount = 0;
        }

        if ($sessionCount >= self::CHALLENGE_RL_PER_SESSION) {
            $retryAfter = max(1, self::CHALLENGE_RL_WINDOW_SECONDS - ($now - $sessionWindowStart));
            return false;
        }

        $clientIp = self::getClientIp();
        $apcuAvailable = self::isApcuAvailable();

        if (!$apcuAvailable && !self::$apcuMissingLogged) {
            self::$apcuMissingLogged = true;
            error_log('lhc_powcaptcha apcu_unavailable: per-IP rate limiting is inactive; only per-session limits apply');
        }

        if ($apcuAvailable && $clientIp !== '') {
            $ipKey = 'lhc_powcaptcha_rl_' . hash('sha256', $action . '|' . $clientIp);
            $ipData = apcu_fetch($ipKey, $ipDataExists);

            if (!$ipDataExists || !is_array($ipData)) {
                $ipData = array('w' => $now, 'c' => 0);
            }

            $ipWindowStart = isset($ipData['w']) ? (int)$ipData['w'] : $now;
            $ipCount = isset($ipData['c']) ? (int)$ipData['c'] : 0;

            if (($now - $ipWindowStart) >= self::CHALLENGE_RL_WINDOW_SECONDS) {
                $ipWindowStart = $now;
                $ipCount = 0;
            }

            if ($ipCount >= self::CHALLENGE_RL_PER_IP) {
                $retryAfter = max(1, self::CHALLENGE_RL_WINDOW_SECONDS - ($now - $ipWindowStart));
                return false;
            }

            $ipData = array('w' => $ipWindowStart, 'c' => $ipCount + 1);
            apcu_store($ipKey, $ipData, self::CHALLENGE_RL_WINDOW_SECONDS + 2);
        }

        $_SESSION['lhc_powcaptcha_challenge_rl'][$action] = array(
            'w' => $sessionWindowStart,
            'c' => $sessionCount + 1,
        );

        return true;
    }

    private static function cleanupReplayCache(int $now): void
    {
        if (!isset($_SESSION['lhc_powcaptcha_used']) || !is_array($_SESSION['lhc_powcaptcha_used'])) {
            return;
        }

        foreach ($_SESSION['lhc_powcaptcha_used'] as $proof => $expiresAt) {
            if ((int)$expiresAt < $now) {
                unset($_SESSION['lhc_powcaptcha_used'][$proof]);
            }
        }

        if (count($_SESSION['lhc_powcaptcha_used']) > self::MAX_SESSION_REPLAY_ENTRIES) {
            asort($_SESSION['lhc_powcaptcha_used'], SORT_NUMERIC);
            while (count($_SESSION['lhc_powcaptcha_used']) > self::MAX_SESSION_REPLAY_ENTRIES) {
                array_shift($_SESSION['lhc_powcaptcha_used']);
            }
        }
    }

    private static function hasLeadingZeroBits(string $hexHash, int $requiredBits): bool
    {
        $fullZeroNibbles = intdiv($requiredBits, 4);
        $remainingBits = $requiredBits % 4;

        if ($fullZeroNibbles > 0) {
            if (substr($hexHash, 0, $fullZeroNibbles) !== str_repeat('0', $fullZeroNibbles)) {
                return false;
            }
        }

        if ($remainingBits === 0) {
            return true;
        }

        $nextNibble = hexdec(substr($hexHash, $fullZeroNibbles, 1));
        $threshold = 1 << (4 - $remainingBits);

        return $nextNibble < $threshold;
    }

    private static function getSecret(): string
    {
        return hash('sha256', (string)erConfigClassLhConfig::getInstance()->getSetting('site', 'secrethash'));
    }

    private static function getSessionBindingToken(): string
    {
        $sessionId = session_id();
        if (is_string($sessionId) && $sessionId !== '') {
            return hash_hmac('sha256', 'sid|' . $sessionId, self::getSecret());
        }

        $clientBindingId = self::getClientBindingId();
        if ($clientBindingId !== '') {
            return hash_hmac('sha256', 'cid|' . $clientBindingId, self::getSecret());
        }

        $clientIp = self::getClientIp();

        return hash_hmac('sha256', 'ctx|' . $clientIp, self::getSecret());
    }

    private static function getClientBindingId(): string
    {
        $cookieValue = isset($_COOKIE[self::BINDING_COOKIE_NAME]) ? (string)$_COOKIE[self::BINDING_COOKIE_NAME] : '';
        if ($cookieValue !== '' && preg_match('/^[a-f0-9]{64}$/', $cookieValue)) {
            return $cookieValue;
        }

        if (headers_sent()) {
            return '';
        }

        try {
            $cookieValue = bin2hex(random_bytes(32));
        } catch (\Throwable $e) {
            return '';
        }

        setcookie(self::BINDING_COOKIE_NAME, $cookieValue, array(
            'expires' => time() + self::BINDING_COOKIE_TTL,
            'path' => '/',
            'secure' => self::isHttps(),
            'httponly' => true,
            'samesite' => 'Lax',
        ));
        $_COOKIE[self::BINDING_COOKIE_NAME] = $cookieValue;

        return $cookieValue;
    }

    private static function isHttps(): bool
    {
        if (isset($_SERVER['HTTPS'])) {
            $https = strtolower((string)$_SERVER['HTTPS']);
            if ($https === 'on' || $https === '1') {
                return true;
            }
        }

        return (isset($_SERVER['SERVER_PORT']) && (string)$_SERVER['SERVER_PORT'] === '443');
    }

    private static function getClientIp(): string
    {
        if (class_exists('erLhcoreClassIPDetect')) {
            $ip = (string)erLhcoreClassIPDetect::getIP();
            if ($ip !== '') {
                return $ip;
            }
        }

        return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function normalizeAllowedActions(array $actions): array
    {
        $normalized = array();

        foreach ($actions as $action) {
            $action = trim((string)$action);
            if ($action !== '' && preg_match('/^[a-z0-9_]{1,64}$/', $action)) {
                $normalized[$action] = true;
            }
        }

        $actions = array_keys($normalized);
        if (empty($actions)) {
            return self::DEFAULT_ALLOWED_ACTIONS;
        }

        return array_values($actions);
    }

    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder > 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return (string)base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Log a security event to the PHP error log.
     * IP is one-way hashed so real addresses are never written to logs.
     *
     * @param string $event   Short machine-readable event name (e.g. 'replay_detected').
     * @param array  $context Optional key=>value pairs to append (values must be safe to log).
     */
    private static function logSecurityEvent(string $event, array $context = []): void
    {
        $ip = self::getClientIp();
        $parts = ['lhc_powcaptcha', $event];

        if ($ip !== '') {
            $parts[] = 'ip_hash:' . substr(hash('sha256', $ip), 0, 12);
        }

        foreach ($context as $k => $v) {
            $parts[] = $k . ':' . $v;
        }

        error_log(implode(' ', $parts));
    }
}
