<?php

#[\AllowDynamicProperties]
class erLhcoreClassPowCaptcha
{
    public const VERSION = '1.4.3';

    private const DEFAULT_DIFFICULTY = 18;
    private const DEFAULT_TTL = 180;
    private const MIN_DIFFICULTY = 12;
    private const MAX_DIFFICULTY = 26;         // protocol limit accepted when verifying
    private const MAX_SETTING_DIFFICULTY = 22; // highest value an admin can set / that is ever issued
    private const DEFAULT_HONEYPOT = 1;
    private const HONEYPOT_FIELD = 'contact_website';
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

    // Adaptive difficulty (short-term captcha failures): every recent captcha failure adds +1 bit.
    private const DEFAULT_ADAPTIVE = 1;
    private const DEFAULT_ADAPTIVE_MAX_BONUS = 4;
    private const MAX_ADAPTIVE_MAX_BONUS = 8;
    private const FAIL_WINDOW_SECONDS = 900;
    private const FAIL_COUNT_CAP = 1000;
    private const NO_PENALTY_REASONS = array('validated', 'difficulty_too_low', 'challenge_expired', 'new_ip_login_alert_sent');

    // 24-hour IP penalty for failed credentials (v1.4.3)
    private const DEFAULT_CRED_PENALTY_ENABLED = 1;
    private const DEFAULT_CRED_PENALTY_HOURS = 24;
    private const IP_PENALTIES_IDENTIFIER = 'powcaptcha_ip_penalties';
    private const MAX_STORED_LIMITED_IPS = 200;

    // New IP email alert (v1.4.3)
    private const DEFAULT_NEW_IP_ALERT = 1;
    private const KNOWN_IPS_IDENTIFIER = 'powcaptcha_known_ips';
    private const MAX_KNOWN_IPS_PER_USER = 25;

    // Attempt log (stored in lh_chat_config, hidden row).
    private const LOG_IDENTIFIER = 'powcaptcha_attempt_log';
    private const LOG_MAX_ENTRIES = 50;
    private const LOG_MAX_BYTES = 60000;
    private const LOG_WRITE_RL_PER_MINUTE = 30;

    private static bool $apcuMissingLogged = false;

    // In-request state for detecting failed login credentials
    private static bool $loginAttemptStarted = false;
    private static bool $loginAttemptSucceeded = false;
    private static ?string $pendingClientIp = null;
    private static ?string $pendingUsername = null;
    private static bool $shutdownHandlerRegistered = false;

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

        $settings['pow_adaptive'] = isset($settings['pow_adaptive']) ? (((int)$settings['pow_adaptive'] === 1) ? 1 : 0) : self::DEFAULT_ADAPTIVE;
        $settings['pow_adaptive_max_bonus'] = isset($settings['pow_adaptive_max_bonus']) ? (int)$settings['pow_adaptive_max_bonus'] : self::DEFAULT_ADAPTIVE_MAX_BONUS;
        if ($settings['pow_adaptive_max_bonus'] < 0 || $settings['pow_adaptive_max_bonus'] > self::MAX_ADAPTIVE_MAX_BONUS) {
            $settings['pow_adaptive_max_bonus'] = self::DEFAULT_ADAPTIVE_MAX_BONUS;
        }

        $settings['pow_honeypot'] = isset($settings['pow_honeypot']) ? (((int)$settings['pow_honeypot'] === 1) ? 1 : 0) : self::DEFAULT_HONEYPOT;

        // v1.4.3: 24h credential penalty settings
        $settings['pow_cred_penalty'] = isset($settings['pow_cred_penalty']) ? (((int)$settings['pow_cred_penalty'] === 1) ? 1 : 0) : self::DEFAULT_CRED_PENALTY_ENABLED;
        $settings['pow_cred_penalty_hours'] = isset($settings['pow_cred_penalty_hours']) ? max(1, min(168, (int)$settings['pow_cred_penalty_hours'])) : self::DEFAULT_CRED_PENALTY_HOURS;

        // v1.4.3: New IP email alert settings
        $settings['pow_new_ip_alert'] = isset($settings['pow_new_ip_alert']) ? (((int)$settings['pow_new_ip_alert'] === 1) ? 1 : 0) : self::DEFAULT_NEW_IP_ALERT;
        $settings['pow_new_ip_email'] = isset($settings['pow_new_ip_email']) ? trim((string)$settings['pow_new_ip_email']) : '';

        // Values above MAX_SETTING_DIFFICULTY cannot be solved by a browser within the TTL.
        if ($settings['pow_difficulty'] < self::MIN_DIFFICULTY || $settings['pow_difficulty'] > self::MAX_SETTING_DIFFICULTY) {
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
        if (!function_exists('apcu_fetch') || !function_exists('apcu_store')) {
            return false;
        }

        if (function_exists('apcu_enabled')) {
            return (bool)apcu_enabled();
        }

        return filter_var((string)ini_get('apc.enabled'), FILTER_VALIDATE_BOOLEAN);
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
        $difficulty = self::getEffectiveDifficulty($settings);

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

    public static function getHoneypotFieldName(): string
    {
        return self::HONEYPOT_FIELD;
    }

    public static function verifySubmittedProof(array $postData, string $action, ?string &$reason = null): bool
    {
        $challenge = isset($postData['pow_challenge']) ? trim((string)$postData['pow_challenge']) : '';
        $nonce = isset($postData['pow_nonce']) ? trim((string)$postData['pow_nonce']) : '';

        // Difficulty required right now (before this attempt can change it); stored in the log.
        $requiredNow = self::getEffectiveDifficulty();

        // Honeypot check: invisible trap for automated form fillers
        if ((int)self::getRecaptchaSettings()['pow_honeypot'] === 1 && isset($postData[self::HONEYPOT_FIELD])
            && (!is_scalar($postData[self::HONEYPOT_FIELD]) || trim((string)$postData[self::HONEYPOT_FIELD]) !== '')) {
            $reason = 'honeypot_triggered';
            self::logSecurityEvent('honeypot_triggered', ['action' => $action]);
            self::recordAttempt($action, false, $reason, $requiredNow);
            return false;
        }

        $valid = self::verifyProof($challenge, $nonce, $action, $reason);

        self::recordAttempt($action, $valid, (string)$reason, $requiredNow);

        return $valid;
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

        // Adaptive difficulty & 24h penalty enforcement:
        // A challenge issued before recent failures cannot be used after failures were recorded.
        $settingsNow = self::getRecaptchaSettings();
        if (((int)$settingsNow['pow_adaptive'] === 1 || (int)$settingsNow['pow_cred_penalty'] === 1)
            && $difficulty < self::getEffectiveDifficulty($settingsNow)) {
            $reason = 'difficulty_too_low';
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

        $apcuReplayKey = null;
        if (self::isApcuAvailable() && function_exists('apcu_add')) {
            $apcuReplayKey = 'lhc_powcaptcha_u_' . $proofHash;
            if (apcu_exists($apcuReplayKey)) {
                $reason = 'replay_detected';
                self::logSecurityEvent('replay_detected', ['action' => $action, 'store' => 'apcu']);
                return false;
            }
        }

        if (!self::hasLeadingZeroBits($proofHash, $difficulty)) {
            $reason = 'insufficient_work';
            return false;
        }

        if ($apcuReplayKey !== null && !apcu_add($apcuReplayKey, 1, max(1, $expiry - $now) + 5) && apcu_exists($apcuReplayKey)) {
            $reason = 'replay_detected';
            self::logSecurityEvent('replay_detected', ['action' => $action, 'store' => 'apcu']);
            return false;
        }

        $_SESSION['lhc_powcaptcha_used'][$proofHash] = $expiry;

        self::cleanupReplayCache($now);

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

    // ------------------------------------------------------------------
    // Effective Difficulty Calculation (combines base, 15m fail, and 24h IP penalty)
    // ------------------------------------------------------------------

    /**
     * Calculates the difficulty required right now:
     * - Base difficulty (pow_difficulty, default 18)
     * - Plus 15-minute captcha failure bonus (pow_adaptive)
     * - Plus 24-hour credential failure bonus for this IP (pow_cred_penalty)
     * All capped at MAX_SETTING_DIFFICULTY (22 bits).
     */
    public static function getEffectiveDifficulty(?array $settings = null, ?string $clientIp = null): int
    {
        if ($settings === null) {
            $settings = self::getRecaptchaSettings();
        }

        $base = (int)$settings['pow_difficulty'];
        $bonus = 0;

        if ((int)$settings['pow_adaptive'] === 1) {
            $shortTermFailures = self::getRecentFailureCount($clientIp);
            $bonus += min((int)$settings['pow_adaptive_max_bonus'], $shortTermFailures);
        }

        if ((int)$settings['pow_cred_penalty'] === 1) {
            $credBonus = self::getIpPenaltyBonus($clientIp);
            $bonus += $credBonus;
        }

        return min(self::MAX_SETTING_DIFFICULTY, $base + max(0, $bonus));
    }

    public static function getRecentFailureCount(?string $clientIp = null): int
    {
        $now = time();
        $count = 0;

        if (isset($_SESSION['lhc_powcaptcha_fail']) && is_array($_SESSION['lhc_powcaptcha_fail'])) {
            $state = $_SESSION['lhc_powcaptcha_fail'];
            if (isset($state['l'], $state['c']) && ($now - (int)$state['l']) <= self::FAIL_WINDOW_SECONDS) {
                $count = max($count, (int)$state['c']);
            }
        }

        $ipKey = self::getFailureIpKey($clientIp);
        if ($ipKey !== null) {
            $data = apcu_fetch($ipKey, $exists);
            if ($exists && is_array($data) && isset($data['l'], $data['c']) && ($now - (int)$data['l']) <= self::FAIL_WINDOW_SECONDS) {
                $count = max($count, (int)$data['c']);
            }
        }

        return min($count, self::FAIL_COUNT_CAP);
    }

    private static function registerFailure(): void
    {
        $now = time();

        $count = 0;
        if (isset($_SESSION['lhc_powcaptcha_fail']) && is_array($_SESSION['lhc_powcaptcha_fail'])) {
            $state = $_SESSION['lhc_powcaptcha_fail'];
            if (isset($state['l'], $state['c']) && ($now - (int)$state['l']) <= self::FAIL_WINDOW_SECONDS) {
                $count = (int)$state['c'];
            }
        }
        $_SESSION['lhc_powcaptcha_fail'] = array('c' => min($count + 1, self::FAIL_COUNT_CAP), 'l' => $now);

        $ipKey = self::getFailureIpKey();
        if ($ipKey !== null) {
            $data = apcu_fetch($ipKey, $exists);
            $ipCount = 0;
            if ($exists && is_array($data) && isset($data['l'], $data['c']) && ($now - (int)$data['l']) <= self::FAIL_WINDOW_SECONDS) {
                $ipCount = (int)$data['c'];
            }
            apcu_store($ipKey, array('c' => min($ipCount + 1, self::FAIL_COUNT_CAP), 'l' => $now), self::FAIL_WINDOW_SECONDS + 5);
        }
    }

    private static function getFailureIpKey(?string $ip = null): ?string
    {
        if (!self::isApcuAvailable()) {
            return null;
        }

        $ip = ($ip !== null && $ip !== '') ? $ip : self::getClientIp();

        return ($ip !== '') ? 'lhc_powcaptcha_fail_' . hash('sha256', $ip) : null;
    }

    // ------------------------------------------------------------------
    // v1.4.3 Feature: 24h IP Penalty for Failed Login Credentials
    // ------------------------------------------------------------------

    /**
     * Returns the extra difficulty bits incurred by this IP due to failed login credentials
     * within the configured window (default 24 hours).
     */
    public static function getIpPenaltyBonus(?string $clientIp = null): int
    {
        $ip = ($clientIp !== null && $clientIp !== '') ? $clientIp : self::getClientIp();
        if ($ip === '') {
            return 0;
        }

        $penaltyData = self::getIpPenaltyData($ip);
        if ($penaltyData === null || !isset($penaltyData['expires_at']) || (int)$penaltyData['expires_at'] < time()) {
            return 0;
        }

        $count = isset($penaltyData['count']) ? (int)$penaltyData['count'] : 0;
        // Each failed login attempt adds +1 difficulty bit, capped so total difficulty won't exceed MAX_SETTING_DIFFICULTY
        return max(0, min(6, $count));
    }

    public static function getIpPenaltyData(string $ip): ?array
    {
        if ($ip === '') {
            return null;
        }

        // Try APCu first for speed
        if (self::isApcuAvailable()) {
            $apcuKey = 'lhc_powcaptcha_pen_' . hash('sha256', $ip);
            $cached = apcu_fetch($apcuKey, $exists);
            if ($exists && is_array($cached)) {
                return $cached;
            }
        }

        // Check persistent store
        $all = self::readAllIpPenalties();
        if (isset($all[$ip]) && is_array($all[$ip])) {
            $entry = $all[$ip];
            if (isset($entry['expires_at']) && (int)$entry['expires_at'] > time()) {
                if (self::isApcuAvailable()) {
                    $ttl = max(1, (int)$entry['expires_at'] - time());
                    apcu_store('lhc_powcaptcha_pen_' . hash('sha256', $ip), $entry, $ttl);
                }
                return $entry;
            }
        }

        return null;
    }

    /**
     * Registers a failed credential login for the given IP address,
     * extending or increasing the penalty for at least 24 hours.
     */
    public static function recordFailedCredentialAttempt(string $ip, string $username = ''): void
    {
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return;
        }

        $settings = self::getRecaptchaSettings();
        $hours = (int)$settings['pow_cred_penalty_hours'];
        $penaltyDuration = $hours * 3600;
        $now = time();
        $expiresAt = $now + $penaltyDuration;

        $all = self::readAllIpPenalties();

        $existing = isset($all[$ip]) && is_array($all[$ip]) ? $all[$ip] : null;
        $count = ($existing && isset($existing['count'])) ? (int)$existing['count'] + 1 : 1;
        $firstFailedAt = ($existing && isset($existing['first_at'])) ? (int)$existing['first_at'] : $now;

        $entry = array(
            'ip' => $ip,
            'count' => $count,
            'bonus' => min(6, $count),
            'first_at' => $firstFailedAt,
            'last_at' => $now,
            'expires_at' => $expiresAt,
            'user' => substr($username, 0, 50),
        );

        $all[$ip] = $entry;

        // Cleanup expired entries and cap total list size
        foreach ($all as $k => $v) {
            if (!isset($v['expires_at']) || (int)$v['expires_at'] < $now) {
                unset($all[$k]);
            }
        }

        if (count($all) > self::MAX_STORED_LIMITED_IPS) {
            uasort($all, fn($a, $b) => ($b['last_at'] ?? 0) <=> ($a['last_at'] ?? 0));
            $all = array_slice($all, 0, self::MAX_STORED_LIMITED_IPS, true);
        }

        self::writeAllIpPenalties($all);

        if (self::isApcuAvailable()) {
            apcu_store('lhc_powcaptcha_pen_' . hash('sha256', $ip), $entry, $penaltyDuration);
        }

        // Record in security log and attempt log
        self::logSecurityEvent('login_failed_credentials', [
            'user' => substr($username, 0, 32),
            'penalty_count' => $count,
            'expires_in_hours' => $hours,
        ]);

        $difficultyNow = self::getEffectiveDifficulty($settings, $ip);
        self::recordAttempt('login_action', false, 'bad_credentials', $difficultyNow, $username);
    }

    public static function removeIpPenalty(string $ip): bool
    {
        $all = self::readAllIpPenalties();
        if (isset($all[$ip])) {
            unset($all[$ip]);
            self::writeAllIpPenalties($all);

            if (self::isApcuAvailable()) {
                apcu_delete('lhc_powcaptcha_pen_' . hash('sha256', $ip));
            }
            return true;
        }
        return false;
    }

    public static function clearAllIpPenalties(): void
    {
        self::writeAllIpPenalties(array());

        $stmt = \ezcDbInstance::get()->prepare('DELETE FROM `lh_chat_config` WHERE `identifier` = :id');
        $stmt->bindValue(':id', self::IP_PENALTIES_IDENTIFIER);
        $stmt->execute();
    }

    /**
     * @return array[] List of limited IPs with active penalties, newest first.
     */
    public static function getLimitedIpsList(): array
    {
        $now = time();
        $all = self::readAllIpPenalties();
        $active = array();

        foreach ($all as $ip => $data) {
            if (isset($data['expires_at']) && (int)$data['expires_at'] > $now) {
                $active[] = $data;
            }
        }

        uasort($active, fn($a, $b) => ($b['last_at'] ?? 0) <=> ($a['last_at'] ?? 0));
        return array_values($active);
    }

    private static function readAllIpPenalties(): array
    {
        try {
            $stmt = \ezcDbInstance::get()->prepare('SELECT `value` FROM `lh_chat_config` WHERE `identifier` = :id');
            $stmt->bindValue(':id', self::IP_PENALTIES_IDENTIFIER);
            $stmt->execute();
            $raw = $stmt->fetchColumn();

            if (!is_string($raw) || $raw === '') {
                return array();
            }

            $decoded = json_decode($raw, true);
            return is_array($decoded) ? $decoded : array();
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha read_penalties_failed: ' . $e->getMessage());
            return array();
        }
    }

    private static function writeAllIpPenalties(array $penalties): void
    {
        try {
            $json = json_encode($penalties);
            if ($json === false) {
                return;
            }

            $stmt = \ezcDbInstance::get()->prepare(
                "INSERT INTO `lh_chat_config` (`identifier`, `value`, `type`, `explain`, `hidden`) VALUES (:id, :v, 0, '', 1) " .
                "ON DUPLICATE KEY UPDATE `value` = :v2"
            );
            $stmt->bindValue(':id', self::IP_PENALTIES_IDENTIFIER);
            $stmt->bindValue(':v', $json);
            $stmt->bindValue(':v2', $json);
            $stmt->execute();
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha write_penalties_failed: ' . $e->getMessage());
        }
    }

    // ------------------------------------------------------------------
    // v1.4.3 Feature: Login Lifecycle Hooks & Detection
    // ------------------------------------------------------------------

    /**
     * Hook triggered by LHC event 'user.login_before_authenticate'.
     * Called right before $currentUser->authenticate(...) runs in modules/lhuser/login.php.
     */
    public static function onLoginBeforeAuthenticate($params): void
    {
        self::$loginAttemptStarted = true;
        self::$loginAttemptSucceeded = false;
        self::$pendingClientIp = self::getClientIp();
        self::$pendingUsername = isset($_POST['Username']) ? trim((string)$_POST['Username']) : '';

        // Register shutdown function to verify whether authentication succeeded or failed
        if (!self::$shutdownHandlerRegistered) {
            self::$shutdownHandlerRegistered = true;
            register_shutdown_function(array(__CLASS__, 'onShutdownCheckLoginFailure'));
        }
    }

    /**
     * Hook triggered by LHC event 'user.login_after_success_authenticate'.
     * Called when the operator credentials were valid and login succeeded.
     */
    public static function onLoginAfterSuccessAuthenticate($params): void
    {
        self::$loginAttemptSucceeded = true;

        $currentUser = isset($params['current_user']) ? $params['current_user'] : \erLhcoreClassUser::instance();
        $ip = self::$pendingClientIp ?: self::getClientIp();

        // Check and send new IP email notification if configured
        self::handleNewIpCheck($currentUser, $ip);
    }

    /**
     * Shutdown handler: checks if a login attempt started but failed to authenticate.
     */
    public static function onShutdownCheckLoginFailure(): void
    {
        if (self::$loginAttemptStarted && !self::$loginAttemptSucceeded) {
            // Check if user actually logged in through any other path
            if (class_exists('erLhcoreClassUser') && \erLhcoreClassUser::instance()->isLogged()) {
                return;
            }

            $ip = self::$pendingClientIp ?: self::getClientIp();
            $username = self::$pendingUsername ?: '';

            if ($ip !== '') {
                self::recordFailedCredentialAttempt($ip, $username);
            }
        }
    }

    // ------------------------------------------------------------------
    // v1.4.3 Feature: New IP Login Detection and Email Alert
    // ------------------------------------------------------------------

    public static function handleNewIpCheck($currentUser, string $ip): void
    {
        try {
            $settings = self::getRecaptchaSettings();
            if ((int)$settings['pow_new_ip_alert'] !== 1 || $ip === '') {
                return;
            }

            $userId = null;
            $userEmail = '';
            $userName = '';

            if (is_object($currentUser) && method_exists($currentUser, 'getUserData')) {
                $userData = $currentUser->getUserData();
                if (is_object($userData)) {
                    $userId = isset($userData->id) ? (int)$userData->id : null;
                    $userEmail = isset($userData->email) ? (string)$userData->email : '';
                    $userName = isset($userData->username) ? (string)$userData->username : '';
                }
            }

            if ($userId === null) {
                return;
            }

            $known = self::readKnownIps();
            $userKey = 'u_' . $userId;
            $userIps = isset($known[$userKey]) && is_array($known[$userKey]) ? $known[$userKey] : array();

            $isNewIp = !isset($userIps[$ip]);

            // Update known IPs for this user
            $userIps[$ip] = time();
            if (count($userIps) > self::MAX_KNOWN_IPS_PER_USER) {
                asort($userIps, SORT_NUMERIC);
                while (count($userIps) > self::MAX_KNOWN_IPS_PER_USER) {
                    array_shift($userIps);
                }
            }
            $known[$userKey] = $userIps;
            self::writeKnownIps($known);

            if ($isNewIp) {
                self::sendNewIpNotificationEmail($userEmail, $userName, $ip);

                // Log the new IP event
                self::recordAttempt('login_action', true, 'new_ip_login_alert_sent', self::getEffectiveDifficulty($settings, $ip), $userName);
                self::logSecurityEvent('new_ip_login', [
                    'user' => $userName,
                    'user_id' => $userId,
                ]);
            }
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha handle_new_ip_failed: ' . $e->getMessage());
        }
    }

    public static function sendNewIpNotificationEmail(string $userEmail, string $userName, string $ip): bool
    {
        $settings = self::getRecaptchaSettings();
        $targetEmail = !empty($settings['pow_new_ip_email']) ? trim((string)$settings['pow_new_ip_email']) : $userEmail;

        if ($targetEmail === '' || filter_var($targetEmail, FILTER_VALIDATE_EMAIL) === false) {
            return false;
        }

        $siteTitle = 'Live Helper Chat';
        if (class_exists('erConfigClassLhConfig')) {
            $siteTitle = (string)\erConfigClassLhConfig::getInstance()->getSetting('site', 'title') ?: $siteTitle;
        }

        $dateStr = date('Y-m-d H:i:s T');
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : 'Unknown';

        $subject = sprintf('[%s] Security Alert: Login from new IP address (%s)', $siteTitle, $userName);

        $body = "Hello,\n\n" .
            "A successful login to your Live Helper Chat account has been detected from a new IP address.\n\n" .
            "Account: " . $userName . "\n" .
            "IP Address: " . $ip . "\n" .
            "Date & Time: " . $dateStr . "\n" .
            "User Agent: " . $userAgent . "\n\n" .
            "If this was you, you can safely ignore this notification.\n" .
            "If you did NOT perform this login, please immediately change your password or contact your system administrator.\n\n" .
            "--\n" . $siteTitle . " Security System";

        return self::sendMail($targetEmail, $subject, $body);
    }

    public static function sendMail(string $toEmail, string $subject, string $body): bool
    {
        try {
            if (class_exists('PHPMailer\\PHPMailer\\PHPMailer')) {
                $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
                if (class_exists('erLhcoreClassChatMail') && method_exists('erLhcoreClassChatMail', 'setupSMTP')) {
                    \erLhcoreClassChatMail::setupSMTP($mail);
                }
                $mail->CharSet = 'UTF-8';
                $mail->Subject = $subject;
                $mail->Body = $body;
                $mail->AltBody = strip_tags($body);
                $mail->addAddress($toEmail);
                return (bool)$mail->send();
            }

            if (class_exists('PHPMailer')) {
                $mail = new \PHPMailer(true);
                if (class_exists('erLhcoreClassChatMail') && method_exists('erLhcoreClassChatMail', 'setupSMTP')) {
                    \erLhcoreClassChatMail::setupSMTP($mail);
                }
                $mail->CharSet = 'UTF-8';
                $mail->Subject = $subject;
                $mail->Body = $body;
                $mail->AltBody = strip_tags($body);
                $mail->AddAddress($toEmail);
                return (bool)$mail->Send();
            }

            $sender = 'no-reply@' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
            $headers = "From: " . $sender . "\r\n" .
                       "Reply-To: " . $sender . "\r\n" .
                       "Content-Type: text/plain; charset=UTF-8\r\n";

            return @mail($toEmail, $subject, $body, $headers);
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha send_mail_failed: ' . $e->getMessage());
            return false;
        }
    }

    private static function readKnownIps(): array
    {
        try {
            $stmt = \ezcDbInstance::get()->prepare('SELECT `value` FROM `lh_chat_config` WHERE `identifier` = :id');
            $stmt->bindValue(':id', self::KNOWN_IPS_IDENTIFIER);
            $stmt->execute();
            $raw = $stmt->fetchColumn();

            if (!is_string($raw) || $raw === '') {
                return array();
            }

            $decoded = json_decode($raw, true);
            return is_array($decoded) ? $decoded : array();
        } catch (\Throwable $e) {
            return array();
        }
    }

    private static function writeKnownIps(array $known): void
    {
        try {
            $json = json_encode($known);
            if ($json === false) {
                return;
            }

            $stmt = \ezcDbInstance::get()->prepare(
                "INSERT INTO `lh_chat_config` (`identifier`, `value`, `type`, `explain`, `hidden`) VALUES (:id, :v, 0, '', 1) " .
                "ON DUPLICATE KEY UPDATE `value` = :v2"
            );
            $stmt->bindValue(':id', self::KNOWN_IPS_IDENTIFIER);
            $stmt->bindValue(':v', $json);
            $stmt->bindValue(':v2', $json);
            $stmt->execute();
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha write_known_ips_failed: ' . $e->getMessage());
        }
    }

    // ------------------------------------------------------------------
    // Attempt Log (stored in lh_chat_config, newest first)
    // ------------------------------------------------------------------

    public static function recordAttempt(string $action, bool $ok, string $reason, int $difficulty, string $extraUser = ''): void
    {
        try {
            if (!$ok && !in_array($reason, self::NO_PENALTY_REASONS, true)) {
                self::registerFailure();
            }

            $ip = self::getClientIp();
            $ip = (filter_var($ip, FILTER_VALIDATE_IP) !== false) ? $ip : '';

            // Bound the DB writes a single IP can cause
            if ($ip !== '' && self::isApcuAvailable() && function_exists('apcu_inc')) {
                $rlKey = 'lhc_powcaptcha_lw_' . hash('sha256', $ip);
                apcu_add($rlKey, 0, 60);
                $written = apcu_inc($rlKey);
                if ($written !== false && $written > self::LOG_WRITE_RL_PER_MINUTE) {
                    return;
                }
            }

            $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';
            if ($extraUser !== '') {
                $userAgent = '[' . substr($extraUser, 0, 24) . '] ' . $userAgent;
            }

            $entry = array(
                't' => time(),
                'ip' => $ip,
                'a' => substr((string)preg_replace('/[^a-z0-9_]/i', '', $action), 0, 64),
                'ok' => $ok ? 1 : 0,
                'r' => substr((string)preg_replace('/[^a-z0-9_]/i', '', $reason), 0, 64),
                'd' => $difficulty,
                'ua' => substr((string)preg_replace('/[^\x20-\x7E]/', '', $userAgent), 0, 100),
            );

            $entries = self::readLogEntries();
            array_unshift($entries, $entry);
            $entries = array_slice($entries, 0, self::LOG_MAX_ENTRIES);

            $encoded = json_encode($entries);
            while ($encoded !== false && strlen($encoded) > self::LOG_MAX_BYTES && count($entries) > 1) {
                array_pop($entries);
                $encoded = json_encode($entries);
            }

            if ($encoded !== false) {
                self::writeLogValue($encoded);
            }
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha attempt_log_failed ' . get_class($e) . ': ' . $e->getMessage());
        }
    }

    public static function getAttemptLog(): array
    {
        try {
            return self::readLogEntries();
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha attempt_log_read_failed ' . get_class($e) . ': ' . $e->getMessage());
            return array();
        }
    }

    public static function clearAttemptLog(): void
    {
        $stmt = \ezcDbInstance::get()->prepare('DELETE FROM `lh_chat_config` WHERE `identifier` = :id');
        $stmt->bindValue(':id', self::LOG_IDENTIFIER);
        $stmt->execute();
    }

    private static function readLogEntries(): array
    {
        $stmt = \ezcDbInstance::get()->prepare('SELECT `value` FROM `lh_chat_config` WHERE `identifier` = :id');
        $stmt->bindValue(':id', self::LOG_IDENTIFIER);
        $stmt->execute();
        $raw = $stmt->fetchColumn();

        if (!is_string($raw) || $raw === '') {
            return array();
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return array();
        }

        $entries = array();
        foreach ($decoded as $row) {
            if (!is_array($row) || !isset($row['t'])) {
                continue;
            }
            $entries[] = array(
                't' => (int)$row['t'],
                'ip' => isset($row['ip']) ? (string)$row['ip'] : '',
                'a' => isset($row['a']) ? (string)$row['a'] : '',
                'ok' => !empty($row['ok']) ? 1 : 0,
                'r' => isset($row['r']) ? (string)$row['r'] : '',
                'd' => isset($row['d']) ? (int)$row['d'] : 0,
                'ua' => isset($row['ua']) ? (string)$row['ua'] : '',
            );
            if (count($entries) >= self::LOG_MAX_ENTRIES) {
                break;
            }
        }

        return $entries;
    }

    private static function writeLogValue(string $json): void
    {
        $stmt = \ezcDbInstance::get()->prepare(
            "INSERT INTO `lh_chat_config` (`identifier`, `value`, `type`, `explain`, `hidden`) VALUES (:id, :v, 0, '', 1) " .
            "ON DUPLICATE KEY UPDATE `value` = :v2"
        );
        $stmt->bindValue(':id', self::LOG_IDENTIFIER);
        $stmt->bindValue(':v', $json);
        $stmt->bindValue(':v2', $json);
        $stmt->execute();
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

    public static function getClientIp(): string
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
