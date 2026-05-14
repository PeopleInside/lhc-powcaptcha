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

    public static function getRecaptchaSettings(): array
    {
        $settings = \LiveHelperChat\Validators\CaptchaValidator::getCaptchaSettings();

        $settings['pow_difficulty'] = isset($settings['pow_difficulty']) ? (int)$settings['pow_difficulty'] : self::DEFAULT_DIFFICULTY;
        $settings['pow_ttl'] = isset($settings['pow_ttl']) ? (int)$settings['pow_ttl'] : self::DEFAULT_TTL;

        if ($settings['pow_difficulty'] < self::MIN_DIFFICULTY || $settings['pow_difficulty'] > self::MAX_DIFFICULTY) {
            $settings['pow_difficulty'] = self::DEFAULT_DIFFICULTY;
        }

        if ($settings['pow_ttl'] < self::MIN_TTL || $settings['pow_ttl'] > self::MAX_TTL) {
            $settings['pow_ttl'] = self::DEFAULT_TTL;
        }

        return $settings;
    }

    public static function isPowEnabled(): bool
    {
        $settings = self::getRecaptchaSettings();
        return ((int)$settings['enabled'] === 1 && $settings['provider'] === 'pow');
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

        $parts = explode('.', $challenge, 2);
        if (count($parts) !== 2) {
            $reason = 'challenge_invalid';
            return false;
        }

        $encodedPayload = $parts[0];
        $providedSignature = $parts[1];
        $calculatedSignature = hash_hmac('sha256', $encodedPayload, self::getSecret());

        if (!hash_equals($calculatedSignature, $providedSignature)) {
            $reason = 'signature_mismatch';
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
            return false;
        }

        $digest = hash('sha256', $challenge . '|' . $nonce);

        if (!self::hasLeadingZeroBits($digest, $difficulty)) {
            $reason = 'insufficient_work';
            return false;
        }

        $_SESSION['lhc_powcaptcha_used'][$proofHash] = $expiry;
        $reason = 'validated';

        return true;
    }

    private static function cleanupReplayCache(int $now): void
    {
        if (!isset($_SESSION['lhc_powcaptcha_used']) || !is_array($_SESSION['lhc_powcaptcha_used'])) {
            return;
        }

        foreach ($_SESSION['lhc_powcaptcha_used'] as $proof => $expiresAt) {
            if ((int)$expiresAt < ($now - 30)) {
                unset($_SESSION['lhc_powcaptcha_used'][$proof]);
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

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder > 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return (string)base64_decode(strtr($data, '-_', '+/'));
    }
}
