<?php

/**
 * E-mail two-factor authentication, required ONLY when an operator logs in
 * from an IP address that is not yet known for that account.
 *
 * Flow:
 *  1. user.login_after_success_authenticate -> maybeChallenge()
 *  2. credentials are valid but IP is new  -> code is mailed, session is logged out,
 *     browser is redirected to /lhpowcaptcha/twofactor/<token>
 *  3. correct code -> setLoggedUser(), IP stored as known, normal post-login steps.
 */
#[\AllowDynamicProperties]
class erLhcoreClassPowTwoFactor
{
    private const PENDING_IDENTIFIER = 'powcaptcha_2fa_pending';
    private const MAX_PENDING = 200;
    private const RESEND_COOLDOWN = 60;
    private const MAX_RESENDS = 3;

    public static function maybeChallenge($currentUser, string $ip, $tpl = null): bool
    {
        try {
            $s = erLhcoreClassPowCaptcha::getRecaptchaSettings();
            if ((int)$s['pow_2fa'] !== 1 || $ip === '' || !is_object($currentUser)) {
                return false;
            }

            $u = $currentUser->getUserData();
            if (!is_object($u) || empty($u->id)) {
                return false;
            }

            $uid = (int)$u->id;
            $username = (string)$u->username;

            if (erLhcoreClassPowCaptcha::isIpKnown($uid, $ip)) {
                return false;
            }

            $email = trim((string)$u->email);
            $diff = erLhcoreClassPowCaptcha::getEffectiveDifficulty($s, $ip);

            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                erLhcoreClassPowCaptcha::recordAttempt('login_action', true, 'two_factor_skipped_no_email', $diff, $username);
                return false;
            }

            $token = bin2hex(random_bytes(16));
            $code = self::generateCode();

            $state = array(
                'uid' => $uid,
                'hash' => self::hashCode($code, $token),
                'exp' => time() + $s['pow_2fa_ttl'] * 60,
                'att' => 0,
                'ip' => $ip,
                'rem' => (isset($_POST['rememberMe']) && $_POST['rememberMe'] == 1) ? 1 : 0,
                'red' => isset($_POST['redirect']) ? substr((string)$_POST['redirect'], 0, 500) : '',
                'sent' => time(),
                'rs' => 0,
            );

            if (!self::sendCodeMail($email, $username, $code, (int)$s['pow_2fa_ttl'], $ip)) {
                // Fail-open: never lock operators out because of broken SMTP
                erLhcoreClassPowCaptcha::recordAttempt('login_action', true, 'two_factor_mail_failed', $diff, $username);
                return false;
            }

            self::savePending($token, $state);
            erLhcoreClassPowCaptcha::recordAttempt('login_action', true, 'two_factor_code_sent', $diff, $username);

            // Remove the freshly created session: the user is NOT logged in until the code is verified
            $currentUser->logout();

            if (strpos((string)($_SERVER['REQUEST_URI'] ?? ''), 'external_request') !== false) {
                $url = erLhcoreClassSystem::getHost() . erLhcoreClassDesign::baseurl('powcaptcha/twofactor') . '/' . $token;
                echo json_encode(array('success' => false, 'result' => '<div class="alert alert-info">Two-factor verification required: <a target="_blank" href="' . htmlspecialchars($url) . '">continue here</a>.</div>'));
                exit;
            }

            // logout() destroyed the PHP session: start a new one so the login form gets a valid CSRF token
            if (session_status() !== PHP_SESSION_ACTIVE) {
                @session_start();
            }

            if (is_object($tpl) && method_exists($tpl, 'set')) {
                // Pop-up on the same login page (rendered by lhkernel/recaptcha.tpl.php override)
                $tpl->set('pow_2fa_token', $token);
                $tpl->set('pow_2fa_masked', self::maskEmail($email));
                $tpl->set('pow_2fa_ttl', (int)$s['pow_2fa_ttl']);
                return true;
            }

            erLhcoreClassModule::redirect('powcaptcha/twofactor', '/' . $token);
            exit;
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha two_factor_failed: ' . $e->getMessage());
            return false;
        }
    }

    public static function getPending(string $token): ?array
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
            return null;
        }
        $all = self::loadPending();
        if (!isset($all[$token]) || !is_array($all[$token]) || $all[$token]['exp'] < time()) {
            return null;
        }
        return $all[$token];
    }

    /** @return array|null state on success; null on failure with $err = expired|locked|wrong|ip */
    public static function verify(string $token, string $code, ?string &$err = null): ?array
    {
        $state = self::getPending($token);
        if ($state === null) {
            $err = 'expired';
            return null;
        }
        if ($state['ip'] !== erLhcoreClassPowCaptcha::getClientIp()) {
            $err = 'ip';
            return null;
        }
        if ($state['att'] >= erLhcoreClassPowCaptcha::getRecaptchaSettings()['pow_2fa_attempts']) {
            self::deletePending($token);
            $err = 'locked';
            return null;
        }

        $code = preg_replace('/\D/', '', $code);
        if (strlen($code) === 6 && hash_equals($state['hash'], self::hashCode($code, $token))) {
            self::deletePending($token);
            return $state;
        }

        $state['att']++;
        self::savePending($token, $state);
        $err = 'wrong';
        return null;
    }

    public static function resend(string $token, ?string &$err = null): bool
    {
        $state = self::getPending($token);
        if ($state === null) {
            $err = 'expired';
            return false;
        }
        if ($state['rs'] >= self::MAX_RESENDS || time() - $state['sent'] < self::RESEND_COOLDOWN) {
            $err = 'cooldown';
            return false;
        }

        $user = erLhcoreClassModelUser::fetch((int)$state['uid']);
        if (!($user instanceof erLhcoreClassModelUser)) {
            $err = 'expired';
            return false;
        }

        $s = erLhcoreClassPowCaptcha::getRecaptchaSettings();
        $code = self::generateCode();
        if (!self::sendCodeMail((string)$user->email, (string)$user->username, $code, (int)$s['pow_2fa_ttl'], $state['ip'])) {
            $err = 'mail';
            return false;
        }

        $state['hash'] = self::hashCode($code, $token);
        $state['exp'] = time() + $s['pow_2fa_ttl'] * 60;
        $state['sent'] = time();
        $state['rs']++;
        self::savePending($token, $state);
        return true;
    }

    public static function failedAttempt(array $state): void
    {
        erLhcoreClassModelUserLogin::logUserAction(array(
            'type' => erLhcoreClassModelUserLogin::TYPE_LOGIN_ATTEMPT,
            'user_id' => (int)$state['uid'],
            'msg' => 'Failed two-factor code. WEB'
        ));
    }

    /** Completes the login after a correct code. */
    public static function finalizeLogin(array $state): bool
    {
        $cu = erLhcoreClassUser::instance();
        if (!$cu->setLoggedUser((int)$state['uid'], !empty($state['rem']))) {
            return false;
        }

        $ip = (string)$state['ip'];
        erLhcoreClassPowCaptcha::rememberIp((int)$state['uid'], $ip);

        $userData = $cu->getUserData();
        $s = erLhcoreClassPowCaptcha::getRecaptchaSettings();

        erLhcoreClassPowCaptcha::recordAttempt('login_action', true, 'two_factor_ok', erLhcoreClassPowCaptcha::getEffectiveDifficulty($s, $ip), (string)$userData->username);

        if ((int)$s['pow_new_ip_alert'] === 1) {
            erLhcoreClassPowCaptcha::sendNewIpNotificationEmail((string)$userData->email, (string)$userData->username, $ip);
        }

        erLhcoreClassModelUserLogin::logUserAction(array(
            'type' => erLhcoreClassModelUserLogin::TYPE_LOGGED,
            'user_id' => $cu->getUserID(),
            'msg' => 'Logged in successfully (two-factor). WEB'
        ));

        $userData->llogin = time();
        $userData->force_logout = 0;
        $userData->updateThis(array('update' => array('llogin', 'force_logout')));

        return true;
    }

    /** JSON API used by the pop-up on the login page. */
    public static function handleAjax(string $token, array $post): array
    {
        try {
            return self::handleAjaxInner($token, $post);
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha two_factor_ajax_failed: ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
            return array('success' => false, 'error' => 'Server error: ' . $e->getMessage());
        }
    }

    private static function handleAjaxInner(string $token, array $post): array
    {
        $t = erTranslationClassLhTranslation::getInstance();
        $state = self::getPending($token);

        if ($state === null) {
            return array('success' => false, 'fatal' => true, 'error' => $t->getTranslation('pow/twofactor', 'This verification has expired or is no longer valid. Please login again.'));
        }

        if (isset($post['do']) && $post['do'] === 'resend') {
            $err = null;
            if (self::resend($token, $err)) {
                return array('success' => false, 'info' => $t->getTranslation('pow/twofactor', 'A new code has been sent.'));
            }
            if ($err === 'cooldown') {
                return array('success' => false, 'error' => $t->getTranslation('pow/twofactor', 'Please wait a minute before requesting another code.'));
            }
            return array('success' => false, 'fatal' => true, 'error' => $t->getTranslation('pow/twofactor', 'Could not send the code. Please login again.'));
        }

        $err = null;
        $ok = self::verify($token, isset($post['code']) ? (string)$post['code'] : '', $err);

        if ($ok !== null) {
            if (!self::finalizeLogin($ok)) {
                return array('success' => false, 'fatal' => true, 'error' => $t->getTranslation('pow/twofactor', 'Could not send the code. Please login again.'));
            }
            $redirect = $ok['red'] !== '' ? (string)base64_decode($ok['red']) : '';
            if ($redirect === '' || !erLhcoreClassUserUtils::isValidRedirectPath($redirect)) {
                $redirect = '/';
            }
            return array('success' => true, 'redirect' => erLhcoreClassDesign::baseurl($redirect));
        }

        if ($err === 'wrong') {
            self::failedAttempt($state);
            return array('success' => false, 'error' => $t->getTranslation('pow/twofactor', 'Incorrect code.'));
        }

        return array('success' => false, 'fatal' => true, 'error' => $t->getTranslation('pow/twofactor', 'This verification has expired or is no longer valid. Please login again.'));
    }

    public static function maskEmail(string $email): string
    {
        $p = explode('@', $email, 2);
        if (count($p) !== 2) {
            return '***';
        }
        return substr($p[0], 0, 1) . str_repeat('*', max(2, strlen($p[0]) - 1)) . '@' . $p[1];
    }

    // ------------------------------------------------------------------

    private static function generateCode(): string
    {
        return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    private static function hashCode(string $code, string $token): string
    {
        $secret = (string)erConfigClassLhConfig::getInstance()->getSetting('site', 'secrethash');
        return hash_hmac('sha256', $code, $secret . '|2fa|' . $token);
    }

    private static function sendCodeMail(string $to, string $username, string $code, int $ttl, string $ip): bool
    {
        $t = erTranslationClassLhTranslation::getInstance();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr(preg_replace('/[^\x20-\x7E]/', '', (string)$_SERVER['HTTP_USER_AGENT']), 0, 160) : '-';
        $subject = $t->getTranslation('pow/twofactor', 'Your verification code') . ': ' . $code;

        $html = '<p>' . sprintf($t->getTranslation('pow/twofactor', 'Hello %s, someone entered your correct password from a new IP address. Enter this code to finish signing in:'), '<b>' . erLhcoreClassPowMail::esc($username) . '</b>') . '</p>'
            . erLhcoreClassPowMail::codeBox($code)
            . '<p>' . sprintf($t->getTranslation('pow/twofactor', 'The code is valid for %d minutes.'), $ttl) . '</p>'
            . erLhcoreClassPowMail::infoTable(array(
                $t->getTranslation('pow/twofactor', 'IP address') => $ip,
                $t->getTranslation('pow/twofactor', 'Date & time') => date('Y-m-d H:i:s T'),
                $t->getTranslation('pow/twofactor', 'Browser') => $ua,
            ))
            . '<p style="color:#c53030;">' . $t->getTranslation('pow/twofactor', 'If this was not you, do not share the code and change your password immediately.') . '</p>';

        $text = $t->getTranslation('pow/twofactor', 'Your verification code') . ': ' . $code . "\n" . sprintf($t->getTranslation('pow/twofactor', 'The code is valid for %d minutes.'), $ttl) . "\nIP: " . $ip;

        return erLhcoreClassPowCaptcha::sendMail($to, $subject, $text, erLhcoreClassPowMail::layout($subject, $html, $t->getTranslation('pow/twofactor', 'Your verification code') . ': ' . $code));
    }

    private static function loadPending(): array
    {
        try {
            $stmt = \ezcDbInstance::get()->prepare('SELECT `value` FROM `lh_chat_config` WHERE `identifier` = :id');
            $stmt->bindValue(':id', self::PENDING_IDENTIFIER);
            $stmt->execute();
            $raw = $stmt->fetchColumn();
            $decoded = is_string($raw) ? json_decode($raw, true) : null;
            return is_array($decoded) ? $decoded : array();
        } catch (\Throwable $e) {
            return array();
        }
    }

    private static function savePending(string $token, array $state): void
    {
        $all = self::loadPending();
        $now = time();
        foreach ($all as $k => $v) {
            if (!is_array($v) || !isset($v['exp']) || $v['exp'] < $now) {
                unset($all[$k]);
            }
        }
        $all[$token] = $state;
        if (count($all) > self::MAX_PENDING) {
            $all = array_slice($all, -self::MAX_PENDING, null, true);
        }
        self::writePending($all);
    }

    private static function deletePending(string $token): void
    {
        $all = self::loadPending();
        unset($all[$token]);
        self::writePending($all);
    }

    private static function writePending(array $all): void
    {
        try {
            $stmt = \ezcDbInstance::get()->prepare(
                "INSERT INTO `lh_chat_config` (`identifier`, `value`, `type`, `explain`, `hidden`) VALUES (:id, :v, 0, '', 1) " .
                "ON DUPLICATE KEY UPDATE `value` = :v2"
            );
            $json = json_encode($all);
            $stmt->bindValue(':id', self::PENDING_IDENTIFIER);
            $stmt->bindValue(':v', $json);
            $stmt->bindValue(':v2', $json);
            $stmt->execute();
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha write_pending_failed: ' . $e->getMessage());
        }
    }
}
