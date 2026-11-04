<?php
#[\AllowDynamicProperties]
class erLhcoreClassExtensionLhcpowcaptcha
{
    public function __construct()
    {
    }

    public function run()
    {
        $this->registerAutoload();
        $this->registerEvents();
        $this->handleActions();
    }

    public function handleActions()
    {
        $isClear = isset($_POST['ClearLoginHistory']) || (isset($_GET['clear_login_history']) && $_GET['clear_login_history'] == '1');
        if ($isClear) {
            $uri = (string)($_SERVER['REQUEST_URI'] ?? '');
            if (strpos($uri, 'loginhistory') !== false || isset($_POST['ClearLoginHistory']) || isset($_GET['clear_login_history'])) {
                if (class_exists('erLhcoreClassUser')) {
                    $currentUser = \erLhcoreClassUser::instance();
                    if ($currentUser->isLogged()) {
                        $token = isset($_POST['csfr_token']) ? (string)$_POST['csfr_token'] : (isset($_GET['csfr_token']) ? (string)$_GET['csfr_token'] : '');
                        $csrfOk = false;
                        if ($token !== '' && method_exists($currentUser, 'validateCSFRToken')) {
                            $csrfOk = $currentUser->validateCSFRToken($token);
                        }
                        if ($csrfOk || empty($token)) {
                            erLhcoreClassPowCaptcha::clearLoginHistory();
                            if (session_status() === PHP_SESSION_ACTIVE) {
                                $_SESSION['pow_loginhistory_cleared'] = true;
                            }
                            if (class_exists('erLhcoreClassModule')) {
                                \erLhcoreClassModule::redirect('audit/loginhistory');
                                exit;
                            }
                        }
                    }
                }
            }
        }
    }

    public function registerAutoload()
    {
        spl_autoload_register(array($this, 'autoloadExt'), true, true);
        spl_autoload_register(array($this, 'autoload'), true, false);
    }

    public function autoloadExt($className)
    {
        if ($className === 'LiveHelperChat\\Validators\\CaptchaValidator') {
            include_once 'extension/lhcpowcaptcha/classes/CaptchaValidator.php';
        }
    }

    public function autoload($className)
    {
        $classesArray = array(
            'erLhcoreClassPowCaptcha' => 'extension/lhcpowcaptcha/classes/erlhcoreclasspowcaptcha.php',
            'erLhcoreClassPowMail' => 'extension/lhcpowcaptcha/classes/erlhcoreclasspowmail.php',
            'erLhcoreClassPowTwoFactor' => 'extension/lhcpowcaptcha/classes/erlhcoreclasspowtwofactor.php',
        );

        if (isset($classesArray[$className])) {
            include_once $classesArray[$className];
        }
    }

    public function registerEvents()
    {
        if (class_exists('erLhcoreClassChatEventDispatcher')) {
            $dispatcher = \erLhcoreClassChatEventDispatcher::getInstance();

            // Hook before authentication to detect when a login attempt starts
            $dispatcher->listen('user.login_before_authenticate', array('erLhcoreClassPowCaptcha', 'onLoginBeforeAuthenticate'));

            // Hook after successful authentication to record success & alert on new IP
            $dispatcher->listen('user.login_after_success_authenticate', array('erLhcoreClassPowCaptcha', 'onLoginAfterSuccessAuthenticate'));

            // Wrap every outgoing LHC mail (password reminder, transcript, ...) in an HTML layout
            $dispatcher->listen('chatmail.setup_smtp', array('erLhcoreClassPowMail', 'onSetupSmtp'));

            // Hook login history audit view to inject clear button when enabled
            $dispatcher->listen('audit.login_history', array('erLhcoreClassPowCaptcha', 'onAuditLoginHistory'));
        }
    }
}
