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
        }
    }
}
