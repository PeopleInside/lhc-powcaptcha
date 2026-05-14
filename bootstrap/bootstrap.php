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
    }

    public function registerAutoload()
    {
        spl_autoload_register(array($this, 'autoload'), true, false);
    }

    public function autoload($className)
    {
        $classesArray = array(
            'erLhcoreClassPowCaptcha' => 'extension/lhcpowcaptcha/classes/erlhcoreclasspowcaptcha.php',
        );

        if (isset($classesArray[$className])) {
            include_once $classesArray[$className];
        }
    }
}
