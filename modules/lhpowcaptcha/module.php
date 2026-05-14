<?php

$Module = array('name' => 'PoW Captcha', 'variable_params' => true);

$FunctionList = array();
$FunctionList['use'] = array('explain' => 'Allow usage of PoW captcha settings');

$ViewList = array();

$ViewList['challenge'] = array(
    'params' => array('action'),
    'uparams' => array()
);

$ViewList['settings'] = array(
    'params' => array(),
    'uparams' => array(),
    'functions' => array('use')
);
