<?php

$Module = array('name' => 'PoW Captcha', 'variable_params' => true);

$ViewList = array();

$ViewList['challenge'] = array(
    'params' => array('action'),
    'uparams' => array()
);

$ViewList['twofactor'] = array(
    'params' => array('token'),
    'uparams' => array()
);
