<?php
/**
 * Created by PhpStorm.
 * User: fanxinyu
 * Date: 2021-08-12
 * Time: 09:50
 */

namespace Daviswwang\JWT\Exception;

class AuthException extends \Exception
{
    public function __construct($msg = '', $code = 500)
    {
        parent::__construct($msg, $code);
    }
}