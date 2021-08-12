<?php
/**
 * Created by PhpStorm.
 * User: fanxinyu
 * Date: 2021-08-12
 * Time: 11:02
 */

namespace Daviswwang\JWT;

/**
 * Interface JWTInterface
 * @package Daviswwang\JWT
 */
interface JWTInterface
{
    public function setSceneConfig(string $scene = 'default', $value = null);
    public function getSceneConfig(string $scene = 'default');
    public function setScene(string $scene);
    public function getScene();
}
