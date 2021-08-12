<?php
/**
 * Created by PhpStorm.
 * User: fanxinyu
 * Date: 2021-08-12
 * Time: 11:02
 */

namespace Daviswwang\JWT\Middleware;

use Daviswwang\JWT\Exception\AuthException;
use Closure;
use Illuminate\Http\Request;
use Daviswwang\JWT\JWT;

class AuthMiddleware
{

    CONST PREFIX = 'Bearer ';

    protected $jwt;

    public function __construct(JWT $jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * @param Request $request
     * @param Closure $next
     * @return mixed
     * @throws AuthException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     * @author: fanxinyu
     */
    public function handle(Request $request, Closure $next)
    {

        if (!$token = $request->header('Authorization', '')) throw new AuthException('未获取Authorization');

        $token = str_replace(self::PREFIX, '', $token);

        try {
            $this->jwt->checkToken($token);

            $res = $this->jwt->getParserData($token);

            if (!is_array($res) || !isset($res['user_code'])) throw new AuthException('未解析成功Authorization');

            $request->offsetSet('auth_user_code', $res['user_code'] ?? "");
            $request->offsetSet('auth_shop_code', $res['shop_code'] ?? '');
            $request->offsetSet('auth_depart_code', $res['depart_code'] ?? "");
            $request->offsetSet('auth_user_info', $res);

        } catch (\Exception $e) {
            throw new AuthException('无效的鉴权');
        }
        return $next($request);
    }
}