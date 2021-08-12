<?php
/**
 * Created by PhpStorm.
 * User: fanxinyu
 * Date: 2021-08-12
 * Time: 11:02
 */
namespace Daviswwang\JWT\Middleware;

use App\Exceptions\AuthException;
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
            //只在正式环境起效
            if (env('APP_DEBUG') == 'false') {
                $this->jwt->checkToken($token);
            }

            $request = $request->offsetSet('user', $this->jwt->getParserData($token));

            var_dump($this->jwt->getParserData($token));

        } catch (\Exception $e) {
            throw new AuthException('无效的鉴权');
        }
        return $next($request);
    }
}