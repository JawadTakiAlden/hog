<?php

namespace App\Http\Middleware;

use App\HttpResponse\HTTPResponse;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class BlockedMiddelWare
{
    use HTTPResponse;
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (boolval(Auth::user()->is_blocked) === false){
            return $next($request);
        }
        return $this->error('you are blocked so , you can\'t doing any action , please call admin to solve the problem' , 403);
    }
}
