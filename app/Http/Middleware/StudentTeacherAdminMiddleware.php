<?php

namespace App\Http\Middleware;

use App\HttpResponse\HTTPResponse;
use App\Types\UserType;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class StudentTeacherAdminMiddleware
{
    use HTTPResponse;
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (strval(Auth::user()->type === UserType::STUDENT) ||
            strval(Auth::user()->type === UserType::ADMIN)||
        strval(Auth::user()->type === UserType::TEACHER)){
            return $next($request);
        }
        return $this->error(__("messages.error.admin_permission") , 403);
    }
}
