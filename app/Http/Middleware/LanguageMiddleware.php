<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Symfony\Component\HttpFoundation\Response;

class LanguageMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $language = $request->query('ln');
        if (!$language){
            App::setLocale('ar');
        }else{
            if ($language === 'en'){
                App::setLocale($language);
            }else{
                App::setLocale('ar');
            }
        }
        return $next($request);
    }
}
