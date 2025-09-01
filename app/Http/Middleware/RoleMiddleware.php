<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RoleMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, string ...$roles): Response
    {
        $user = $request->user();

        if (! $user || ! $user->hasAnyRole($roles)) {
            return response()->json([
                'code' => 403,
                'status' => 'error',
                'message' => 'Erişim reddedildi. Yetkiniz yok.',
            ], 403);
        }

        return $next($request);
    }
}
