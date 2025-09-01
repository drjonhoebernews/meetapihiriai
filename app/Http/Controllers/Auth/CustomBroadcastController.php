<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Broadcast;
use Tymon\JWTAuth\Facades\JWTAuth;
class CustomBroadcastController extends Controller
{
    public function authenticate(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json(['message' => 'Unauthorized.'], 403);
            }

            return Broadcast::validAuthenticationResponse($request, $user);
        } catch (\Exception $e) {
            return response()->json(['message' => 'JWT Error'], 403);
        }
    }
}
