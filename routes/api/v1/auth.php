<?php

use App\Http\Controllers\Auth\CustomBroadcastController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;

Route::prefix('auth')->group(function () {
    Route::post('/register', [AuthController::class, 'registers'])->name('register');
    Route::post('/login', [AuthController::class, 'login'])->name('login');
    Route::post('/refresh', [AuthController::class, 'refresh'])->name('refresh');
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword'])->name('forgot-password');
    Route::post('/reset-password', [AuthController::class, 'resetPassword'])->name('reset-password');
    Route::post('/google-login', [AuthController::class, 'googleLogin']);
    Route::post('/integration-login', [AuthController::class, 'integrationLogin']);

    Route::middleware('auth:api')->group(function () {
        Route::post('/broadcasting/auth', [CustomBroadcastController::class, 'authenticate']);
        Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
        Route::get('/me', [AuthController::class, 'me'])->name('me');
        Route::post('/api-credentials', [AuthController::class, 'generateApiCredentials']);
        Route::prefix('2fa')->group(function () {
            Route::post('/verify', [AuthController::class, 'verifyTwoFactor']);
            Route::post('/enable', [AuthController::class, 'enableTwoFactor']);
            Route::post('/disable', [AuthController::class, 'disableTwoFactor']);
            Route::get('/qrcode', [AuthController::class, 'getTwoFactorQrCode']);
        });
    });
});
