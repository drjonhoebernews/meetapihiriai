<?php
//require __DIR__ . '/auth.php';
//require __DIR__ . '/admin.php';
//require __DIR__ . '/dealer.php';
//require __DIR__ . '/customer.php';
//require __DIR__ . '/ai.php';
//require __DIR__ . '/common.php';
use Illuminate\Support\Facades\Route;

Route::get('/version', fn () => response()->json(['version' => 'v2']));
