<?php
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(base_path('routes/api/v1/index.php'));
Route::prefix('v2')->group(base_path('routes/api/v2/index.php'));



