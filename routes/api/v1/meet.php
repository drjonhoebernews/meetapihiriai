<?php

use App\Http\Controllers\Api\MeetingController;
use Illuminate\Support\Facades\Route;

Route::prefix('meetings')->name('meetings.')->middleware('auth:api')->group(function () {
    Route::get('/', [MeetingController::class, 'index'])->name('index');
    Route::get('/{id}', [MeetingController::class, 'show'])->name('show');
    Route::post('/', [MeetingController::class, 'store'])->name('store');
    Route::put('/{id}', [MeetingController::class, 'update'])->name('update');
    Route::delete('/{id}', [MeetingController::class, 'destroy'])->name('destroy');
});
