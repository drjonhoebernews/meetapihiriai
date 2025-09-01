<?php


use App\Http\Controllers\Api\Web\LicenseVerificationController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\Customer\{BlogCategoryCustomerController,
    BlogCustomerController,
    CampaignCustomerBannerController,
    ContactCustomerController,
    ContractCustomerController,
    ProductCustomerTemplateController,
    ReferenceCustomerController,
};

Route::prefix('web')->group(function () {

    Route::prefix('product-templates')->group(function () {
        Route::get('/', [ProductCustomerTemplateController::class, 'index']);
        Route::get('{id}', [ProductCustomerTemplateController::class, 'show']);
    });

    Route::prefix('blogs')->group(function () {
        Route::get('/', [BlogCustomerController::class, 'index']);
        Route::get('{id}', [BlogCustomerController::class, 'show']);
    });

    Route::prefix('blog-categories')->group(function () {
        Route::get('/', [BlogCategoryCustomerController::class, 'index']);
        Route::get('{slug}', [BlogCategoryCustomerController::class, 'show']);
    });

    Route::post('contacts', [ContactCustomerController::class, 'store']);

    Route::prefix('campaign-banners')->group(function () {
        Route::get('/', [CampaignCustomerBannerController::class, 'index']);
        Route::get('{id}', [CampaignCustomerBannerController::class, 'show']);
        Route::post('{id}/click', [CampaignCustomerBannerController::class, 'click']);
    });

    Route::prefix('contracts')->group(function () {
        Route::get('/', [ContractCustomerController::class, 'index']);
        Route::get('/titles', [ContractCustomerController::class, 'titles']);
        Route::get('/{id}', [ContractCustomerController::class, 'show']);
    });

    Route::prefix('references')->group(function () {
        Route::get('/', [ReferenceCustomerController::class, 'index']);
    });

    Route::prefix('verify')->group(function () {
        Route::get('/', [LicenseVerificationController::class, 'verify']);
    });
});
