<?php

use App\Http\Middleware\RoleMiddleware;
use App\Traits\ApiResponseTrait;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\QueryException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        channels: __DIR__.'/../routes/channels.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->group('api', [
            SubstituteBindings::class,
            HandleCors::class,
        ]);
        $middleware->alias([
            'role' => RoleMiddleware::class,
        ]);
    })
    ->withExceptions(using: function (Exceptions $exceptions) {
        $response = new class {
            use ApiResponseTrait;
        };
        $exceptions->render(using: function (Throwable $e, $request) use ($response) {
            if (true) {
                if ($e instanceof ValidationException) {
                    return $response->errorResponse('İşlem başarısız!', $response::HTTP_UNPROCESSABLE_ENTITY, $e->errors());
                }

                if ($e instanceof ModelNotFoundException || $e instanceof NotFoundHttpException) {
                    return $response->errorResponse('Talep edilen kaynak bulunamadı.', $response::HTTP_NOT_FOUND);
                }

                if ($e instanceof AuthenticationException) {
                    return $response->errorResponse('Yetkisiz erişim.', $response::HTTP_UNAUTHORIZED);
                }

                if ($e instanceof MethodNotAllowedHttpException) {
                    return $response->errorResponse('HTTP metodu bu kaynak için geçerli değil.', $response::HTTP_METHOD_NOT_ALLOWED);
                }

                if ($e instanceof QueryException || $e instanceof \PDOException) {
                    Log::error($e);
                    return $response->errorResponse('Sunucu hatası oluştu. Lütfen daha sonra tekrar deneyiniz.', $response::HTTP_INTERNAL_SERVER_ERROR);
                }

                if ($e instanceof HttpException) {
                    return $response->errorResponse($e->getMessage() ?: 'İstemci hatası', $e->getStatusCode());
                }

                return $response->errorResponse('Beklenmeyen bir hata oluştu.', $response::HTTP_INTERNAL_SERVER_ERROR, [
                    'internal' => [app()->environment('local') ? $e->getMessage() : null]
                ]);
            }
        });
    })->create();
