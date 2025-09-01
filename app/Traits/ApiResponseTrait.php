<?php

namespace App\Traits;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;
use Jenssegers\Agent\Agent;

trait ApiResponseTrait
{
    const HTTP_OK = 200;
    const HTTP_CREATED = 201;
    const HTTP_ACCEPTED = 202;
    const HTTP_NO_CONTENT = 204;

    const HTTP_BAD_REQUEST = 400;
    const HTTP_UNAUTHORIZED = 401;
    const HTTP_FORBIDDEN = 403;
    const HTTP_NOT_FOUND = 404;
    const HTTP_METHOD_NOT_ALLOWED = 405;
    const HTTP_CONFLICT = 409;
    const HTTP_UNPROCESSABLE_ENTITY = 422;

    const HTTP_TOO_MANY_REQUESTS = 429;
    const HTTP_INTERNAL_SERVER_ERROR = 500;

    /**
     * @return string
     */
    protected function getClientIp(): string
    {
        $forwarded = request()->header('X-Forwarded-For');
        if ($forwarded) {
            $ips = explode(',', $forwarded);
            return trim($ips[0]);
        }

        return request()->ip();
    }

    /**
     * @return string
     */
    private function getServerIp(): string
    {
        $ip = null;

        if (PHP_OS_FAMILY === 'Windows') {
            $ip = getHostByName(getHostName());
        } else {
            $result = shell_exec("hostname -I");
            if ($result) {
                $ips = explode(' ', trim($result));
                foreach ($ips as $item) {
                    if (filter_var($item, FILTER_VALIDATE_IP) && !str_starts_with($item, '127')) {
                        $ip = $item;
                        break;
                    }
                }
            }
        }

        return $ip ?? 'UNKNOWN';
    }


    /**
     * @param int $status
     * @return array
     */
    protected function meta(int $status): array
    {
        $agent = new Agent();
        return [
            'code' => $status,
            'status' => $status < 400 ? 'success' : 'error',
            'timestamp' => now()->format('Y-m-d H:i:s'),
            'request_id' => request()->attributes->get('request_id') ?? Str::uuid()->toString(),
            'path' => request()->path(),
            'method' => request()->method(),
            'environment' => app()->environment(),
            'duration_ms' => (microtime(true) - LARAVEL_START) * 1000,
            'locale' => app()->getLocale(),
            'user_agent' => request()->header('User-Agent'),
            'device' => $agent->device(),
            'user_id' => optional(auth()->user())->id,
            'performance_tag' => strtoupper(request()->method()) . ' ' . request()->path(),
            'test_mode' => app()->environment('local'),
            'ip' => $this->getClientIp(),
            'response_node' => gethostname(),
        ];
    }


    /**
     * @param $data
     * @param string $message
     * @param int $status
     * @return JsonResponse
     */
    public function successResponse($data, string $message = 'Success', int $status = self::HTTP_OK): JsonResponse
    {
        return response()->json(array_merge(
            $this->meta($status),
            ['message' => $message, 'data' => $data]
        ), $status);
    }


    /**
     * @param string $message
     * @param int $status
     * @param array $errors
     * @param $exception
     * @return JsonResponse
     */
    public function errorResponse(string $message = 'Error', int $status = self::HTTP_BAD_REQUEST, array $errors = [], $exception = null): JsonResponse
    {
        $response = array_merge(
            $this->meta($status),
            ['message' => $message, 'errors' => $errors]
        );

        if (app()->isLocal() && $exception instanceof \Throwable) {
            $response['debug'] = [
                'exception' => get_class($exception),
                'file' => $exception->getFile(),
                'line' => $exception->getLine(),
                'trace' => collect($exception->getTrace())->take(3)
            ];
        }
        return response()->json($response, $status);
    }
}
