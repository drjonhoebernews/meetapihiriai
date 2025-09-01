<?php
namespace App\Services;

use Illuminate\Support\Facades\Http;

class NetgsmService
{
    public static function send(array $messages, string $encoding = 'TR', ?string $iysFilter = null): array
    {
        $payload = [
            'msgheader' => config('services.netgsm.sender'),
            'messages' => $messages,
            'encoding' => $encoding,
            'iysfilter' => $iysFilter ?? '',
            'partnercode' => ''
        ];

        $username = config('services.netgsm.username');
        $password = config('services.netgsm.password');

        $response = Http::withHeaders([
            'Authorization' => 'Basic ' . base64_encode("$username:$password"),
            'Content-Type' => 'application/json',
        ])->post(config('services.netgsm.url'), $payload);

        if ($response->failed()) {
            throw new \Exception('Netgsm SMS gönderimi başarısız: ' . $response->body());
        }

        return $response->json();
    }
}
