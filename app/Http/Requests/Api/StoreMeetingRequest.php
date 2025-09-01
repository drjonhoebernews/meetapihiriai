<?php

namespace App\Http\Requests\Api;

use Illuminate\Foundation\Http\FormRequest;

class StoreMeetingRequest extends FormRequest
{
    public function authorize(): bool
    {
        return auth('api')->check();
    }

    public function rules(): array
    {
        return [
            'link'         => ['required', 'url', 'max:1024'],
            'type'         => ['required', 'in:meet,teams,zoom'],
            'start_at'     => ['required', 'date'],
            'end_at'       => ['nullable', 'date', 'after_or_equal:start_at'],
            'record_path'  => ['nullable', 'string', 'max:2048'],
            'log'          => ['nullable', 'array'],
        ];
    }

    public function messages(): array
    {
        return [
            'type.in' => "type sadece: meet, teams, zoom olabilir.",
        ];
    }
}
