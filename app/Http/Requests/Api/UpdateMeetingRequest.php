<?php

namespace App\Http\Requests\Api;

use Illuminate\Foundation\Http\FormRequest;

class UpdateMeetingRequest extends FormRequest
{
    public function authorize(): bool
    {
        return auth('api')->check();
    }

    public function rules(): array
    {
        return [
            'link'         => ['sometimes', 'url', 'max:1024'],
            'type'         => ['sometimes', 'in:meet,teams,zoom'],
            'start_at'     => ['sometimes', 'date'],
            'end_at'       => ['nullable', 'date', 'after_or_equal:start_at'],
            'record_path'  => ['nullable', 'string', 'max:2048'],
            'log'          => ['nullable', 'array'],
        ];
    }
}
