<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;


class VerifyTwoFactorRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'code' => ['required', 'string', 'size:6'],
        ];
    }

    public function messages(): array
    {
        return [
            'code.required' => 'Doğrulama kodu zorunludur.',
            'code.size' => '6 haneli bir doğrulama kodu girmelisiniz.',
        ];
    }
}
