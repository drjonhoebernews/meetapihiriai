<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class LoginRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'email_or_phone_or_cmappsID' => 'required|string',
            'password' => 'required|string|min:6',
        ];
    }

    public function messages(): array
    {
        return [
            'email_or_phone_or_cmappsID.required' => 'E-posta, telefon veya CMApps ID alanı zorunludur.',
            'email_or_phone_or_cmappsID.string'   => 'Bu alan geçerli bir metin olmalıdır.',

            'password.required' => 'Şifre alanı boş bırakılamaz.',
            'password.string'   => 'Şifre geçerli bir metin olmalıdır.',
            'password.min'      => 'Şifreniz en az 6 karakter olmalıdır.',
        ];
    }

    public function attributes(): array
    {
        return [
            'email_or_phone_or_cmappsID' => 'E-posta / Telefon / CMApps ID',
            'password' => 'Şifre',
        ];
    }
}
