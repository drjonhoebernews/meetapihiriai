<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ForgotPasswordRequest extends FormRequest
{
    /**
     * @return bool
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return string[]
     */
    public function rules(): array
    {
        return [
            'email' => 'required|email|exists:users,email'
        ];
    }

    /**
     * @return string[]
     */
    public function messages(): array
    {
        return [
            'email.required' => 'E-posta alanı zorunludur.',
            'email.email' => 'Geçerli bir e-posta adresi giriniz.',
            'email.exists' => 'Bu e-posta adresi ile kayıtlı bir kullanıcı bulunamadı.'
        ];
    }
}
