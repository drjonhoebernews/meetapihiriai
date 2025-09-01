<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * @property mixed $email
 */
class ResetPasswordRequest extends FormRequest
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
            'email' => 'required|email|exists:users,email',
            'token' => 'required|string',
            'password' => 'required|string|min:8|confirmed',
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
            'email.exists' => 'Bu e-posta adresi ile kayıtlı bir kullanıcı bulunamadı.',
            'token.required' => 'Şifre sıfırlama bağlantısı geçersiz veya eksik.',
            'password.required' => 'Yeni şifre alanı zorunludur.',
            'password.min' => 'Şifre en az 8 karakter olmalıdır.',
            'password.confirmed' => 'Girilen şifreler uyuşmuyor.',
        ];
    }
}
