<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'username' => 'required|string|max:255|unique:users',
            'firstname' => 'nullable|string|max:255',
            'lastname' => 'nullable|string|max:255',
            'email' => 'required|email|unique:users,email|max:255',
            'phone' => 'nullable|string|max:50|unique:users,phone',
            'password' => 'required|string|min:6|confirmed',

            'address' => 'nullable|string|max:500',
            'avatar' => 'nullable|url|max:255',
            'pincode' => 'nullable|string|max:20',

            'active' => 'boolean',
            'banned' => 'boolean',

            'otp' => 'nullable|string|max:10',
            'two_factor_enabled' => 'boolean',

            // Opsiyonel olarak eklenebilir:
            'google_id' => 'nullable|string|max:255|unique:users,google_id',
            'cmappsID' => 'nullable|string|max:255',
            'api_key' => 'nullable|string|max:255|unique:users,api_key',
            'api_secret' => 'nullable|string|max:255',
        ];
    }

    public function messages(): array
    {
        return [
            'username.required' => 'Kullanıcı adı zorunludur.',
            'username.unique' => 'Bu kullanıcı adı zaten kayıtlı.',
            'email.required' => 'E-posta adresi zorunludur.',
            'email.email' => 'Geçerli bir e-posta adresi giriniz.',
            'email.unique' => 'Bu e-posta zaten kayıtlı.',
            'password.required' => 'Şifre gereklidir.',
            'password.min' => 'Şifre en az 6 karakter olmalıdır.',
            'password.confirmed' => 'Şifreler uyuşmuyor.',
            'phone.unique' => 'Bu telefon numarası zaten kayıtlı.',
            'google_id.unique' => 'Bu Google hesabı zaten bağlanmış.',
            'api_key.unique' => 'API anahtarı zaten kullanımda.',
        ];
    }

    public function attributes(): array
    {
        return [
            'username' => 'Kullanıcı Adı',
            'firstname' => 'Ad',
            'lastname' => 'Soyad',
            'email' => 'E-posta',
            'phone' => 'Telefon',
            'password' => 'Şifre',
            'address' => 'Adres',
            'avatar' => 'Avatar URL',
            'pincode' => 'Pin Kodu',
            'otp' => 'Tek Kullanımlık Kod',
            'two_factor_enabled' => 'İki Aşamalı Doğrulama',
            'google_id' => 'Google ID',
            'cmappsID' => 'CM Apps ID',
            'api_key' => 'API Anahtarı',
            'api_secret' => 'API Şifresi',
        ];
    }
}
