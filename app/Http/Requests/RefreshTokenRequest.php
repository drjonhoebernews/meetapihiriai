<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RefreshTokenRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'refresh_token' => 'required|string'
        ];
    }

    /**
     * Hata mesajlarını özelleştirme
     */
    public function messages(): array
    {
        return [
            'refresh_token.required' => 'Refresh token gereklidir!',
            'refresh_token.string' => 'Refresh token geçerli bir string olmalıdır!',
        ];
    }

    /**
     * Alan adlarını kullanıcı dostu şekilde tanımlar
     */
    public function attributes(): array
    {
        return [
            'refresh_token' => 'Yenileme tokenı',
        ];
    }

}
