<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @method static updateOrCreate(array $array, array $array1)
 * @method static where(string $string, mixed $email)
 */
class PasswordResetToken extends Model
{
    protected $table = 'password_reset_tokens';

    public $timestamps = false;
    public $incrementing = false;
    protected $primaryKey = null;

    protected $fillable = ['email', 'token', 'created_at'];

    public function isExpired(): bool
    {
        return Carbon::parse($this->created_at)->addMinutes(60)->isPast();
    }
}
