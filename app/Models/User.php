<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Traits\HasRoles;
use Tymon\JWTAuth\Contracts\JWTSubject;

/**
 * @method static create(mixed $data)
 * @method static where(string $string, mixed $email)
 * @method static whereIn(string $string, mixed $user_id)
 * @method static find($id)
 * @method static findOrFail(mixed $to_user_id)
 */
class User extends Authenticatable implements JWTSubject
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use  Notifiable, HasUuids, HasRoles;

    protected $keyType = 'string';
    public $incrementing = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'username',
        'firstname',
        'lastname',
        'cmappsID',
        'email',
        'password',
        'phone',
        'address',
        'active',
        'banned',
        'otp',
        'otp_expires_at',
        'avatar',
        'pincode',
        'two_factor_enabled',
        'api_key',
        'api_secret',
    ];
    protected $with = ['roles', 'permissions'];


    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'otp',
        'pincode',
        'api_secret',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'two_factor_enabled' => 'boolean',
        ];
    }

    /**
     * Token içinde kullanıcıyı tanımlayan ID bilgisini al.
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * JWT Payload içine eklenecek özel alanlar
     */
    public function getJWTCustomClaims(): array
    {
        return [
            'user_id' => $this->id,
            'email' => $this->email,
            'phone' => $this->phone,
            'ip' => request()->ip(),
            'device' => request()->header('User-Agent'),
            'roles' => $this->getRoleNames(),
            'permissions' => $this->getAllPermissions()->pluck('name')
        ];
    }
}
