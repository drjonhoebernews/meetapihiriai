<?php

namespace App\Http\Controllers\Auth;
use App\Http\Controllers\Controller;
use App\Http\Requests\DisableTwoFactorRequest;
use App\Http\Requests\EnableTwoFactorRequest;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\GoogleLoginRequest;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RefreshTokenRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Requests\VerifyTwoFactorRequest;
use App\Mail\ContactFormSubmitted;
use App\Mail\RegisterForm;
use App\Mail\ResetPasswordMail;
use App\Models\PasswordResetToken;
use App\Models\User;
use App\Services\NetgsmService;
use App\Traits\ApiResponseTrait;
use Google_Client;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Str;
use PragmaRX\Google2FA\Google2FA;
use SimpleSoftwareIO\QrCode\Facades\QrCode;
use Tymon\JWTAuth\Facades\JWTAuth;

/**
 * @OA\Tag(
 *     name="Kimlik Doğrulama İşlemleri",
 *     description="Kimlik doğrulama işlemleri: kayıt, giriş, token yenileme vs."
 * )
 */
class AuthController extends Controller
{
    use ApiResponseTrait;

    /**
     * @OA\Post(
     *     path="/v1/auth/register",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Yeni kullanıcı kaydı oluşturur.",
     *     description="Yeni kullanıcı kaydı yapar ve JWT token ile birlikte geri döner.",
     *     operationId="authRegister",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"username", "email", "password", "password_confirmation"},
     *             @OA\Property(property="username", type="string", example="cmappsdev"),
     *             @OA\Property(property="firstname", type="string", example="Ali"),
     *             @OA\Property(property="lastname", type="string", example="Veli"),
     *             @OA\Property(property="email", type="string", format="email", example="ali@example.com"),
     *             @OA\Property(property="phone", type="string", example="5551112233"),
     *             @OA\Property(property="password", type="string", format="password", example="12345678"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="12345678"),
     *             @OA\Property(property="address", type="string", example="İstanbul, Türkiye"),
     *             @OA\Property(property="cmappsID", type="string", example="CM123456"),
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Kullanıcı başarıyla oluşturuldu.",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string"),
     *             @OA\Property(property="token_type", type="string", example="bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=3600),
     *             @OA\Property(property="user", type="object",
     *                 @OA\Property(property="id", type="string", format="uuid"),
     *                 @OA\Property(property="username", type="string"),
     *                 @OA\Property(property="email", type="string"),
     *                 @OA\Property(property="roles", type="array", @OA\Items(type="string")),
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Geçersiz veri",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Veri doğrulama hatası."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Sunucu hatası",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Sunucuda bir hata oluştu.")
     *         )
     *     )
     * )
     */
    public function registers(RegisterRequest $request): \Illuminate\Http\JsonResponse
    {
        DB::beginTransaction();

        try {
            $user = User::create([
                'username' => $request->username,
                'firstname' => $request->firstname,
                'lastname' => $request->lastname,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'phone' => $request->phone,
                'address' => $request->address,
                'cmappsID'=> generate_cmappsID(),
            ]);

            $user->assignRole('applicant');
            $roles = $user->roles()->pluck('name')->toArray();
            $permissions = $user->permissions()->pluck('name')->toArray();

            $token = JWTAuth::fromUser($user);
            $user->makeHidden(['roles', 'permissions']);

            DB::commit();

            $fullName = $user->firstname . ' ' . $user->lastname;

            Mail::send(new RegisterForm([
                'name' => $fullName,
                'email' => $request->email,
                'message' => $request->message,
            ]));




            return $this->successResponse([
                'user' => $user,
                'roles' => $roles,
                'permissions' => $permissions,
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60
            ], 'Kayıt Başarılı!', self::HTTP_CREATED);
        } catch (\Exception $e) {
            DB::rollBack();

            return $this->errorResponse('Kayıt sırasında bir hata oluştu!', self::HTTP_INTERNAL_SERVER_ERROR, [
                'error' => $e->getMessage()
            ]);
        }
    }


    /**
     * @OA\Post(
     *     path="/v1/auth/login",
     *     operationId="authLogin",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Kullanıcı girişi yapar (JWT + 2FA destekli)",
     *     description="Email, telefon veya cmappsID ile giriş yapılır. 2FA aktifse pending token döner, değilse token seti ile tam oturum sağlanır.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email_or_phone_or_cmappsID", "password"},
     *             @OA\Property(property="email_or_phone_or_cmappsID", type="string", example="user1@cmapps.co"),
     *             @OA\Property(property="password", type="string", format="password", example="cmapps123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Başarılı giriş veya 2FA doğrulama bekleniyor.",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     description="2FA aktif: pending token ile dönüş",
     *                     @OA\Property(property="status", type="string", example="success"),
     *                     @OA\Property(property="message", type="string", example="2FA doğrulama gerekiyor."),
     *                     @OA\Property(property="data", type="object",
     *                         @OA\Property(property="user", type="object",
     *                             @OA\Property(property="id", type="string", format="uuid"),
     *                             @OA\Property(property="name", type="string", example="User 1"),
     *                             @OA\Property(property="email", type="string", format="email"),
     *                             @OA\Property(property="phone", type="string"),
     *                             @OA\Property(property="avatar", type="string", format="uri"),
     *                             @OA\Property(property="authority", type="string", example="admin"),
     *                             @OA\Property(property="two_factor_enabled", type="boolean", example=true)
     *                         ),
     *                         @OA\Property(property="pending_token", type="string")
     *                     )
     *                 ),
     *                 @OA\Schema(
     *                     description="2FA kapalı: access + refresh token ile dönüş",
     *                     @OA\Property(property="status", type="string", example="success"),
     *                     @OA\Property(property="message", type="string", example="Giriş başarılı!"),
     *                     @OA\Property(property="data", type="object",
     *                         @OA\Property(property="user", type="object",
     *                             @OA\Property(property="id", type="string", format="uuid"),
     *                             @OA\Property(property="name", type="string"),
     *                             @OA\Property(property="email", type="string", format="email"),
     *                             @OA\Property(property="phone", type="string"),
     *                             @OA\Property(property="avatar", type="string", format="uri"),
     *                             @OA\Property(property="authority", type="string", example="admin"),
     *                             @OA\Property(property="two_factor_enabled", type="boolean", example=false)
     *                         ),
     *                         @OA\Property(property="access_token", type="string"),
     *                         @OA\Property(property="refresh_token", type="string"),
     *                         @OA\Property(property="token_type", type="string", example="bearer"),
     *                         @OA\Property(property="expires_in", type="integer", example=3600)
     *                     )
     *                 )
     *             }
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Giriş başarısız (hatalı şifre veya kullanıcı bulunamadı).",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Şifre eşleşmedi!"),
     *             @OA\Property(property="errors", type="object",
     *                 @OA\Property(property="reason", type="string", example="invalid_password")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Hesap pasif veya yasaklı.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Hesabınız devre dışı bırakılmış!"),
     *             @OA\Property(property="errors", type="object",
     *                 @OA\Property(property="reason", type="string", example="account_inactive")
     *             )
     *         )
     *     )
     * )
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $loginField = $request->email_or_phone_or_cmappsID;
        $password = $request->password;

        $user = User::where('email', $loginField)
            ->orWhere('phone', $loginField)
            ->orWhere('cmappsID', $loginField)
            ->orWhere('username', $loginField)
            ->first();

        if (!$user) {
            return $this->errorResponse('Kullanıcı bulunamadı!', self::HTTP_UNAUTHORIZED, [
                'reason' => 'Kullanıcı bulunamadı'
            ]);
        }

        if (!Hash::check($password, $user->password)) {
            return $this->errorResponse('Şifre eşleşmedi!', self::HTTP_UNAUTHORIZED, [
                'reason' => 'Şifre eşleşmedi!'
            ]);
        }

        if (!$user->active) {
            return $this->errorResponse('Hesabınız devre dışı bırakılmış!', self::HTTP_FORBIDDEN, [
                'reason' => 'Hesabınız devre dışı bırakılmış!'
            ]);
        }

        if ($user->banned) {
            return $this->errorResponse('Hesabınız yasaklanmış!', self::HTTP_FORBIDDEN, [
                'reason' => 'Hesabınız yasaklanmış!'
            ]);
        }

        if ($user->two_factor_enabled) {
            $pendingToken = JWTAuth::claims([
                '2fa_pending' => true,
            ])->fromUser($user);
            return $this->successResponse([
                'pending_token' => $pendingToken,
                'user' => [
                    'id' => $user->id,
                    'username' => $user->username,
                    'fullname' => $user->firstname . ' ' . $user->lastname,
                    'email' => $user->email,
                    'phone' => $user->phone,
                    'cmappsID' => $user->cmappsID,
                    'avatar' => generate_avatar_url($user->email),
                    'authority' => $user->getRoleNames()->first(),
                    'two_factor_enabled' => true,
                ],
            ], '2FA doğrulama gerekiyor.', self::HTTP_OK);
        }

        $accessToken = JWTAuth::fromUser($user);
        $refreshToken = JWTAuth::claims(['refresh' => true])->fromUser($user);

        return $this->successResponse([
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'fullname' => $user->firstname . ' ' . $user->lastname,
                'email' => $user->email,
                'phone' => $user->phone,
                'cmappsID' => $user->cmappsID,
                'avatar' => generate_avatar_url($user->email),
                'authority' => $user->getRoleNames()->first(),
                'two_factor_enabled' => false,
            ],
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ], 'Giriş başarılı!', self::HTTP_OK);
    }


    /**
     * @param ForgotPasswordRequest $request
     * @return JsonResponse
     */
    /**
     * @OA\Post(
     *     path="/v1/auth/forgot-password",
     *     operationId="forgotPassword",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Şifre sıfırlama bağlantısı gönderir",
     *     description="Kullanıcının e-posta adresine şifre sıfırlama bağlantısı gönderir.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Şifre sıfırlama bağlantısı gönderildi",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Şifre sıfırlama bağlantısı e-posta adresinize gönderildi."),
     *             @OA\Property(property="data", type="string", example=null)
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Geçersiz e-posta adresi",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Doğrulama hatası oluştu."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function forgotPassword(ForgotPasswordRequest $request): \Illuminate\Http\JsonResponse
    {
        $email = strtolower(trim($request->input('email')));
        $throttleKey = 'forgot-password:' . md5($email);

        if (Cache::has($throttleKey)) {
            return $this->errorResponse(
                'Bu e-posta için kısa süre önce şifre sıfırlama isteği gönderildi. Lütfen biraz bekleyin.',
                self::HTTP_TOO_MANY_REQUESTS
            );
        }

        $token = Str::random(64);

        PasswordResetToken::updateOrCreate(
            ['email' => $email],
            ['token' => hash('sha256', $token), 'created_at' => now()]
        );

        Mail::to($email)->queue(
            (new ResetPasswordMail($token, $email))->onQueue('FORGOT_PASSWORD')
        );

        Cache::put($throttleKey, true, now()->addSeconds(60));

        return $this->successResponse(null, 'Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.');
    }

    /**
     * @param ResetPasswordRequest $request
     * @return JsonResponse
     */
    /**
     * @OA\Post(
     *     path="/v1/auth/reset-password",
     *     operationId="resetPassword",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Yeni şifre belirleme",
     *     description="Kullanıcı, şifre sıfırlama bağlantısındaki token ve e-posta bilgisiyle yeni şifresini belirler.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "token", "password", "password_confirmation"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com", description="Şifresi sıfırlanacak kullanıcının e-posta adresi"),
     *             @OA\Property(property="token", type="string", example="abc123token", description="Şifre sıfırlama bağlantısındaki token"),
     *             @OA\Property(property="password", type="string", format="password", example="entekas123", minLength=8, description="Yeni şifre"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="entekas123", description="Yeni şifre tekrarı")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Şifre başarıyla sıfırlandı.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Şifre başarıyla sıfırlandı."),
     *             @OA\Property(property="data", type="string", example=null)
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Token geçersiz veya süresi dolmuş.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Şifre sıfırlama bağlantısı geçersiz veya süresi dolmuş!"),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Kullanıcı bulunamadı.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Kullanıcı bulunamadı."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Doğrulama hatası.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Doğrulama hatası oluştu."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        $hashedToken = hash('sha256', $request->token);

        $record = PasswordResetToken::where('email', $request->email)
            ->where('token', $hashedToken)
            ->first();

        if (!$record || $record->isExpired()) {
            return $this->errorResponse('Şifre sıfırlama bağlantısı geçersiz veya süresi dolmuş!', self::HTTP_BAD_REQUEST);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return $this->errorResponse('Kullanıcı bulunamadı!', self::HTTP_NOT_FOUND);
        }

        $user->update([
            'password' => Hash::make($request->password),
        ]);

        DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->where('token', $hashedToken)
            ->delete();

        return $this->successResponse(null, 'Şifre başarıyla sıfırlandı.');
    }



    /**
     * @OA\Get(
     *     path="/v1/auth/me",
     *     operationId="authMe",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Giriş yapan kullanıcının bilgilerini getirir.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(response=200, description="Başarılı"),
     *     @OA\Response(response=401, description="Yetkisiz veya token geçersiz")
     * )
     */

    public function me(): \Illuminate\Http\JsonResponse
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return $this->errorResponse('Token geçersiz!', self::HTTP_UNAUTHORIZED);
            }
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return $this->errorResponse('Token süresi dolmuş!', self::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return $this->errorResponse('Token geçersiz!', self::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return $this->errorResponse('Token bulunamadı!', self::HTTP_UNAUTHORIZED);
        }

        return $this->successResponse($user, 'Kullanıcı bilgisi getirildi!', self::HTTP_OK);
    }

    /**
     * @OA\Post(
     *     path="/v1/auth/logout",
     *     operationId="authLogout",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Kullanıcı çıkışı yapar.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(response=200, description="Başarıyla çıkış yapıldı"),
     *     @OA\Response(response=500, description="Çıkış yapılamadı")
     * )
     */

    public function logout(): \Illuminate\Http\JsonResponse
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return $this->successResponse(null, 'Başarıyla çıkış yapıldı!', self::HTTP_OK);
        } catch (\Exception $e) {
            return $this->errorResponse('Çıkış yapılamadı!', self::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/auth/refresh",
     *     operationId="authRefresh",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Token yeniler.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"refresh_token"},
     *             @OA\Property(property="refresh_token", type="string")
     *         )
     *     ),
     *     @OA\Response(response=200, description="Token yenilendi"),
     *     @OA\Response(response=400, description="Refresh token gönderilmedi"),
     *     @OA\Response(response=401, description="Geçersiz refresh token"),
     *     @OA\Response(response=404, description="Kullanıcı bulunamadı")
     * )
     */

    public function refresh(RefreshTokenRequest $request): \Illuminate\Http\JsonResponse
    {
        try {
            $refreshToken = $request->input('refresh_token');

            if (!$refreshToken) {
                return $this->errorResponse('Refresh token gerekli!', self::HTTP_BAD_REQUEST);
            }

            JWTAuth::setToken($refreshToken);
            $user = JWTAuth::authenticate();

            if (!$user) {
                return $this->errorResponse('Kullanıcı bulunamadı!', self::HTTP_NOT_FOUND);
            }

            $newAccessToken = JWTAuth::fromUser($user);
            $newRefreshToken = JWTAuth::claims(['refresh' => true])->fromUser($user);

            return $this->successResponse([
                'access_token' => $newAccessToken,
                'refresh_token' => $newRefreshToken,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60
            ], 'Token yenilendi!', self::HTTP_OK);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return $this->errorResponse('Refresh token süresi dolmuş!', self::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return $this->errorResponse('Geçersiz refresh token!', self::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return $this->errorResponse('Token bulunamadı!', self::HTTP_UNAUTHORIZED);
        }
    }


    /**
     * @OA\Post(
     *     path="/v1/auth/google-login",
     *     operationId="googleLogin",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Google Access Token ile giriş yapar.",
     *     description="Google Access Token ile mevcut kayıtlı kullanıcı giriş yapar. Kullanıcı bulunamazsa hata döner.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"access_token"},
     *             @OA\Property(property="access_token", type="string", example="ya29.a0AfH6SMCQmhz6Xh3P0H...GoogleAccessToken")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Google ile giriş başarılı",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Google ile giriş başarılı!"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="user", type="object",
     *                     @OA\Property(property="id", type="string", format="uuid", example="9eaa92fa-9066-41f2-84cc-bfb248b27d7a"),
     *                     @OA\Property(property="name", type="string", example="User 1"),
     *                     @OA\Property(property="email", type="string", example="user1@entekas.com"),
     *                     @OA\Property(property="phone", type="string", example="0533 123 45 67"),
     *                     @OA\Property(property="avatar", type="string", format="uri", example="https://example.com/avatar.png"),
     *                     @OA\Property(property="authority", type="string", example="customer")
     *                 ),
     *                 @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGci..."),
     *                 @OA\Property(property="refresh_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGci..."),
     *                 @OA\Property(property="token_type", type="string", example="bearer"),
     *                 @OA\Property(property="expires_in", type="integer", example=3600)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Geçersiz Google Access Token",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Google kimlik doğrulaması başarısız oldu."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Hesap devre dışı bırakılmış veya yasaklı",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Hesabınız devre dışı bırakılmış."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Kullanıcı bulunamadı",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Sistemde kayıtlı e-posta bulunamadı, kayıt olunuz."),
     *             @OA\Property(property="errors", type="object",
     *                 @OA\Property(property="reason", type="string", example="user_not_found")
     *             )
     *         )
     *     )
     * )
     */
    public function googleLogin(GoogleLoginRequest $request): \Illuminate\Http\JsonResponse
    {
        $accessToken = $request->access_token;

        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $accessToken,
        ])->get('https://www.googleapis.com/oauth2/v2/userinfo');

        if ($response->failed()) {
            return $this->errorResponse('Google kimlik doğrulaması başarısız oldu.', self::HTTP_UNAUTHORIZED);
        }

        $userInfo = $response->json();

        $user = \App\Models\User::where('google_id', $userInfo['id'])
            ->orWhere('email', $userInfo['email'])
            ->first();

        if (!$user) {
            return $this->errorResponse('Sistemde kayıtlı e-posta bulunamadı, kayıt olunuz.', self::HTTP_NOT_FOUND, [
                'reason' => 'user_not_found'
            ]);
        }

        if (empty($user->google_id)) {
            $user->google_id = $userInfo['id'];
            $user->save();
        }

        if (!$user->active) {
            return $this->errorResponse('Hesabınız devre dışı bırakılmış!', self::HTTP_FORBIDDEN);
        }

        if ($user->banned) {
            return $this->errorResponse('Hesabınız yasaklanmış!', self::HTTP_FORBIDDEN);
        }

        $accessToken = JWTAuth::fromUser($user);
        $refreshToken = JWTAuth::claims(['refresh' => true])->fromUser($user);

        return $this->successResponse([
            'user' => [
                'id' => $user->id,
                'username' => $request->username,
                'firstname' => $request->firstname,
                'lastname' => $request->lastname,
                'email' => $user->email,
                'phone' => $user->phone,
                'avatar' => $user->avatar ?? generate_avatar_url($user->email),
                'authority' => $user->getRoleNames()->first(),
                'cmappsID' => $request->cmappsID,
            ],
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
        ], 'Google ile giriş başarılı!', self::HTTP_OK);
    }



    /**
     * @OA\Post(
     *     path="/v1/auth/2fa/enable",
     *     operationId="enableTwoFactor",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="İki faktörlü kimlik doğrulamasını (2FA) aktif eder.",
     *     description="Kullanıcıdan Google Authenticator kodu ister ve doğrulama başarılı olursa 2FA aktif edilir.",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"code"},
     *             @OA\Property(property="code", type="string", example="123456")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="2FA başarıyla aktif edildi.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="İki faktörlü kimlik doğrulama aktif edildi!"),
     *             @OA\Property(property="data", type="string", example=null)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Geçersiz 2FA kodu",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Geçersiz 2FA kodu."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function enableTwoFactor(EnableTwoFactorRequest $request): \Illuminate\Http\JsonResponse
    {
        $user = JWTAuth::parseToken()->authenticate();
        $google2fa = new Google2FA();

        if (!$user->two_factor_secret) {
            $secret = $google2fa->generateSecretKey();
            $user->two_factor_secret = Crypt::encryptString($secret);
            $user->save();
        } else {
            $secret = Crypt::decryptString($user->two_factor_secret);
        }

        $valid = $google2fa->verifyKey($secret, $request->code);

        if (!$valid) {
            return $this->errorResponse('Geçersiz 2FA kodu!', self::HTTP_UNAUTHORIZED);
        }

        $user->two_factor_enabled = true;
        $user->save();

        return $this->successResponse(null, 'İki faktörlü kimlik doğrulama aktif edildi!');
    }

    /**
     * @OA\Post(
     *     path="/v1/auth/2fa/disable",
     *     operationId="disableTwoFactor",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="İki faktörlü kimlik doğrulamasını (2FA) devre dışı bırakır.",
     *     description="Kullanıcıdan Google Authenticator kodu ister ve doğrulama başarılı olursa 2FA iptal edilir.",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"code"},
     *             @OA\Property(property="code", type="string", example="654321")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="2FA başarıyla devre dışı bırakıldı.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="İki faktörlü kimlik doğrulama başarıyla devre dışı bırakıldı!"),
     *             @OA\Property(property="data", type="string", example=null)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Geçersiz 2FA kodu",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Geçersiz 2FA kodu."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="2FA zaten aktif değil",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="İki faktörlü kimlik doğrulama zaten aktif değil."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function disableTwoFactor(DisableTwoFactorRequest $request): \Illuminate\Http\JsonResponse
    {
        $user = JWTAuth::parseToken()->authenticate();
        $google2fa = new \PragmaRX\Google2FA\Google2FA();

        if (!$user->two_factor_secret) {
            return $this->errorResponse('İki faktörlü kimlik doğrulama zaten aktif değil!', self::HTTP_BAD_REQUEST);
        }

        $secret = Crypt::decryptString($user->two_factor_secret);
        $valid = $google2fa->verifyKey($secret, $request->code);

        if (!$valid) {
            return $this->errorResponse('Geçersiz 2FA kodu!', self::HTTP_UNAUTHORIZED);
        }

        $user->two_factor_enabled = false;
        $user->two_factor_secret = null;
        $user->save();

        return $this->successResponse(null, 'İki faktörlü kimlik doğrulama başarıyla devre dışı bırakıldı!');
    }

    /**
     * @OA\Get(
     *     path="/v1/auth/2fa/qrcode",
     *     operationId="getTwoFactorQrCode",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="2FA için QR kodu ve gizli anahtarı getirir.",
     *     description="Kullanıcının Google Authenticator uygulamasında kullanması için QR kodu ve secret anahtarı döner.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="QR kod ve secret başarıyla getirildi.",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="2FA QR kodu başarıyla oluşturuldu!"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="qr_code", type="string", example="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."),
     *                 @OA\Property(property="secret", type="string", example="JBSWY3DPEHPK3PXP")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Yetkilendirme hatası",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Token bulunamadı."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function getTwoFactorQrCode(): \Illuminate\Http\JsonResponse
    {
        $user = JWTAuth::parseToken()->authenticate();
        $google2fa = new \PragmaRX\Google2FA\Google2FA();

        if (!$user->two_factor_secret) {
            $secret = $google2fa->generateSecretKey();
            $user->two_factor_secret = Crypt::encryptString($secret);
            $user->save();
        } else {
            $secret = Crypt::decryptString($user->two_factor_secret);
        }

        $qrCodeUrl = $google2fa->getQRCodeUrl(
            'CMapps',
            $user->email,
            $secret
        );

        $qrImage = QrCode::format('png')->size(250)->margin(2)->generate($qrCodeUrl);
        $qrImageBase64 = 'data:image/png;base64,' . base64_encode($qrImage);

        return $this->successResponse([
            'qr_code' => $qrImageBase64,
            'secret' => $secret,
        ], '2FA QR kodu başarıyla oluşturuldu!');
    }

    /**
     * @OA\Post(
     *     path="/v1/auth/verify-2fa",
     *     operationId="authVerify2FA",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="2FA kodu doğrulaması yapar ve yeni token ile kullanıcı bilgisi döner.",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"code"},
     *             @OA\Property(property="code", type="string", example="123456")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="2FA doğrulama başarılı",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="2FA doğrulaması başarılı!"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="user", type="object",
     *                     @OA\Property(property="id", type="string", format="uuid", example="9eaa92fa-9066-41f2-84cc-bfb248b27d7a"),
     *                     @OA\Property(property="name", type="string", example="User 1"),
     *                     @OA\Property(property="email", type="string", example="user1@entekas.com"),
     *                     @OA\Property(property="phone", type="string", example="0533 731 89 67"),
     *                     @OA\Property(property="avatar", type="string", format="uri", example="https://www.gravatar.com/avatar/3cb671e3e55b1919b5a0e98a3b9db823?s=200&d=identicon"),
     *                     @OA\Property(property="authority", type="string", example="admin")
     *                 ),
     *                 @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGci..."),
     *                 @OA\Property(property="token_type", type="string", example="bearer"),
     *                 @OA\Property(property="expires_in", type="integer", example=3600)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Geçersiz kod",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Kod doğrulanamadı!")
     *         )
     *     )
     * )
     */
    public function verifyTwoFactor(VerifyTwoFactorRequest $request): JsonResponse
    {
        $user = JWTAuth::parseToken()->authenticate();

        if (!$user || !$user->two_factor_secret) {
            return $this->errorResponse('İki faktörlü doğrulama aktif değil!', self::HTTP_UNAUTHORIZED);
        }

        $google2fa = new Google2FA();
        $secret = Crypt::decryptString($user->two_factor_secret);

        $valid = $google2fa->verifyKey($secret, $request->code);

        if (!$valid) {
            return $this->errorResponse('Geçersiz doğrulama kodu!', self::HTTP_UNAUTHORIZED);
        }

        $newAccessToken = JWTAuth::fromUser($user);

        return $this->successResponse([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'phone' => $user->phone,
                'avatar' => generate_avatar_url($user->email),
                'authority' => $user->getRoleNames()->first(),
                'two_factor_enabled' => false,
            ],
            'access_token' => $newAccessToken,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
        ], '2FA doğrulaması başarılı!', self::HTTP_OK);
    }

    /**
     * @OA\Post(
     *     path="/v1/auth/integration-login",
     *     operationId="integrationLogin",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="x-api-key ve x-api-secret ile access_token alır (ek entegrasyonlar için).",
     *     description="Belirlenen API key ve API secret ile access_token üretir. Giriş yapmaya gerek yoktur. Banlı veya kapalı hesaplar token alamaz.",
     *     @OA\Parameter(
     *         name="x-api-key",
     *         in="header",
     *         required=true,
     *         description="Kullanıcının API anahtarı",
     *         @OA\Schema(type="string", example="AbCdEfGh1234567890")
     *     ),
     *     @OA\Parameter(
     *         name="x-api-secret",
     *         in="header",
     *         required=true,
     *         description="Kullanıcının API secret anahtarı",
     *         @OA\Schema(type="string", example="s3cr3tK3y9876543210")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Access token başarıyla üretildi.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="token_type", type="string", example="bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=3600)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Geçersiz API bilgileri (key veya secret hatalı).",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Geçersiz API bilgileri."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Kullanıcı hesabı devre dışı bırakılmış veya yasaklanmış.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Hesabınız devre dışı bırakılmış."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function integrationLogin(): JsonResponse
    {
        $apiKey = request()->header('x-api-key');
        $apiSecret = request()->header('x-api-secret');

        if (!$apiKey || !$apiSecret) {
            return $this->errorResponse('API anahtarı ve secret zorunludur.', self::HTTP_UNAUTHORIZED);
        }

        $user = User::where('api_key', $apiKey)
            ->where('api_secret', $apiSecret)
            ->first();

        if (!$user) {
            return $this->errorResponse('Geçersiz API bilgileri.', self::HTTP_UNAUTHORIZED);
        }

        if (!$user->active) {
            return $this->errorResponse('Hesabınız devre dışı bırakılmış.', self::HTTP_FORBIDDEN, [
                'reason' => 'Hesabınız devre dışı bırakılmış.'
            ]);
        }

        if ($user->banned) {
            return $this->errorResponse('Hesabınız yasaklanmış.', self::HTTP_FORBIDDEN, [
                'reason' => 'Hesabınız yasaklanmış.'
            ]);
        }

        $accessToken = JWTAuth::fromUser($user);

        return $this->successResponse([
            'access_token' => $accessToken,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 1200
        ], 'Access token başarıyla oluşturuldu!', self::HTTP_OK);
    }



    /**
     * @OA\Post(
     *     path="/v1/auth/api-credentials",
     *     operationId="generateApiCredentials",
     *     tags={"Kimlik Doğrulama İşlemleri"},
     *     summary="Giriş yapan kullanıcı için yeni API Key ve Secret üretir.",
     *     description="Bu endpoint, JWT token ile kimlik doğrulaması yapılmış kullanıcıya yeni bir API Key ve Secret üretir.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="API Key ve Secret başarıyla üretildi.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="api_key", type="string", example="8f5a8d3b7f5c4e12b9b1c5a9d2e8f3c7"),
     *                 @OA\Property(property="api_secret", type="string", example="f4e8d3b7c5a9d2e8f3c78f5a8d3b7f5c4e12b9b1c5a9d2e8f3c78f5a")
     *             ),
     *             @OA\Property(property="message", type="string", example="API Key ve Secret başarıyla oluşturuldu!")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Yetkisiz erişim.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Kullanıcı bulunamadı!")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Sunucu hatası.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="API bilgileri üretilirken hata oluştu."),
     *             @OA\Property(property="error", type="string", example="Exception mesajı")
     *         )
     *     )
     * )
     */
    public function generateApiCredentials(): JsonResponse
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return $this->errorResponse('Kullanıcı bulunamadı!', self::HTTP_UNAUTHORIZED);
            }

            $user->api_key = Str::random(32);
            $user->api_secret = Str::random(64);
            $user->save();

            return $this->successResponse([
                'api_key' => $user->api_key,
                'api_secret' => $user->api_secret,
            ], 'API Key ve Secret başarıyla oluşturuldu!', self::HTTP_OK);
        } catch (\Exception $e) {
            return $this->errorResponse('API bilgileri üretilirken hata oluştu.', self::HTTP_INTERNAL_SERVER_ERROR, [
                'error' => $e->getMessage()
            ]);
        }
    }
}
