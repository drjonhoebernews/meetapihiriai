<?php

namespace App\Http\Controllers;

use OpenApi\Annotations as OA;

/**
 * @OA\Info(
 *      version="1.0.0",
 *      title="HiriBot HR API",
 *      description="HiriBot İK (HRIS) platformunun REST API'si. Çalışan yönetimi, izin & devamsızlık, bordro, işe alım, toplantı planlama/kayıt ve denetim logları gibi modüller için güvenli entegrasyon sağlar.",
 *      @OA\Contact(
 *          email="support@hiri.ai",
 *          name="HiriBot API Destek"
 *      ),
 *      @OA\License(
 *          name="HiriBot Proprietary License",
 *          url="https://hiri.ai/legal/api-license"
 *      )
 * )
 *
 * @OA\Server(
 *      url="https://meetapi.test/api",
 *      description="Prod API Sunucusu"
 * )
 * @OA\Server(
 *      url="https://staging.hiribot.hiri.ai/api",
 *      description="Staging API Sunucusu"
 * )
 * @OA\Server(
 *      url="http://hiribot.local/api",
 *      description="Yerel Geliştirme Sunucusu"
 * )
 *
 * @OA\SecurityScheme(
 *     securityScheme="bearerAuth",
 *     type="http",
 *     scheme="bearer",
 *     bearerFormat="Sanctum/JWT",
 *     description="Bearer token ile yetkilendirme. Örn: 'Authorization: Bearer {token}'"
 * )
 *
 * @OA\SecurityScheme(
 *     securityScheme="apiKeyAuth",
 *     type="apiKey",
 *     in="header",
 *     name="X-API-KEY",
 *     description="Proje düzeyi API anahtarı. Tüm isteklerde 'X-API-KEY' başlığı gerektirir."
 * )
 *
 * @OA\Tag(
 *     name="Auth",
 *     description="Kimlik doğrulama ve yetkilendirme uçları."
 * )
 * @OA\Tag(
 *     name="Employees",
 *     description="Çalışan kartları, roller, departmanlar."
 * )
 * @OA\Tag(
 *     name="Attendance",
 *     description="Giriş-çıkış, vardiya, devamsızlık."
 * )
 * @OA\Tag(
 *     name="Leave",
 *     description="İzin talepleri, onay akışları."
 * )
 * @OA\Tag(
 *     name="Recruitment",
 *     description="Aday, ilan, mülakat süreçleri."
 * )
 * @OA\Tag(
 *     name="Meetings",
 *     description="Toplantı planlama, kayıt & log yönetimi."
 * )
 * @OA\Tag(
 *     name="Records",
 *     description="Denetim (audit) logları ve raporlama."
 * )
 */
abstract class Controller
{
    //
}
