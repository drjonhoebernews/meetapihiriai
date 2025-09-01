<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Meeting;
use Illuminate\Http\JsonResponse;
use App\Http\Requests\Api\StoreMeetingRequest;
use App\Http\Requests\Api\UpdateMeetingRequest;
use OpenApi\Annotations as OA;

/**
 * @OA\Schema(
 *   schema="Meeting",
 *   type="object",
 *   required={"id","link","type","start_at","created_at","updated_at"},
 *   properties={
 *     @OA\Property(property="id", type="string", format="uuid", example="7d3c1c7e-02aa-4a4d-bb13-6a6c1a3f4c1a"),
 *     @OA\Property(property="link", type="string", format="uri", maxLength=1024, example="https://meet.google.com/abc-defg-hij"),
 *     @OA\Property(property="type", type="string", enum={"meet","teams","zoom"}, example="meet"),
 *     @OA\Property(property="start_at", type="string", format="date-time", example="2025-09-01T12:00:00Z"),
 *     @OA\Property(property="end_at", type="string", format="date-time", nullable=true, example="2025-09-01T13:00:00Z"),
 *     @OA\Property(property="record_path", type="string", nullable=true, maxLength=2048, example="/records/2025/09/01/abc123.mp4"),
 *     @OA\Property(property="log", type="object", nullable=true, example={"scheduled_by":"a8c2...","status":"queued"}),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time"),
 *     @OA\Property(property="deleted_at", type="string", format="date-time", nullable=true)
 *   }
 * )
 *
 * @OA\Schema(
 *   schema="MeetingInput",
 *   type="object",
 *   required={"link","type","start_at"},
 *   properties={
 *     @OA\Property(property="link", type="string", format="uri", maxLength=1024, example="https://meet.google.com/abc-defg-hij"),
 *     @OA\Property(property="type", type="string", enum={"meet","teams","zoom"}, example="teams"),
 *     @OA\Property(property="start_at", type="string", format="date-time", example="2025-09-01T12:00:00Z"),
 *     @OA\Property(property="end_at", type="string", format="date-time", nullable=true, example="2025-09-01T13:30:00Z"),
 *     @OA\Property(property="record_path", type="string", nullable=true, maxLength=2048, example="https://cdn.hiribot.hiri.ai/recs/abc.mp4"),
 *     @OA\Property(property="log", type="object", nullable=true, example={"agent":"recorder-1","priority":5})
 *   }
 * )
 *
 * @OA\Schema(
 *   schema="ValidationError",
 *   type="object",
 *   properties={
 *     @OA\Property(property="message", type="string", example="The given data was invalid."),
 *     @OA\Property(
 *       property="errors",
 *       type="object",
 *       additionalProperties=@OA\Schema(type="array", @OA\Items(type="string")),
 *       example={"link":{"The link field must be a valid URL."}}
 *     )
 *   }
 * )
 *
 * @OA\Schema(
 *   schema="MeetingPage",
 *   type="object",
 *   properties={
 *     @OA\Property(property="current_page", type="integer", example=1),
 *     @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/Meeting")),
 *     @OA\Property(property="first_page_url", type="string"),
 *     @OA\Property(property="from", type="integer", nullable=true),
 *     @OA\Property(property="last_page", type="integer"),
 *     @OA\Property(property="last_page_url", type="string"),
 *     @OA\Property(property="links", type="array", @OA\Items(type="object")),
 *     @OA\Property(property="next_page_url", type="string", nullable=true),
 *     @OA\Property(property="path", type="string"),
 *     @OA\Property(property="per_page", type="integer", example=15),
 *     @OA\Property(property="prev_page_url", type="string", nullable=true),
 *     @OA\Property(property="to", type="integer", nullable=true),
 *     @OA\Property(property="total", type="integer", example=42)
 *   }
 * )
 */
class MeetingController extends Controller
{
    /**
     * @OA\Get(
     *   path="/v1/meetings",
     *   summary="Toplantıları listele (sayfalı)",
     *   description="Meeting kayıtlarını sayfalı olarak döner.",
     *   operationId="meetingsIndex",
     *   tags={"Meetings"},
     *   security={{"bearerAuth":{}},{"apiKeyAuth":{}}},
     *   @OA\Parameter(
     *     name="page", in="query", required=false, description="Sayfa numarası",
     *     @OA\Schema(type="integer", minimum=1, example=1)
     *   ),
     *   @OA\Parameter(
     *     name="per_page", in="query", required=false, description="Sayfa başı kayıt",
     *     @OA\Schema(type="integer", minimum=1, maximum=100, example=15)
     *   ),
     *   @OA\Response(
     *     response=200, description="OK",
     *     @OA\JsonContent(ref="#/components/schemas/MeetingPage")
     *   )
     * )
     */
    public function index(): JsonResponse
    {
        $perPage  = (int) request('per_page', 15);
        $perPage  = $perPage > 0 && $perPage <= 100 ? $perPage : 15;
        $meetings = Meeting::latest()->paginate($perPage);

        return response()->json($meetings);
    }

    /**
     * @OA\Get(
     *   path="/v1/meetings/{id}",
     *   summary="Tek toplantıyı getir",
     *   operationId="meetingsShow",
     *   tags={"Meetings"},
     *   security={{"bearerAuth":{}},{"apiKeyAuth":{}}},
     *   @OA\Parameter(
     *     name="id", in="path", required=true, description="Meeting UUID",
     *     @OA\Schema(type="string", format="uuid")
     *   ),
     *   @OA\Response(response=200, description="OK", @OA\JsonContent(ref="#/components/schemas/Meeting")),
     *   @OA\Response(response=404, description="Bulunamadı")
     * )
     */
    public function show(string $id): JsonResponse
    {
        $meeting = Meeting::findOrFail($id);
        return response()->json($meeting);
    }

    /**
     * @OA\Post(
     *   path="/v1/meetings",
     *   summary="Toplantı oluştur",
     *   operationId="meetingsStore",
     *   tags={"Meetings"},
     *   security={{"bearerAuth":{}},{"apiKeyAuth":{}}},
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(ref="#/components/schemas/MeetingInput")
     *   ),
     *   @OA\Response(response=201, description="Oluşturuldu", @OA\JsonContent(ref="#/components/schemas/Meeting")),
     *   @OA\Response(response=422, description="Doğrulama Hatası", @OA\JsonContent(ref="#/components/schemas/ValidationError")))
     * )
     */
    public function store(StoreMeetingRequest $request): JsonResponse
    {
        $meeting = Meeting::create($request->validated());
        return response()->json($meeting, 201);
    }

    /**
     * @OA\Put(
     *   path="/v1/meetings/{id}",
     *   summary="Toplantıyı güncelle",
     *   operationId="meetingsUpdate",
     *   tags={"Meetings"},
     *   security={{"bearerAuth":{}},{"apiKeyAuth":{}}},
     *   @OA\Parameter(
     *     name="id", in="path", required=true, description="Meeting UUID",
     *     @OA\Schema(type="string", format="uuid")
     *   ),
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(ref="#/components/schemas/MeetingInput")
     *   ),
     *   @OA\Response(response=200, description="Güncellendi", @OA\JsonContent(ref="#/components/schemas/Meeting")),
     *   @OA\Response(response=404, description="Bulunamadı"),
     *   @OA\Response(response=422, description="Doğrulama Hatası", @OA\JsonContent(ref="#/components/schemas/ValidationError")))
     * )
     */
    public function update(UpdateMeetingRequest $request, string $id): JsonResponse
    {
        $meeting = Meeting::findOrFail($id);
        $meeting->update($request->validated());
        return response()->json($meeting);
    }

    /**
     * @OA\Delete(
     *   path="/v1/meetings/{id}",
     *   summary="Toplantıyı sil",
     *   description="Soft delete uygular.",
     *   operationId="meetingsDestroy",
     *   tags={"Meetings"},
     *   security={{"bearerAuth":{}},{"apiKeyAuth":{}}},
     *   @OA\Parameter(
     *     name="id", in="path", required=true, description="Meeting UUID",
     *     @OA\Schema(type="string", format="uuid")
     *   ),
     *   @OA\Response(response=200, description="Silindi", @OA\JsonContent(
     *     type="object",
     *     example={"message":"Silindi."},
     *     @OA\Property(property="message", type="string")
     *   )),
     *   @OA\Response(response=404, description="Bulunamadı")
     * )
     */
    public function destroy(string $id): JsonResponse
    {
        $meeting = Meeting::findOrFail($id);
        $meeting->delete();
        return response()->json(['message' => 'Silindi.']);
    }
}
