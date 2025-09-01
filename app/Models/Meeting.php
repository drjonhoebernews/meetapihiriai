<?php

namespace App\Models;

use App\Traits\HasUuid;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Meeting extends Model
{
    use SoftDeletes;
    use HasUuid;

    protected $table = 'meetings';

    public $incrementing = false;
    protected $keyType   = 'string';

    protected $fillable = [
        'link',
        'type',
        'start_at',
        'end_at',
        'record_path',
        'log',
    ];

    protected $casts = [
        'start_at'   => 'datetime',
        'end_at'     => 'datetime',
        'log'        => 'array',
    ];

    public const TYPE_MEET  = 'meet';
    public const TYPE_TEAMS = 'teams';
    public const TYPE_ZOOM  = 'zoom';
}
