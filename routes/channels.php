<?php

use Illuminate\Support\Facades\Broadcast;

Broadcast::channel('presence-users.{anything}', function ($user, $anything) {
    logger('🔥 WILDCARD CHANNEL tetiklendi', ['user' => $user?->email, 'sub' => $anything]);

    return [
        'id' => (string) $user->id,
        'name' => $user->name,
        'email' => $user->email,
    ];
});

Broadcast::channel('presence-app-users', function ($user) {
    logger('🟢 AUTH DENEMESİ', ['user' => $user?->email]);
    return [
        'id' => (string) $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->getRoleNames()->first(),
        'avatar' => $user->avatar,
    ];
});
