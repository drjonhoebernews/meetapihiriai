<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'token' => env('POSTMARK_TOKEN'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    'vapi' => [
        'token' => env('VAPI_API_TOKEN'),
        'default_phone_number_id' => env('VAPI_PHONE_ID'),
        'default_assistant_id' => env('VAPI_ASSISTANT_ID'),
    ],

    'recaptcha' => [
        'key' => env('RECAPTCHA_SITE_KEY'),
        'secret' => env('RECAPTCHA_SECRET_KEY'),
        'min_score' => 0.5,
    ],

    'netgsm' => [
        'username' => env('NETGSM_USERNAME'),
        'password' => env('NETGSM_PASSWORD'),
        'sender'   => env('NETGSM_SENDER'),
        'url'      => 'https://api.netgsm.com.tr/sms/rest/v2/send',
    ],

    'openai' => [
        'key' => env('OPENAI_API_KEY'),
    ],
];
