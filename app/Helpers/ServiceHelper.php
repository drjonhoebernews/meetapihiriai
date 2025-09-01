<?php

function generate_avatar_url(string $seed, string $style = 'micah'): string
{
    {
        $encoded = urlencode($seed);
        return "https://api.dicebear.com/6.x/{$style}/svg?seed={$encoded}";
    }
}


if (!function_exists('generate_cmappsID')) {
    function generate_cmappsID(): string
    {
        $prefix = 'CM';
        $random = strtoupper(substr(md5(uniqid(rand(), true)), 0, 5));

        return "{$prefix}{$random}";
    }
}
