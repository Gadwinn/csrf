<?php

declare(strict_types=1);

namespace G\Csrf\Tests;

/**
 * Makes stored tokens older without waiting: avoids sleep() in the tests.
 */
trait ExpiresTokensTrait
{
    private function ageTokens(int $seconds, string $sessionKey = '_csrf_tokens'): void
    {
        array_walk_recursive($_SESSION[$sessionKey], static function (mixed &$value, int|string $key) use ($seconds): void {
            if ($key === 'expires_at') {
                $value -= $seconds;
            }
        });
    }
}
