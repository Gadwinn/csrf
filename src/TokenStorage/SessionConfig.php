<?php

declare(strict_types=1);

namespace G\Csrf\TokenStorage;

/**
 * @phpstan-type SameSite 'Lax'|'lax'|'None'|'none'|'Strict'|'strict'
 *
 * Attribute to configure SessionTokenStorage via subclassing.
 *
 * Storage keys and session settings are applied before session_start(),
 * only when the session is not yet active.
 *
 * Usage:
 *
 *   #[SessionConfig(
 *       name: '__Secure-app',
 *       savePath: '/var/lib/php/sessions/myapp',
 *       cookieSecure: true,
 *       cookieHttponly: true,
 *       cookieSamesite: 'Strict',
 *   )]
 *   class AppSessionStorage extends SessionTokenStorage {}
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
final class SessionConfig
{
    /**
     * @param string|null $sessionKey $_SESSION key used to store all CSRF tokens
     * @param string|null $defaultKey Key used when no named key is provided
     * @param string|null $name session_name()
     * @param string|null $savePath session_save_path()
     * @param string|null $moduleName session_module_name()
     * @param string|null $cacheLimiter session_cache_limiter()
     * @param int|null $cacheExpire session_cache_expire() in minutes
     * @param int|null $cookieLifetime Cookie lifetime in seconds (0 = session cookie)
     * @param string|null $cookiePath Cookie path
     * @param string|null $cookieDomain Cookie domain
     * @param bool|null $cookieSecure HTTPS only
     * @param bool|null $cookieHttponly Inaccessible via JavaScript
     * @phpstan-param SameSite|null $cookieSamesite
     * @param string|null $cookieSamesite 'None', 'Lax', or 'Strict'
     */
    public function __construct(
        public readonly ?string $sessionKey = null,
        public readonly ?string $defaultKey = null,
        public readonly ?string $name = null,
        public readonly ?string $savePath = null,
        public readonly ?string $moduleName = null,
        public readonly ?string $cacheLimiter = null,
        public readonly ?int $cacheExpire = null,
        public readonly ?int $cookieLifetime = null,
        public readonly ?string $cookiePath = null,
        public readonly ?string $cookieDomain = null,
        public readonly ?bool $cookieSecure = null,
        public readonly ?bool $cookieHttponly = null,
        /** @phpstan-var SameSite|null */
        public readonly ?string $cookieSamesite = null,
    ) { //
    }
}
