<?php

declare(strict_types=1);

namespace G\Csrf\Middleware;

#[\Attribute(\Attribute::TARGET_CLASS)]
final class CsrfConfig
{
    /**
     * @param string       $tokenKeyAttribute PSR-7 request attribute name carrying the CSRF key
     * @param string       $tokenField        POST body field name
     * @param list<string> $tokenHeaders      HTTP header names checked in order
     * @param list<string> $supervisedMethods HTTP methods that require CSRF validation
     */
    public function __construct(
        public readonly string $tokenKeyAttribute = CsrfMiddleware::TOKEN_KEY_ATTRIBUTE,
        public readonly string $tokenField = '_token',
        public readonly array $tokenHeaders = ['X-CSRF-Token', 'X-XSRF-Token'],
        public readonly array $supervisedMethods = ['POST', 'PUT', 'PATCH', 'DELETE'],
    ) {
    }
}
