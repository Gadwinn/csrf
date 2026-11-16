<?php

declare(strict_types=1);

namespace G\Csrf;

interface CsrfManagerInterface
{
    /**
     * Generate a CSRF token.
     *
     * @param null|string $key
     * @return string
     */
    public function generateToken(?string $key = null): string;

    /**
     * Get a CSRF token.
     *
     * @param null|string $key
     * @return string|null
     */
    public function getToken(?string $key = null): ?string;

    /**
     * Validate a CSRF token.
     *
     * @param string $token
     * @param null|string $key
     * @return bool
     */
    public function isValid(string $token, ?string $key = null): bool;
}
