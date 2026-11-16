<?php

declare(strict_types=1);

namespace G\Csrf;

use G\Csrf\TokenGenerator\TokenGeneratorInterface;
use G\Csrf\TokenStorage\TokenStorageInterface;

class CsrfManager implements CsrfManagerInterface
{
    public function __construct(
        private readonly TokenGeneratorInterface $generator,
        private readonly TokenStorageInterface $storage
    ) { //
    }

    public function generateToken(?string $key = null): string
    {
        $token = $this->generator->generate();
        $this->storage->setToken($token, $key);
        return $token;
    }

    public function getToken(?string $key = null): ?string
    {
        return $this->storage->getToken($key);
    }

    public function isValid(string $token, ?string $key = null): bool
    {
        return $this->storage->consumeToken($token, $key);
    }
}
