<?php

declare(strict_types=1);

namespace G\Csrf\TokenGenerator;

interface TokenGeneratorInterface
{
    public function generate(): string;
}
