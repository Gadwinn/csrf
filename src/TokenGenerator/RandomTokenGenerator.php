<?php

declare(strict_types=1);

namespace G\Csrf\TokenGenerator;

class RandomTokenGenerator implements TokenGeneratorInterface
{
    /** Minimum token length, in hexadecimal characters (128 bits of entropy). */
    public const int MIN_LENGTH = 32;

    /**
     * @param int $length Token length, in hexadecimal characters
     *
     * @throws \InvalidArgumentException When the length is below MIN_LENGTH
     */
    public function __construct(
        private readonly int $length = self::MIN_LENGTH
    ) {
        if ($length < self::MIN_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf('Token length must be at least %d characters, %d given.', self::MIN_LENGTH, $length)
            );
        }
    }

    public function generate(): string
    {
        $bytes = max(1, (int) ceil($this->length / intval(2)));

        return substr(bin2hex(random_bytes($bytes)), 0, $this->length);
    }
}
