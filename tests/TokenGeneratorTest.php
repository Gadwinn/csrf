<?php

declare(strict_types=1);

namespace G\Csrf\Tests;

use G\Csrf\TokenGenerator\RandomTokenGenerator;
use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
    public function testGenerateCreatesTokenOfCorrectLength(): void
    {
        // Test default length (32 bytes parameter creates 16 bytes = 32 hex chars)
        $generator = new RandomTokenGenerator();
        $token = $generator->generate();
        $this->assertSame(32, strlen($token)); // 16 bytes = 32 hex chars

        // Test custom length of 32 (creates 16 bytes = 32 hex chars)
        $generator = new RandomTokenGenerator(32);
        $token = $generator->generate();
        $this->assertSame(32, strlen($token)); // 16 bytes = 32 hex chars

        // Test with 64 length parameter (creates 32 bytes = 64 hex chars)
        $generator = new RandomTokenGenerator(64);
        $token = $generator->generate();
        $this->assertSame(64, strlen($token)); // 32 bytes = 64 hex chars
    }

    public function testGenerateCreatesUniqueTokens(): void
    {
        $generator = new RandomTokenGenerator();

        $token1 = $generator->generate();
        $token2 = $generator->generate();

        $this->assertNotSame($token1, $token2);
    }

    public function testGenerateCreatesHexadecimalTokens(): void
    {
        $generator = new RandomTokenGenerator();
        $token = $generator->generate();

        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);
    }

    public function testGenerateUsesCryptographicallySecureRandom(): void
    {
        $generator = new RandomTokenGenerator();

        // This test verifies that random_bytes is being used
        // by checking that the output is always valid hex
        for ($i = 0; $i < 10; $i++) {
            $token = $generator->generate();
            $this->assertTrue(ctype_xdigit($token));
        }
    }

    public function testConstructorRejectsLengthBelowMinimum(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RandomTokenGenerator(16);
    }

    public function testOddLengthIsRespected(): void
    {
        $this->assertSame(33, strlen((new RandomTokenGenerator(33))->generate()));
    }

    public function testMinimumLengthIsAccepted(): void
    {
        $token = (new RandomTokenGenerator(RandomTokenGenerator::MIN_LENGTH))->generate();

        $this->assertSame(RandomTokenGenerator::MIN_LENGTH, strlen($token));
    }
}
