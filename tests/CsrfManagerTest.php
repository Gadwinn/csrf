<?php

declare(strict_types=1);

namespace G\Csrf\Tests;

use G\Csrf\CsrfManager;
use G\Csrf\TokenGenerator\RandomTokenGenerator;
use G\Csrf\TokenStorage\SessionTokenStorage;
use PHPUnit\Framework\TestCase;

class CsrfManagerTest extends TestCase
{
    private CsrfManager $csrf;
    private SessionTokenStorage $storage;

    protected function setUp(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $_SESSION = [];

        $generator = new RandomTokenGenerator();
        $this->storage = new SessionTokenStorage();
        $this->csrf = new CsrfManager($generator, $this->storage);
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
    }

    public function testGenerateTokenCreatesValidToken(): void
    {
        $token = $this->csrf->generateToken();

        $this->assertIsString($token);
        $this->assertSame(32, strlen($token));
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);
    }

    public function testGenerateTokenWithKey(): void
    {
        $token = $this->csrf->generateToken('my-form');

        $this->assertIsString($token);
        $this->assertTrue($this->storage->hasToken($token, 'my-form'));
    }

    public function testIsValidReturnsTrueForValidToken(): void
    {
        $token = $this->csrf->generateToken('test-form');

        $this->assertTrue($this->csrf->isValid($token, 'test-form'));
    }

    public function testIsValidReturnsFalseForInvalidToken(): void
    {
        $this->assertFalse($this->csrf->isValid('invalid-token', 'test-form'));
    }

    public function testIsValidDestroysTokenAfterValidation(): void
    {
        $token = $this->csrf->generateToken('consume-form');

        $this->assertTrue($this->csrf->isValid($token, 'consume-form'));
        $this->assertFalse($this->csrf->isValid($token, 'consume-form')); // Should fail second time
    }

    public function testIsValidWithNullKey(): void
    {
        $token = $this->csrf->generateToken();

        $this->assertTrue($this->csrf->isValid($token));
        $this->assertFalse($this->csrf->isValid($token)); // Should be consumed
    }

    public function testIsValidWithStackKey(): void
    {
        $token1 = $this->csrf->generateToken('stack-form[]');
        $token2 = $this->csrf->generateToken('stack-form[]');

        $this->assertTrue($this->csrf->isValid($token1, 'stack-form[]'));
        $this->assertTrue($this->csrf->isValid($token2, 'stack-form[]'));

        // Both tokens should be consumed
        $this->assertFalse($this->csrf->isValid($token1, 'stack-form[]'));
    }

    public function testGetTokenReturnsToken(): void
    {
        $generatedToken = $this->csrf->generateToken('retrieve-form');
        $retrievedToken = $this->csrf->getToken('retrieve-form');

        $this->assertSame($generatedToken, $retrievedToken);
    }

    public function testGetTokenReturnsNullForNonExistingKey(): void
    {
        $token = $this->csrf->getToken('non-existing-form');

        $this->assertNull($token);
    }

    public function testTokenValidationIsAtomic(): void
    {
        $token = $this->csrf->generateToken('atomic-form');

        // First validation should succeed and consume the token
        $firstResult = $this->csrf->isValid($token, 'atomic-form');

        // Second validation should fail because token was consumed
        $secondResult = $this->csrf->isValid($token, 'atomic-form');

        $this->assertTrue($firstResult);
        $this->assertFalse($secondResult);
    }

    public function testMultipleTokensWithSameKey(): void
    {
        $token1 = $this->csrf->generateToken('multi-form');
        $token2 = $this->csrf->generateToken('multi-form');

        // Second token should overwrite the first
        $this->assertSame($token2, $this->csrf->getToken('multi-form'));
        $this->assertFalse($this->csrf->isValid($token1, 'multi-form'));
        $this->assertTrue($this->csrf->isValid($token2, 'multi-form'));
    }

    public function testStackBehaviorWithCsrfManager(): void
    {
        // Generate multiple tokens for the same stack key
        $tokens = [];
        for ($i = 0; $i < 5; $i++) {
            $tokens[] = $this->csrf->generateToken('stack-key[]');
        }

        // All tokens should be valid initially
        foreach ($tokens as $token) {
            $this->assertTrue($this->csrf->isValid($token, 'stack-key[]'));
        }

        // After consuming all tokens, they should all be invalid
        foreach ($tokens as $token) {
            $this->assertFalse($this->csrf->isValid($token, 'stack-key[]'));
        }
    }

    public function testTokenGenerationWithDifferentKeys(): void
    {
        $token1 = $this->csrf->generateToken('form-1');
        $token2 = $this->csrf->generateToken('form-2');

        $this->assertNotSame($token1, $token2);
        $this->assertTrue($this->csrf->isValid($token1, 'form-1'));
        $this->assertTrue($this->csrf->isValid($token2, 'form-2'));
    }

    public function testExplicitStackLimit(): void
    {
        // Create tokens with explicit limit of 3
        $tokens = [];
        for ($i = 0; $i < 5; $i++) {
            $tokens[] = $this->csrf->generateToken('limited[3]');
        }

        // Only the 3 most recent tokens should be valid
        $this->assertFalse($this->csrf->isValid($tokens[0], 'limited[3]'));
        $this->assertTrue($this->csrf->isValid($tokens[2], 'limited[3]'));
        $this->assertTrue($this->csrf->isValid($tokens[3], 'limited[3]'));
        $this->assertTrue($this->csrf->isValid($tokens[4], 'limited[3]'));
        $this->assertFalse($this->csrf->isValid($tokens[1], 'limited[3]'));
    }
}
