<?php

declare(strict_types=1);

namespace G\Csrf\Tests;

use G\Csrf\CsrfManager;
use G\Csrf\TokenGenerator\RandomTokenGenerator;
use G\Csrf\TokenStorage\SessionTokenStorage;
use PHPUnit\Framework\TestCase;

class IntegrationTest extends TestCase
{
    use ExpiresTokensTrait;

    private CsrfManager $csrf;

    protected function setUp(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $_SESSION = [];

        $generator = new RandomTokenGenerator();
        $storage = new SessionTokenStorage();
        $this->csrf = new CsrfManager($generator, $storage);
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
    }

    public function testCompleteCsrfWorkflow(): void
    {
        // Simulate a complete CSRF protection workflow

        // 1. Generate token for a login form
        $loginToken = $this->csrf->generateToken('login_form');

        // 2. Verify token exists in storage
        $this->assertNotNull($this->csrf->getToken('login_form'));

        // 3. Validate the token (simulating form submission)
        $this->assertTrue($this->csrf->isValid($loginToken, 'login_form'));

        // 4. Verify token was consumed
        $this->assertFalse($this->csrf->isValid($loginToken, 'login_form'));
    }

    public function testMultiTabScenario(): void
    {
        // Simulate multiple tabs with the same form

        // Tab 1: Generate token
        $token1 = $this->csrf->generateToken('search_form[]');

        // Tab 2: Generate another token (should be stacked)
        $token2 = $this->csrf->generateToken('search_form[]');

        // Both tokens should be valid
        $this->assertTrue($this->csrf->isValid($token1, 'search_form[]'));
        $this->assertTrue($this->csrf->isValid($token2, 'search_form[]'));

        // Generate a third token
        $token3 = $this->csrf->generateToken('search_form[]');

        // All three should still be valid (within default limit)
        $this->assertTrue($this->csrf->isValid($token3, 'search_form[]'));
    }

    public function testTokenExpirationInWorkflow(): void
    {
        // Create storage with short TTL for testing
        $generator = new RandomTokenGenerator();
        $storage = new SessionTokenStorage(defaultMaxTokens: 10, ttl: 1); // 1 second TTL
        $csrf = new CsrfManager($generator, $storage);

        $token = $csrf->generateToken('expire_form');

        // Token should be valid immediately
        $this->assertTrue($csrf->isValid($token, 'expire_form'));

        $this->ageTokens(2);

        // New token generation should work
        $newToken = $csrf->generateToken('expire_form');
        $this->assertTrue($csrf->isValid($newToken, 'expire_form'));
    }

    public function testComplexFormScenario(): void
    {
        // Simulate a complex application with multiple forms

        // User profile form
        $profileToken = $this->csrf->generateToken('profile_form');

        // Settings form
        $settingsToken = $this->csrf->generateToken('settings_form');

        // Password change form (more secure, single use)
        $passwordToken = $this->csrf->generateToken('password_form');

        // All tokens should be valid initially
        $this->assertTrue($this->csrf->isValid($profileToken, 'profile_form'));
        $this->assertTrue($this->csrf->isValid($settingsToken, 'settings_form'));
        $this->assertTrue($this->csrf->isValid($passwordToken, 'password_form'));

        // After validation, tokens should be consumed
        $this->assertFalse($this->csrf->isValid($profileToken, 'profile_form'));
        $this->assertFalse($this->csrf->isValid($settingsToken, 'settings_form'));
        $this->assertFalse($this->csrf->isValid($passwordToken, 'password_form'));
    }

    public function testSecurityFeatures(): void
    {
        // Test that tokens are properly secured

        $token = $this->csrf->generateToken('secure_form');

        // Token should be hexadecimal
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);

        // Token should be of correct length (32 chars for 16-byte token)
        $this->assertSame(32, strlen($token));

        // Invalid token should not pass validation
        $this->assertFalse($this->csrf->isValid('invalid-token', 'secure_form'));
        $this->assertFalse($this->csrf->isValid('', 'secure_form'));
        $this->assertFalse($this->csrf->isValid('a', 'secure_form'));
    }

    public function testSessionIsolation(): void
    {
        // Verify that tokens are properly isolated in session

        $token1 = $this->csrf->generateToken('form1');
        $token2 = $this->csrf->generateToken('form2');

        // Tokens should be different
        $this->assertNotSame($token1, $token2);

        // Each token should only work with its own key
        $this->assertTrue($this->csrf->isValid($token1, 'form1'));
        $this->assertFalse($this->csrf->isValid($token1, 'form2'));

        $this->assertTrue($this->csrf->isValid($token2, 'form2'));
        $this->assertFalse($this->csrf->isValid($token2, 'form1'));
    }

    public function testStackOverflowProtection(): void
    {
        // Test that stack limits are respected

        // Generate more tokens than the default limit
        $tokens = [];
        for ($i = 0; $i < 15; $i++) {
            $tokens[] = $this->csrf->generateToken('stack_overflow[]');
        }

        // Only the most recent tokens should be valid
        $validCount = 0;
        foreach ($tokens as $i => $token) {
            if ($this->csrf->isValid($token, 'stack_overflow[]')) {
                $validCount++;
            }
        }

        // Should have at most 10 valid tokens (default limit)
        $this->assertLessThanOrEqual(10, $validCount);
    }

    public function testAtomicOperations(): void
    {
        // Test that operations are atomic

        $token = $this->csrf->generateToken('atomic_test');

        // First validation should succeed
        $result1 = $this->csrf->isValid($token, 'atomic_test');

        // Second validation should fail (token consumed)
        $result2 = $this->csrf->isValid($token, 'atomic_test');

        $this->assertTrue($result1);
        $this->assertFalse($result2);

        // Verify token is completely removed from storage
        $this->assertNull($this->csrf->getToken('atomic_test'));
    }
}
