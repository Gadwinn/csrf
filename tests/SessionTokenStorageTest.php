<?php

declare(strict_types=1);

namespace G\Csrf\Tests;

use G\Csrf\TokenStorage\SessionConfig;
use G\Csrf\TokenStorage\SessionTokenStorage;
use PHPUnit\Framework\TestCase;

class SessionTokenStorageTest extends TestCase
{
    use ExpiresTokensTrait;

    private SessionTokenStorage $storage;

    protected function setUp(): void
    {
        $_SESSION = [];
        $this->storage = new SessionTokenStorage();
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
    }

    // --- Session lifecycle ---

    public function testConstructorStartsSessionWhenNotActive(): void
    {
        session_write_close();
        $this->assertSame(PHP_SESSION_NONE, session_status());

        new SessionTokenStorage();

        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
    }

    public function testConstructorDoesNotErrorWhenSessionAlreadyActive(): void
    {
        $this->assertSame(PHP_SESSION_ACTIVE, session_status());

        new SessionTokenStorage();

        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
    }

    // --- SessionConfig: storage keys ---

    public function testCustomSessionKeyViaConfig(): void
    {
        $storage = new SessionTokenStorage(new SessionConfig(sessionKey: '_custom_csrf'));
        $storage->setToken('tok', 'form');

        $this->assertArrayHasKey('_custom_csrf', $_SESSION);
        $this->assertTrue($storage->hasToken('tok', 'form'));
    }

    public function testCustomSessionKeyDoesNotWriteToDefaultKey(): void
    {
        $_SESSION = [];
        new SessionTokenStorage(new SessionConfig(sessionKey: '_custom_csrf'));

        $this->assertArrayNotHasKey('_csrf_tokens', $_SESSION);
        $this->assertArrayHasKey('_custom_csrf', $_SESSION);
    }

    public function testCustomDefaultKeyViaConfig(): void
    {
        $storage = new SessionTokenStorage(new SessionConfig(defaultKey: '_main'));
        $storage->setToken('tok', null);

        // Token stored under '_main' not '_default'
        $this->assertSame('tok', $storage->getToken(null));
        $this->assertArrayHasKey('_main', $_SESSION['_csrf_tokens']);
        $this->assertArrayNotHasKey('_default', $_SESSION['_csrf_tokens']);
    }

    // --- SessionConfig: session settings applied before session_start() ---

    public function testSessionNameAppliedWhenSessionNotStarted(): void
    {
        session_write_close();
        $this->assertSame(PHP_SESSION_NONE, session_status());

        new SessionTokenStorage(new SessionConfig(name: 'TestApp'));

        $this->assertSame('TestApp', session_name());
        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
    }

    public function testCookieParamsAppliedWhenSessionNotStarted(): void
    {
        session_write_close();
        $this->assertSame(PHP_SESSION_NONE, session_status());

        new SessionTokenStorage(new SessionConfig(cookieSecure: true, cookieHttponly: true, cookieSamesite: 'Strict'));

        $params = session_get_cookie_params();
        $this->assertTrue($params['secure']);
        $this->assertTrue($params['httponly']);
        $this->assertSame('Strict', $params['samesite']);
    }

    public function testRemainingSessionOptionsAppliedWhenSessionNotStarted(): void
    {
        session_write_close();
        $this->assertSame(PHP_SESSION_NONE, session_status());

        new SessionTokenStorage(new SessionConfig(moduleName: 'files', cacheLimiter: 'nocache', cacheExpire: 180, cookieLifetime: 3600, cookiePath: '/app', cookieDomain: 'example.com'));

        $this->assertSame('nocache', session_cache_limiter());
        $this->assertSame(180, session_cache_expire());

        $params = session_get_cookie_params();
        $this->assertSame(3600, $params['lifetime']);
        $this->assertSame('/app', $params['path']);
        $this->assertSame('example.com', $params['domain']);
    }

    public function testSessionSettingsNotAppliedWhenSessionAlreadyActive(): void
    {
        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
        $nameBefore = session_name();

        // NamedSessionStorage wants to set name='TestApp', but session is already active
        new SessionTokenStorage(new SessionConfig(name: 'TestApp'));

        // Name unchanged - applySessionConfig was skipped
        $this->assertSame($nameBefore, session_name());
    }

    // --- Core token operations (unchanged behaviour) ---

    public function testSetAndGetTokenWithNullKey(): void
    {
        $this->storage->setToken('test-token-1', null);
        $token = $this->storage->getToken(null);

        $this->assertSame('test-token-1', $token);
    }

    public function testSetAndGetTokenWithStringKey(): void
    {
        $this->storage->setToken('test-token-2', 'my-form');
        $token = $this->storage->getToken('my-form');

        $this->assertSame('test-token-2', $token);
    }

    public function testSetTokenOverwritesPreviousWithSameKey(): void
    {
        $this->storage->setToken('token-1', 'form-key');
        $this->storage->setToken('token-2', 'form-key');

        $token = $this->storage->getToken('form-key');
        $this->assertSame('token-2', $token);
    }

    public function testSetTokenWithStackSyntax(): void
    {
        $this->storage->setToken('token-1', 'form[]');
        $this->storage->setToken('token-2', 'form[]');

        $token = $this->storage->getToken('form[]');
        $this->assertSame('token-2', $token);
    }

    public function testSetTokenWithExplicitStackLimit(): void
    {
        $this->storage->setToken('token-1', 'form[3]');
        $this->storage->setToken('token-2', 'form[3]');
        $this->storage->setToken('token-3', 'form[3]');
        $this->storage->setToken('token-4', 'form[3]');

        $token = $this->storage->getToken('form[3]');
        $this->assertSame('token-4', $token);

        $this->assertFalse($this->storage->hasToken('token-1', 'form[3]'));
    }

    public function testHasTokenReturnsTrueForExistingToken(): void
    {
        $this->storage->setToken('existing-token', 'test-key');

        $this->assertTrue($this->storage->hasToken('existing-token', 'test-key'));
    }

    public function testHasTokenReturnsFalseForNonExistingToken(): void
    {
        $this->assertFalse($this->storage->hasToken('non-existing-token', 'test-key'));
    }

    public function testHasTokenWithStack(): void
    {
        $this->storage->setToken('token-1', 'stack[]');
        $this->storage->setToken('token-2', 'stack[]');

        $this->assertTrue($this->storage->hasToken('token-1', 'stack[]'));
        $this->assertTrue($this->storage->hasToken('token-2', 'stack[]'));
    }

    public function testDeleteTokenRemovesToken(): void
    {
        $this->storage->setToken('to-delete', 'delete-key');
        $this->assertTrue($this->storage->hasToken('to-delete', 'delete-key'));

        $this->storage->deleteToken('to-delete', 'delete-key');
        $this->assertFalse($this->storage->hasToken('to-delete', 'delete-key'));
    }

    public function testDeleteTokenFromStack(): void
    {
        $this->storage->setToken('token-1', 'stack[]');
        $this->storage->setToken('token-2', 'stack[]');

        $this->storage->deleteToken('token-1', 'stack[]');
        $this->assertFalse($this->storage->hasToken('token-1', 'stack[]'));
        $this->assertTrue($this->storage->hasToken('token-2', 'stack[]'));
    }

    public function testTokenExpiration(): void
    {
        $shortTtlStorage = new SessionTokenStorage(defaultMaxTokens: 10, ttl: 1);

        $shortTtlStorage->setToken('short-lived', 'expiring-key');
        $this->assertTrue($shortTtlStorage->hasToken('short-lived', 'expiring-key'));

        $this->ageTokens(2);

        $this->assertFalse($shortTtlStorage->hasToken('short-lived', 'expiring-key'));
    }

    public function testCleanExpiredTokensIsCalledAutomatically(): void
    {
        $shortTtlStorage = new SessionTokenStorage(defaultMaxTokens: 10, ttl: 1);

        $shortTtlStorage->setToken('expired-1', 'key1');
        $shortTtlStorage->setToken('expired-2', 'key2');

        $this->ageTokens(2);

        $shortTtlStorage->setToken('new-token', 'key3');

        $this->assertFalse($shortTtlStorage->hasToken('expired-1', 'key1'));
        $this->assertFalse($shortTtlStorage->hasToken('expired-2', 'key2'));
    }

    public function testGetTokenReturnsNullForNonExistingKey(): void
    {
        $token = $this->storage->getToken('non-existing-key');
        $this->assertNull($token);
    }

    public function testCleanExpiredTokensRemovesExpiredItemsFromStack(): void
    {
        $shortTtlStorage = new SessionTokenStorage(defaultMaxTokens: 10, ttl: 1);

        $shortTtlStorage->setToken('stack-token-1', 'stack[]');
        $shortTtlStorage->setToken('stack-token-2', 'stack[]');

        $this->ageTokens(2);

        $token = $shortTtlStorage->getToken('stack[]');

        $this->assertNull($token);
        $this->assertFalse($shortTtlStorage->hasToken('stack-token-1', 'stack[]'));
        $this->assertFalse($shortTtlStorage->hasToken('stack-token-2', 'stack[]'));
    }

    public function testCleanExpiredTokensKeepsValidItemsInStack(): void
    {
        $shortTtlStorage = new SessionTokenStorage(defaultMaxTokens: 10, ttl: 1);

        $shortTtlStorage->setToken('stack-token-1', 'stack[]');

        $this->ageTokens(2);

        $shortTtlStorage->setToken('stack-token-2', 'stack[]');

        $this->assertFalse($shortTtlStorage->hasToken('stack-token-1', 'stack[]'));
        $this->assertTrue($shortTtlStorage->hasToken('stack-token-2', 'stack[]'));
    }

    public function testGetTokenReturnsNullForEmptyStack(): void
    {
        $_SESSION['_csrf_tokens']['form'] = [];

        $token = $this->storage->getToken('form[]');
        $this->assertNull($token);
    }

    public function testGetTokenReturnsNullForNonExistentStack(): void
    {
        $token = $this->storage->getToken('nonexistent[]');
        $this->assertNull($token);
    }

    public function testStackBehaviorWithDefaultLimit(): void
    {
        for ($i = 0; $i < 15; $i++) {
            $this->storage->setToken("token-$i", 'default-stack[]');
        }

        $this->assertTrue($this->storage->hasToken('token-14', 'default-stack[]'));
        $this->assertTrue($this->storage->hasToken('token-10', 'default-stack[]'));
        $this->assertFalse($this->storage->hasToken('token-4', 'default-stack[]'));
    }

    // --- Key type collisions ---

    public function testStackKeyOnScalarTokenThrows(): void
    {
        $this->storage->setToken('scalar', 'form');

        $this->expectException(\LogicException::class);

        $this->storage->setToken('stacked', 'form[]');
    }

    public function testScalarKeyNeverMatchesAStack(): void
    {
        $this->storage->setToken('stacked', 'form[]');

        $this->assertNull($this->storage->getToken('form'));
        $this->assertFalse($this->storage->hasToken('stacked', 'form'));
        $this->assertFalse($this->storage->consumeToken('stacked', 'form'));
        $this->assertTrue($this->storage->hasToken('stacked', 'form[]'));
    }

    public function testStackKeyNeverMatchesAScalarToken(): void
    {
        $this->storage->setToken('scalar', 'form');

        $this->assertNull($this->storage->getToken('form[]'));
        $this->assertFalse($this->storage->hasToken('scalar', 'form[]'));
        $this->assertFalse($this->storage->consumeToken('scalar', 'form[]'));
        $this->assertTrue($this->storage->hasToken('scalar', 'form'));
    }

    // --- Consumption ---

    public function testConsumeTokenIsSingleUse(): void
    {
        $this->storage->setToken('once', 'form');

        $this->assertFalse($this->storage->consumeToken('other', 'form'));
        $this->assertTrue($this->storage->consumeToken('once', 'form'));
        $this->assertFalse($this->storage->consumeToken('once', 'form'));
    }

    public function testConsumeTokenFromStackKeepsTheOthers(): void
    {
        $this->storage->setToken('token-1', 'stack[]');
        $this->storage->setToken('token-2', 'stack[]');
        $this->storage->setToken('token-3', 'stack[]');

        $this->assertTrue($this->storage->consumeToken('token-2', 'stack[]'));
        $this->assertFalse($this->storage->consumeToken('token-2', 'stack[]'));
        $this->assertTrue($this->storage->hasToken('token-1', 'stack[]'));
        $this->assertSame('token-3', $this->storage->getToken('stack[]'));
    }

    public function testDeleteTokenRequiresTheRightValue(): void
    {
        $this->storage->setToken('real', 'form');

        $this->storage->deleteToken('guess', 'form');

        $this->assertTrue($this->storage->hasToken('real', 'form'));
    }

    public function testStackIsTrimmedToASmallerLimit(): void
    {
        for ($i = 1; $i <= 5; $i++) {
            $this->storage->setToken("token-$i", 'form[5]');
        }

        $this->storage->setToken('token-6', 'form[2]');

        $this->assertTrue($this->storage->hasToken('token-6', 'form[]'));
        $this->assertTrue($this->storage->hasToken('token-5', 'form[]'));
        $this->assertFalse($this->storage->hasToken('token-4', 'form[]'));
    }

    public function testTokenIsStillValidAtItsExpirationSecond(): void
    {
        $storage = new SessionTokenStorage(ttl: 10);
        $storage->setToken('tok', 'form');

        $this->ageTokens(10);
        $this->assertTrue($storage->hasToken('tok', 'form'));

        $this->ageTokens(1);
        $this->assertFalse($storage->hasToken('tok', 'form'));
    }

    // --- Long-running workers: the storage outlives the request ---

    public function testStorageSurvivesANewRequest(): void
    {
        $this->storage->setToken('tok', 'form');

        // What a worker does between two requests: the session is closed and the superglobal reset.
        session_write_close();
        $_SESSION = [];

        // The storage reopens the session by itself and finds the token again.
        $this->assertTrue($this->storage->hasToken('tok', 'form'));
        $this->assertSame(PHP_SESSION_ACTIVE, session_status());

        $this->storage->setToken('next', 'form');
        $this->assertTrue($this->storage->consumeToken('next', 'form'));
    }

    public function testCorruptedSessionDataIsIgnored(): void
    {
        $_SESSION['_csrf_tokens'] = ['a' => 'garbage', 'b' => ['garbage'], 'c' => ['value' => 'x']];

        $this->assertNull($this->storage->getToken('a'));
        $this->assertNull($this->storage->getToken('b[]'));
        $this->assertFalse($this->storage->hasToken('x', 'c'));
    }
}
