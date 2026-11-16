<?php

declare(strict_types=1);

namespace G\Csrf\TokenStorage;

/**
 * Stores the tokens in the PHP session.
 *
 * The session is started on demand, with the settings of the SessionConfig:
 *
 *   new SessionTokenStorage(new SessionConfig(
 *       name: '__Secure-app',
 *       cookieSecure: true,
 *       cookieHttponly: true,
 *       cookieSamesite: 'Strict',
 *   ));
 *
 * @phpstan-type CsrfToken array{value: string, expires_at: int}
 * @phpstan-type CsrfTokensMap array<string, CsrfToken|list<CsrfToken>>
 */
class SessionTokenStorage implements TokenStorageInterface
{
    /**
     * @param SessionConfig $config Storage keys and session settings
     * @param int $defaultMaxTokens Default maximum number of tokens to store for stack keys (e.g. "form[5]")
     * when the max is not specified in the key.
     * @param int $ttl Time-to-live for tokens in seconds.
     */
    public function __construct(
        private readonly SessionConfig $config = new SessionConfig(),
        private readonly int $defaultMaxTokens = 10,
        private readonly int $ttl = 1800,
    ) {
        $this->ensureSession();

        if (!isset($_SESSION[$this->config->sessionKey])) {
            $_SESSION[$this->config->sessionKey] = [];
        }
    }

    public function setToken(string $token, ?string $key = null): void
    {
        $tokens = $this->getTokens();
        [$name, $maxTokens] = $this->parseKey($key);
        $item = ['value' => $token, 'expires_at' => time() + $this->ttl];

        if ($maxTokens === null) {
            $tokens[$name] = $item;
            $this->setTokens($tokens);

            return;
        }

        // Detect type collision: scalar token already stored under the same name
        if (isset($tokens[$name]['value'])) {
            throw new \LogicException(
                "Cannot use key '{$name}' as a stack: it already exists as a scalar token."
            );
        }

        /** @var list<CsrfToken> $stack */
        $stack = $tokens[$name] ?? [];
        array_unshift($stack, $item);

        $tokens[$name] = array_slice($stack, 0, $maxTokens);
        $this->setTokens($tokens);
    }

    public function getToken(?string $key = null): ?string
    {
        return $this->findCandidates($this->getTokens(), $key)[0]['value'] ?? null;
    }

    public function hasToken(string $token, ?string $key = null): bool
    {
        foreach ($this->findCandidates($this->getTokens(), $key) as $item) {
            if (hash_equals($item['value'], $token)) {
                return true;
            }
        }

        return false;
    }

    public function deleteToken(string $token, ?string $key = null): void
    {
        $this->consumeToken($token, $key);
    }

    public function consumeToken(string $token, ?string $key = null): bool
    {
        $tokens = $this->getTokens();
        [$name, $maxTokens] = $this->parseKey($key);

        foreach ($this->findCandidates($tokens, $key) as $i => $item) {
            // The value is always verified before deleting (no unconditional deletion)
            if (!hash_equals($item['value'], $token)) {
                continue;
            }

            if ($maxTokens === null) {
                unset($tokens[$name]);
            } else {
                /** @var list<CsrfToken> $stack */
                $stack = $tokens[$name];
                unset($stack[$i]);
                $tokens[$name] = array_values($stack);
            }

            $this->setTokens($tokens);

            return true;
        }

        return false;
    }

    /**
     * Splits a key into its name and, for a stack key ("name[]" or "name[5]"), its maximum size.
     *
     * @return array{string, int|null} Name and stack size (null for a scalar key)
     */
    private function parseKey(?string $key): array
    {
        $key ??= $this->config->defaultKey;

        if (preg_match('/^(.+?)\[(\d*)\]$/D', $key, $matches)) {
            return [$matches[1], (int) $matches[2] ?: $this->defaultMaxTokens];
        }

        return [$key, null];
    }

    /**
     * Returns the tokens a key gives access to, most recent first: the whole stack for a stack key,
     * the single token for a scalar key, nothing when the stored type does not match the key type.
     *
     * @param CsrfTokensMap $tokens
     *
     * @return list<CsrfToken>
     */
    private function findCandidates(array $tokens, ?string $key): array
    {
        [$name, $maxTokens] = $this->parseKey($key);
        $stored = $tokens[$name] ?? null;

        if ($stored === null || isset($stored['value']) !== ($maxTokens === null)) {
            return [];
        }

        /** @var list<CsrfToken> */
        return $maxTokens === null ? [$stored] : $stored;
    }

    /**
     * Starts the session when needed: in a long-running worker the storage outlives the request
     * it was created in, so the session cannot be started once and for all by the constructor.
     */
    private function ensureSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            $this->applySessionConfig($this->config);
            session_start();
        }
    }
    private function applySessionConfig(SessionConfig $config): void
    {
        if ($config->name !== null) {
            session_name($config->name);
        }

        if ($config->savePath !== null) {
            $resolved = realpath($config->savePath);
            if ($resolved === false || !is_dir($resolved) || !is_writable($resolved)) {
                throw new \InvalidArgumentException(
                    sprintf("Invalid session save path: '%s'.", $config->savePath)
                );
            }
            session_save_path($resolved);
        }

        if ($config->moduleName !== null) {
            session_module_name($config->moduleName);
        }

        if ($config->cacheLimiter !== null) {
            session_cache_limiter($config->cacheLimiter);
        }

        if ($config->cacheExpire !== null) {
            session_cache_expire($config->cacheExpire);
        }

        $cookieOptions = [];

        if ($config->cookieLifetime !== null) {
            $cookieOptions['lifetime'] = $config->cookieLifetime;
        }
        if ($config->cookiePath !== null) {
            $cookieOptions['path'] = $config->cookiePath;
        }
        if ($config->cookieDomain !== null) {
            $cookieOptions['domain'] = $config->cookieDomain;
        }
        if ($config->cookieSecure !== null) {
            $cookieOptions['secure'] = $config->cookieSecure;
        }
        if ($config->cookieHttponly !== null) {
            $cookieOptions['httponly'] = $config->cookieHttponly;
        }
        if ($config->cookieSamesite !== null) {
            $cookieOptions['samesite'] = $config->cookieSamesite;
        }

        if ($cookieOptions !== []) {
            session_set_cookie_params($cookieOptions);
        }
    }

    /**
     * Returns the stored tokens that have not expired yet.
     *
     * @return CsrfTokensMap
     */
    private function getTokens(): array
    {
        $this->ensureSession();

        $now = time();
        $tokens = [];
        $stored = $_SESSION[$this->config->sessionKey] ?? [];

        foreach (is_array($stored) ? $stored : [] as $name => $data) {
            if (!is_array($data)) {
                continue;
            }

            if (isset($data['expires_at'])) {
                if ($data['expires_at'] >= $now) {
                    $tokens[(string) $name] = $data;
                }
                continue;
            }

            $stack = array_values(array_filter(
                $data,
                static fn(mixed $item): bool => is_array($item) && ($item['expires_at'] ?? 0) >= $now
            ));

            if ($stack !== []) {
                $tokens[(string) $name] = $stack;
            }
        }

        /** @var CsrfTokensMap */
        return $tokens;
    }

    /**
     * @param CsrfTokensMap $tokens
     */
    private function setTokens(array $tokens): void
    {
        $_SESSION[$this->config->sessionKey] = $tokens;
    }
}
