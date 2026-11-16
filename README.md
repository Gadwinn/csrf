# gadwinn/csrf

A paranoid-level CSRF protection library with flexible token management for PHP 8.3+.

Solves the classic conflict between **single-use tokens** (security) and **multi-tab browsing** (UX) through a keyed stack storage system.

---

## Installation

```bash
composer require gadwinn/csrf
```

## Requirements

- PHP >= 8.3

---

## Session Configuration via `SessionConfig`

`SessionTokenStorage` starts the session itself when none is active. Pass it a `SessionConfig` to apply your session policy before `session_start()` - this is the recommended approach for production:

```php
use G\Csrf\CsrfManager;
use G\Csrf\TokenGenerator\RandomTokenGenerator;
use G\Csrf\TokenStorage\SessionConfig;
use G\Csrf\TokenStorage\SessionTokenStorage;

$storage = new SessionTokenStorage(new SessionConfig(
    name: '__Secure-app_session',
    savePath: '/var/lib/php/sessions/myapp',
    cacheLimiter: 'nocache',
    cookieLifetime: 0,
    cookiePath: '/',
    cookieDomain: 'example.com',
    cookieSecure: true,
    cookieHttponly: true,
    cookieSamesite: 'Strict',
));

$csrf = new CsrfManager(new RandomTokenGenerator(), $storage);
```

The session key names are also configurable:

```php
new SessionTokenStorage(new SessionConfig(sessionKey: '_app_csrf', defaultKey: '_global'));
```

> Session settings are applied **only when the session is not yet active**. If you start the session yourself before instantiation, the session settings are ignored (the session is already configured).
>
> The session is checked again on every operation: in a long-running worker (FrankenPHP worker mode…), the same storage instance reopens the session of each new request by itself.

### All `SessionConfig` options

| Parameter | PHP function | Default |
|---|---|---|
| `sessionKey` | *(internal `$_SESSION` key)* | `'_csrf_tokens'` |
| `defaultKey` | *(default token name)* | `'_default'` |
| `name` | `session_name()` | `null` *(skip)* |
| `savePath` | `session_save_path()` | `null` *(skip)* |
| `moduleName` | `session_module_name()` | `null` *(skip)* |
| `cacheLimiter` | `session_cache_limiter()` | `null` *(skip)* |
| `cacheExpire` | `session_cache_expire()` | `null` *(skip)* |
| `cookieLifetime` | `session_set_cookie_params()` | `null` *(skip)* |
| `cookiePath` | `session_set_cookie_params()` | `null` *(skip)* |
| `cookieDomain` | `session_set_cookie_params()` | `null` *(skip)* |
| `cookieSecure` | `session_set_cookie_params()` | `null` *(skip)* |
| `cookieHttponly` | `session_set_cookie_params()` | `null` *(skip)* |
| `cookieSamesite` | `session_set_cookie_params()` | `null` *(skip)* |

---

## Manual Session Configuration

`SessionTokenStorage` calls `session_start()` automatically if no session is active. This is convenient but **not recommended in production** : calling `session_start()` without options uses PHP's defaults, which are often too permissive.

For better security, start the session yourself **before** instantiating the storage, using the PHP session configuration functions:

```php
session_name('__Secure-app_session');

session_save_path('/var/lib/php/sessions/myapp'); // isolated from other apps on the server

session_set_cookie_params([
    'lifetime' => 0,          // session cookie (expires on browser close)
    'path'     => '/',
    'domain'   => 'example.com',
    'secure'   => true,       // HTTPS only
    'httponly' => true,       // not accessible via JavaScript
    'samesite' => 'Strict',   // blocks cross-site requests entirely
]);

session_start();
```

When a session is already active, `SessionTokenStorage` skips its own `session_start()` call entirely and uses the existing session as-is.

> `session_set_cookie_params()` and `session_name()` must be called **before** `session_start()`, otherwise they have no effect.

---

## Quick Start

```php
use G\Csrf\CsrfManager;
use G\Csrf\TokenGenerator\RandomTokenGenerator;
use G\Csrf\TokenStorage\SessionTokenStorage;

// Recommended: configure and start the session before instantiation
session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_start();

$csrf = new CsrfManager(
    new RandomTokenGenerator(),
    new SessionTokenStorage()
);

// Generate a token and embed it in a form
$token = $csrf->generateToken('contact_form');
echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';

// Validate on form submission (token is consumed on first use)
if ($csrf->isValid($_POST['csrf_token'], 'contact_form')) {
    // Valid - process the form
}
```

---

## Key Syntax

The `$key` parameter controls how tokens are stored. Three formats are supported:

### `null` - Default token

```php
$csrf->generateToken();        // store
$csrf->isValid($token);        // validate
```

A single token with no named key. Overwritten on each call to `generateToken()`.

### `'name'` - Named atomic token

```php
$csrf->generateToken('login');
$csrf->isValid($token, 'login');
```

One token per key. Each new generation replaces the previous one.
Suited for simple forms where only one active token is needed at a time.

### `'name[]'` - Named stack (default limit)

```php
$csrf->generateToken('checkout[]');
$csrf->isValid($token, 'checkout[]');
```

Maintains a stack of up to **10 tokens** (default) for this key.
Each generation pushes a new token; the oldest is dropped when the limit is reached.
Each validation consumes exactly one token from the stack.

Suited for forms that may be open in **multiple tabs simultaneously**.

### `'name[n]'` - Named stack (custom limit)

```php
$csrf->generateToken('search[3]');  // stack of max 3 tokens
$csrf->isValid($token, 'search[3]');
```

Same behavior as `name[]` with an explicit maximum size.

---

## API Reference

### `CsrfManager`

| Method | Description |
|---|---|
| `generateToken(?string $key): string` | Generate a token, store it, and return it |
| `isValid(string $token, ?string $key): bool` | Validate a token and consume it if valid |
| `getToken(?string $key): ?string` | Retrieve the current token without consuming it |

### `SessionTokenStorage`

```php
new SessionTokenStorage(
    config: new SessionConfig(), // storage keys and session settings
    defaultMaxTokens: 10,   // default stack size for name[] syntax
    ttl: 1800               // token lifetime in seconds (default: 30 min)
)
```

| Method | Description |
|---|---|
| `setToken(string $token, ?string $key): void` | Store a token |
| `getToken(?string $key): ?string` | Retrieve a token |
| `hasToken(string $token, ?string $key): bool` | Check if a token exists (timing-safe) |
| `deleteToken(string $token, ?string $key): void` | Delete a token (only if the value matches) |
| `consumeToken(string $token, ?string $key): bool` | Check and delete a token in one step |

A name is either a single token or a stack, never both: using `'form[]'` while `'form'` holds a single token throws a `LogicException`.

Expired tokens are cleaned up automatically on every operation.

### `RandomTokenGenerator`

```php
new RandomTokenGenerator(length: 32) // length in hexadecimal characters
```

Generates cryptographically secure hex tokens via `random_bytes()`. The length cannot be lower than `RandomTokenGenerator::MIN_LENGTH` (32 characters, 128 bits): a shorter one throws an `InvalidArgumentException`.

```php
$generator->generate(); // returns a 32-character hex string
```

---

## Extending

Both `SessionTokenStorage` and `RandomTokenGenerator` implement interfaces, making them easy to swap:

```php
use G\Csrf\TokenStorage\TokenStorageInterface;

class RedisTokenStorage implements TokenStorageInterface
{
    // implement setToken, getToken, hasToken, deleteToken, consumeToken
}

$csrf = new CsrfManager(new RandomTokenGenerator(), new RedisTokenStorage(...));
```

---

## Security Design

| Feature | Implementation |
|---|---|
| Cryptographic generation | `random_bytes()` + `bin2hex()` |
| Timing-attack protection | `hash_equals()` on all comparisons |
| Single-use enforcement | Token is deleted immediately after successful validation |
| Automatic expiry | TTL stored alongside each token; expired tokens removed on every operation |
| Stack overflow prevention | Oldest tokens pruned when stack limit is reached |
| Minimum entropy | Tokens shorter than 32 hex characters are refused |

Out of scope, left to the application: rate limiting of failed attempts and logging of CSRF failures (wrap `CsrfManager` or handle `CsrfTokenMismatchException`).

---

## AJAX Usage

Include the token in the request body or a custom header:

```js
fetch('/api/action', {
    method: 'POST',
    headers: { 'X-CSRF-Token': document.querySelector('[name=csrf_token]').value },
});
```

```php
$token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!$csrf->isValid($token, 'api_action')) {
    http_response_code(403);
    exit;
}
```

---

## PSR-15 Middleware

The library includes an optional PSR-15 middleware (`G\Csrf\Middleware`) that delegates CSRF protection to `CsrfManager`. It requires `psr/http-message`, `psr/http-server-handler`, and `psr/http-server-middleware` - install them only if you use the middleware.

```bash
composer require psr/http-message psr/http-server-handler psr/http-server-middleware
```

### How it works

On every **supervised request** (`POST`, `PUT`, `PATCH`, `DELETE`), the middleware:

1. Reads the token from the `_token` field of the parsed body, then `X-CSRF-Token` header, then `X-XSRF-Token` header
2. Reads the CSRF key from the PSR-7 request attribute `csrf_key`
3. Calls `CsrfManager::isValid($token, $key)` - which validates **and consumes** the token in one step
4. Passes to the next handler if valid, or calls the failure handler if not

All other methods (`GET`, `HEAD`, `OPTIONS`, …) pass through without any check.

### Quick Start

```php
use G\Csrf\CsrfManager;
use G\Csrf\TokenGenerator\RandomTokenGenerator;
use G\Csrf\TokenStorage\SessionTokenStorage;
use G\Csrf\Middleware\CsrfMiddleware;

session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_start();

$csrf = new CsrfManager(new RandomTokenGenerator(), new SessionTokenStorage());
$middleware = new CsrfMiddleware($csrf);
```

### Configuration via `CsrfConfig`

Override the defaults with a `CsrfConfig`:

```php
use G\Csrf\Middleware\CsrfConfig;
use G\Csrf\Middleware\CsrfMiddleware;

$middleware = new CsrfMiddleware($csrf, config: new CsrfConfig(
    tokenField: '_csrf',
    supervisedMethods: ['POST', 'PUT'],
));
```

| Parameter | Default | Description |
|---|---|---|
| `tokenKeyAttribute` | `'csrf_key'` | PSR-7 request attribute name |
| `tokenField` | `'_token'` | POST body field name |
| `tokenHeaders` | `['X-CSRF-Token', 'X-XSRF-Token']` | Headers checked in order |
| `supervisedMethods` | `['POST', 'PUT', 'PATCH', 'DELETE']` | Methods requiring validation |

### Token Key

The middleware reads the token key from the PSR-7 request attribute `CsrfMiddleware::TOKEN_KEY_ATTRIBUTE` (`"csrf_key"`):

```php
$request = $request->withAttribute(CsrfMiddleware::TOKEN_KEY_ATTRIBUTE, 'checkout');
```

If the attribute is absent or not a string, the middleware falls back to `null` (unnamed token slot).

### Custom Failure Handler

By default, `FailureRequestHandler` throws a `G\Csrf\Exception\CsrfTokenMismatchException` (to be turned into a 403 response by your error handling). Replace it with any `RequestHandlerInterface`:

```php
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};
use Psr\Http\Server\RequestHandlerInterface;

class CsrfFailureHandler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return (new ResponseFactory())->createResponse(403);
    }
}

$middleware = new CsrfMiddleware($csrf, new CsrfFailureHandler());
```
