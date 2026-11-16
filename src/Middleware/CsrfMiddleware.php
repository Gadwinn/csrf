<?php

declare(strict_types=1);

namespace G\Csrf\Middleware;

use G\Csrf\CsrfManagerInterface;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/**
 * PSR-15 CSRF middleware powered by gadwinn/csrf.
 *
 * Configure via #[CsrfConfig] on a subclass to override defaults:
 *
 *   #[CsrfConfig(tokenField: '_csrf', supervisedMethods: ['POST', 'PUT'])]
 *   class MyCsrfMiddleware extends CsrfMiddleware {}
 */
class CsrfMiddleware implements MiddlewareInterface
{
    /** Default PSR-7 request attribute name for the CSRF key. */
    public const TOKEN_KEY_ATTRIBUTE = 'csrf_key';

    /** @var list<string> */
    private array $tokenHeaders;

    /** @var list<string> */
    private array $supervisedMethods;

    private string $tokenField;

    public readonly string $tokenKeyAttribute;

    public function __construct(
        private readonly CsrfManagerInterface $csrf,
        private readonly RequestHandlerInterface $failureHandler = new FailureRequestHandler()
    ) {
        $config = $this->resolveConfig();

        $this->tokenKeyAttribute = $config->tokenKeyAttribute;
        $this->tokenField = $config->tokenField;
        $this->tokenHeaders = $config->tokenHeaders;
        $this->supervisedMethods = array_map('strtoupper', $config->supervisedMethods);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array(strtoupper($request->getMethod()), $this->supervisedMethods, true)) {
            return $handler->handle($request);
        }

        $token = $this->extractToken($request);
        $key   = $request->getAttribute($this->tokenKeyAttribute);
        $key   = is_string($key) ? $key : null;

        if (!$this->csrf->isValid($token, $key)) {
            return $this->failureHandler->handle($request);
        }

        return $handler->handle($request);
    }

    private function extractToken(ServerRequestInterface $request): string
    {
        $body = $request->getParsedBody();

        if (is_array($body)) {
            $fieldValue = $body[$this->tokenField] ?? null;
            if (is_string($fieldValue) && $fieldValue !== '') {
                return $fieldValue;
            }
        }

        foreach ($this->tokenHeaders as $header) {
            $value = $request->getHeaderLine($header);
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    private function resolveConfig(): CsrfConfig
    {
        $attrs = (new \ReflectionClass(static::class))->getAttributes(CsrfConfig::class);

        return $attrs !== [] ? $attrs[0]->newInstance() : new CsrfConfig();
    }
}
