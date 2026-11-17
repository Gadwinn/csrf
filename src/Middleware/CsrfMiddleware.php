<?php

declare(strict_types=1);

namespace G\Csrf\Middleware;

use G\Csrf\CsrfManagerInterface;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/**
 * PSR-15 CSRF middleware powered by gadwinn/csrf.
 *
 * Defaults are overridden with a CsrfConfig:
 *
 *   new CsrfMiddleware($csrf, config: new CsrfConfig(tokenField: '_csrf', supervisedMethods: ['POST', 'PUT']));
 */
class CsrfMiddleware implements MiddlewareInterface
{
    /** Default PSR-7 request attribute name for the CSRF key. */
    public const TOKEN_KEY_ATTRIBUTE = 'csrf_key';

    /** @var list<string> */
    private readonly array $supervisedMethods;

    public readonly string $tokenKeyAttribute;

    public function __construct(
        private readonly CsrfManagerInterface $csrf,
        private readonly RequestHandlerInterface $failureHandler = new FailureRequestHandler(),
        private readonly CsrfConfig $config = new CsrfConfig(),
    ) {
        $this->tokenKeyAttribute = $config->tokenKeyAttribute;
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
            $fieldValue = $body[$this->config->tokenField] ?? null;
            if (is_string($fieldValue) && $fieldValue !== '') {
                return $fieldValue;
            }
        }

        foreach ($this->config->tokenHeaders as $header) {
            $value = $request->getHeaderLine($header);
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }
}
