<?php

declare(strict_types=1);

namespace G\Csrf\Middleware;

use G\Csrf\Exception\CsrfTokenMismatchException;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\RequestHandlerInterface;

class FailureRequestHandler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        throw new CsrfTokenMismatchException('CSRF validation failed.');
    }
}
