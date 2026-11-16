<?php

declare(strict_types=1);

namespace G\Csrf\Tests\Middleware;

use G\Csrf\Middleware\FailureRequestHandler;
use Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class FailureRequestHandlerTest extends TestCase
{
    public function testFailureRequestHandler(): void
    {
        $requestHandler = new FailureRequestHandler();
        $this->assertInstanceOf(
            RequestHandlerInterface::class,
            $requestHandler
        );
    }

    public function testHandle(): void
    {
        $requestHandler = new FailureRequestHandler();
        $this->expectException(Exception::class);
        $requestHandler->handle($this->createStub(ServerRequestInterface::class));
    }
}
