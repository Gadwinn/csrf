<?php

declare(strict_types=1);

namespace G\Csrf\Tests\Middleware;

use G\Csrf\CsrfManager;
use G\Csrf\Middleware\{CsrfConfig, CsrfMiddleware};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

class CsrfMiddlewareTest extends TestCase
{
    private function makeCsrf(bool $valid): CsrfManager
    {
        $csrf = $this->createStub(CsrfManager::class);
        $csrf->method('isValid')->willReturn($valid);
        return $csrf;
    }

    private function makeRequest(
        string $method,
        array|object|null $body = null,
        array $headers = [],
        ?string $csrfKey = 'my_form',
        string $csrfKeyAttribute = CsrfMiddleware::TOKEN_KEY_ATTRIBUTE
    ): ServerRequestInterface {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        $request->method('getParsedBody')->willReturn($body);
        $request->method('getAttribute')->willReturnCallback(
            static fn(string $name): mixed =>
                $name === $csrfKeyAttribute ? $csrfKey : null
        );
        $request->method('getHeaderLine')->willReturnCallback(
            static fn(string $name): string => $headers[$name] ?? ''
        );

        return $request;
    }

    private function makeHandler(?ResponseInterface $response = null): RequestHandlerInterface
    {
        $response ??= $this->createStub(ResponseInterface::class);
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);
        return $handler;
    }

    // --- Interface ---

    public function testImplementsMiddlewareInterface(): void
    {
        $this->assertInstanceOf(
            MiddlewareInterface::class,
            new CsrfMiddleware($this->createStub(CsrfManager::class))
        );
    }

    // --- Unsupervised methods pass through without any token check ---

    #[DataProvider('unsupervisedMethodsProvider')]
    public function testUnsupervisedMethodPassesThrough(string $method): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->never())->method('isValid');

        $response = $this->createStub(ResponseInterface::class);
        $request  = $this->makeRequest($method);

        $result = (new CsrfMiddleware($csrf))->process($request, $this->makeHandler($response));

        $this->assertSame($response, $result);
    }

    /** @return array<string, array{string}> */
    public static function unsupervisedMethodsProvider(): array
    {
        return [
            'GET'     => ['GET'],
            'HEAD'    => ['HEAD'],
            'OPTIONS' => ['OPTIONS'],
        ];
    }

    // --- Supervised methods validate the token ---

    #[DataProvider('supervisedMethodsProvider')]
    public function testSupervisedMethodWithValidTokenPasses(string $method): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $request  = $this->makeRequest($method, ['_token' => 'abc123']);

        $result = (new CsrfMiddleware($this->makeCsrf(true)))->process($request, $this->makeHandler($response));

        $this->assertSame($response, $result);
    }

    #[DataProvider('supervisedMethodsProvider')]
    public function testSupervisedMethodWithInvalidTokenCallsFailureHandler(string $method): void
    {
        $failureResponse = $this->createStub(ResponseInterface::class);
        $failureHandler  = $this->makeHandler($failureResponse);
        $request         = $this->makeRequest($method, ['_token' => 'wrong']);

        $result = (new CsrfMiddleware($this->makeCsrf(false), $failureHandler))->process($request, $this->makeHandler());

        $this->assertSame($failureResponse, $result);
    }

    /** @return array<string, array{string}> */
    public static function supervisedMethodsProvider(): array
    {
        return [
            'POST'   => ['POST'],
            'PUT'    => ['PUT'],
            'PATCH'  => ['PATCH'],
            'DELETE' => ['DELETE'],
        ];
    }

    // --- CsrfConfig ---

    public function testDefaultsMatchConstants(): void
    {
        $middleware = new CsrfMiddleware($this->createStub(CsrfManager::class));

        $this->assertSame(CsrfMiddleware::TOKEN_KEY_ATTRIBUTE, $middleware->tokenKeyAttribute);
    }

    public function testCustomTokenFieldViaConfig(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('tok', 'my_form')->willReturn(true);

        // Body uses '_csrf' - default '_token' would be ignored
        $request = $this->makeRequest('POST', ['_csrf' => 'tok']);

        (new CsrfMiddleware($csrf, config: new CsrfConfig(tokenField: '_csrf')))->process($request, $this->makeHandler());
    }

    public function testDefaultTokenFieldIgnoredWhenCustomField(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('', 'my_form')->willReturn(false);

        // Body has '_token' but middleware expects '_csrf' → falls back to empty string
        $request = $this->makeRequest('POST', ['_token' => 'tok']);

        (new CsrfMiddleware($csrf, $this->makeHandler(), config: new CsrfConfig(tokenField: '_csrf')))->process($request, $this->makeHandler());
    }

    public function testCustomSupervisedMethodsViaConfig(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->never())->method('isValid');

        $response = $this->createStub(ResponseInterface::class);

        // DELETE is not supervised in PostOnlyMiddleware
        $result = (new CsrfMiddleware($csrf, config: new CsrfConfig(supervisedMethods: ['POST'])))->process(
            $this->makeRequest('DELETE'),
            $this->makeHandler($response)
        );

        $this->assertSame($response, $result);
    }

    public function testPostStillSupervisedWithPostOnlyMiddleware(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->willReturn(true);

        (new CsrfMiddleware($csrf, config: new CsrfConfig(supervisedMethods: ['POST'])))->process(
            $this->makeRequest('POST', ['_token' => 'tok']),
            $this->makeHandler()
        );
    }

    public function testCustomTokenKeyAttributeViaConfig(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('tok', 'my_form')->willReturn(true);

        $this->assertSame('my_csrf_key', (new CsrfMiddleware($csrf, config: new CsrfConfig(tokenKeyAttribute: 'my_csrf_key')))->tokenKeyAttribute);

        $request = $this->makeRequest('POST', ['_token' => 'tok'], [], 'my_form', 'my_csrf_key');
        (new CsrfMiddleware($csrf, config: new CsrfConfig(tokenKeyAttribute: 'my_csrf_key')))->process($request, $this->makeHandler());
    }

    public function testCustomTokenHeaderViaConfig(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('hdr-tok', 'my_form')->willReturn(true);

        $request = $this->makeRequest('POST', null, ['X-Custom-Token' => 'hdr-tok']);
        (new CsrfMiddleware($csrf, config: new CsrfConfig(tokenHeaders: ['X-Custom-Token'])))->process($request, $this->makeHandler());
    }

    public function testDefaultXCsrfHeaderIgnoredWhenCustomHeader(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        // X-CSRF-Token is not in CustomHeaderMiddleware's list → empty string reaches isValid
        $csrf->expects($this->once())->method('isValid')->with('', 'my_form')->willReturn(false);

        $request = $this->makeRequest('POST', null, ['X-CSRF-Token' => 'tok']);
        (new CsrfMiddleware($csrf, $this->makeHandler(), config: new CsrfConfig(tokenHeaders: ['X-Custom-Token'])))->process($request, $this->makeHandler());
    }

    // --- Token key from request attribute ---

    public function testStringAttributeUsedAsTokenKey(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('tok', 'checkout')->willReturn(true);

        $request = $this->makeRequest('POST', ['_token' => 'tok'], [], 'checkout');

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    public function testNullAttributeFallsBackToNullKey(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('tok', null)->willReturn(true);

        $request = $this->makeRequest('POST', ['_token' => 'tok'], [], null);

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    public function testNonStringAttributeFallsBackToNullKey(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('tok', null)->willReturn(true);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getParsedBody')->willReturn(['_token' => 'tok']);
        $request->method('getAttribute')->willReturn(42);
        $request->method('getHeaderLine')->willReturn('');

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    // --- Token extraction: body ---

    public function testTokenExtractedFromBody(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('body-token', 'my_form')->willReturn(true);

        (new CsrfMiddleware($csrf))->process(
            $this->makeRequest('POST', ['_token' => 'body-token']),
            $this->makeHandler()
        );
    }

    public function testEmptyStringTokenInBodyFallsBackToHeader(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('header-token', 'my_form')->willReturn(true);

        $request = $this->makeRequest('POST', ['_token' => ''], ['X-CSRF-Token' => 'header-token']);

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    public function testNullBodyFallsBackToHeader(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('header-token', 'my_form')->willReturn(true);

        $request = $this->makeRequest('POST', null, ['X-CSRF-Token' => 'header-token']);

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    public function testObjectBodyFallsBackToHeader(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('header-token', 'my_form')->willReturn(true);

        $request = $this->makeRequest('POST', new \stdClass(), ['X-CSRF-Token' => 'header-token']);

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    // --- Token extraction: headers ---

    public function testTokenExtractedFromXCsrfTokenHeader(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('csrf-header-token', 'my_form')->willReturn(true);

        $request = $this->makeRequest('POST', null, ['X-CSRF-Token' => 'csrf-header-token']);

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    public function testTokenExtractedFromXXsrfTokenHeader(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('xsrf-header-token', 'my_form')->willReturn(true);

        $request = $this->makeRequest('POST', null, ['X-XSRF-Token' => 'xsrf-header-token']);

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    public function testXCsrfHeaderTakesPrecedenceOverXXsrfHeader(): void
    {
        $csrf = $this->createMock(CsrfManager::class);
        $csrf->expects($this->once())->method('isValid')->with('first', 'my_form')->willReturn(true);

        $request = $this->makeRequest('POST', null, [
            'X-CSRF-Token' => 'first',
            'X-XSRF-Token' => 'second',
        ]);

        (new CsrfMiddleware($csrf))->process($request, $this->makeHandler());
    }

    // --- No token at all ---

    public function testNoTokenCallsFailureHandler(): void
    {
        $failureResponse = $this->createStub(ResponseInterface::class);
        $failureHandler  = $this->makeHandler($failureResponse);

        $result = (new CsrfMiddleware($this->makeCsrf(false), $failureHandler))->process(
            $this->makeRequest('POST', null),
            $this->makeHandler()
        );

        $this->assertSame($failureResponse, $result);
    }

    // --- Default failure handler ---

    public function testDefaultFailureHandlerThrowsException(): void
    {
        $request = $this->makeRequest('POST', ['_token' => 'bad']);

        $this->expectException(\Exception::class);
        (new CsrfMiddleware($this->makeCsrf(false)))->process($request, $this->makeHandler());
    }
}
