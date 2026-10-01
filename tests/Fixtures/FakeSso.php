<?php

namespace Jiorpilla\SsoClientBundle\Tests\Fixtures;

use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * An in-memory SSO: serves discovery, JWKS and the token endpoint, and records requests.
 */
final class FakeSso
{
    /**
     * @var list<TestKey>
     */
    public array $keys;

    public bool $withEndSession = false;

    /**
     * @var list<array{method: string, url: string, options: array<string, mixed>}>
     */
    public array $requests = [];

    /**
     * @var list<\Closure(array<string, mixed>): ResponseInterface>
     */
    private array $tokenResponses = [];

    public function __construct()
    {
        $this->keys = [TestKey::get()];
    }

    /**
     * Queues the response for the next token endpoint call.
     *
     * @param array<string, mixed> $body
     */
    public function queueTokenResponse(array $body, int $status = 200): void
    {
        $this->tokenResponses[] = static fn (): ResponseInterface => new JsonMockResponse($body, ['http_code' => $status]);
    }

    /**
     * @param array<string, mixed> $idTokenClaims
     */
    public function queueTokens(array $idTokenClaims = [], ?string $refreshToken = 'refresh-1', int $expiresIn = 600): void
    {
        $this->queueTokenResponse(array_filter([
            'token_type' => 'Bearer',
            'expires_in' => $expiresIn,
            'access_token' => TokenFactory::accessToken(),
            'refresh_token' => $refreshToken,
            'id_token' => TokenFactory::idToken($idTokenClaims),
        ], static fn (mixed $value): bool => null !== $value));
    }

    public function httpClient(): MockHttpClient
    {
        return new MockHttpClient($this->handle(...), TokenFactory::ISSUER);
    }

    /**
     * @return list<array{method: string, url: string, options: array<string, mixed>}>
     */
    public function requestsTo(string $path): array
    {
        return array_values(array_filter($this->requests, static fn (array $r): bool => str_ends_with((string) parse_url($r['url'], \PHP_URL_PATH), $path)));
    }

    /**
     * @param array<string, mixed> $options
     */
    private function handle(string $method, string $url, array $options): ResponseInterface
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'options' => $options];
        $path = (string) parse_url($url, \PHP_URL_PATH);

        return match ($path) {
            '/.well-known/openid-configuration' => new JsonMockResponse(array_filter([
                'issuer' => TokenFactory::ISSUER,
                'authorization_endpoint' => TokenFactory::ISSUER.'/authorize',
                'token_endpoint' => TokenFactory::ISSUER.'/token',
                'userinfo_endpoint' => TokenFactory::ISSUER.'/userinfo',
                'jwks_uri' => TokenFactory::ISSUER.'/jwks',
                'end_session_endpoint' => $this->withEndSession ? TokenFactory::ISSUER.'/logout' : null,
            ])),
            '/jwks' => new JsonMockResponse(['keys' => array_map(static fn (TestKey $key): array => $key->jwk, $this->keys)]),
            '/token' => [] !== $this->tokenResponses
                ? array_shift($this->tokenResponses)($options)
                : new JsonMockResponse(['error' => 'invalid_grant'], ['http_code' => 400]),
            default => new MockResponse('Not found', ['http_code' => 404]),
        };
    }
}
