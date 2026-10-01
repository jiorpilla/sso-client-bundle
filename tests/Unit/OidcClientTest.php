<?php

namespace Jiorpilla\SsoClientBundle\Tests\Unit;

use Jiorpilla\SsoClientBundle\Client\OidcClient;
use Jiorpilla\SsoClientBundle\Client\Pkce;
use Jiorpilla\SsoClientBundle\Discovery\OidcDiscovery;
use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\FakeSso;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\TokenFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\Response\JsonMockResponse;

final class OidcClientTest extends TestCase
{
    private FakeSso $sso;

    protected function setUp(): void
    {
        $this->sso = new FakeSso();
    }

    public function testAuthorizationUrl(): void
    {
        $url = $this->client()->getAuthorizationUrl('https://app.test/sso/callback', 'the-state', 'the-nonce', 'the-challenge', ['prompt' => 'login']);

        self::assertStringStartsWith(TokenFactory::ISSUER.'/authorize?', $url);
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);
        self::assertSame([
            'response_type' => 'code',
            'client_id' => TokenFactory::CLIENT_ID,
            'redirect_uri' => 'https://app.test/sso/callback',
            'scope' => 'openid profile email roles',
            'state' => 'the-state',
            'nonce' => 'the-nonce',
            'code_challenge' => 'the-challenge',
            'code_challenge_method' => 'S256',
            'prompt' => 'login',
        ], $query);
    }

    public function testPkceS256Challenge(): void
    {
        $verifier = Pkce::generateVerifier();

        // RFC 7636: 43-128 characters from the unreserved set
        self::assertMatchesRegularExpression('/^[A-Za-z0-9._~-]{43,128}$/', $verifier);
        // S256 = BASE64URL(SHA256(verifier)), checked against an independent implementation
        $expected = sodium_bin2base64((string) openssl_digest($verifier, 'sha256', true), \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        self::assertSame($expected, Pkce::challenge($verifier));
        self::assertNotSame($verifier, Pkce::generateVerifier());
    }

    public function testConfidentialClientUsesBasicAuth(): void
    {
        $this->sso->queueTokens();

        $tokens = $this->client('s3cr3t:with/special')->exchangeCode('the-code', 'the-verifier', 'https://app.test/sso/callback');

        self::assertSame('refresh-1', $tokens->refreshToken);
        self::assertNotNull($tokens->idToken);
        $request = $this->sso->requestsTo('/token')[0];
        self::assertSame('POST', $request['method']);
        $headers = implode("\n", $this->headers($request['options'])['authorization'] ?? []);
        self::assertStringContainsString('Basic '.base64_encode(TokenFactory::CLIENT_ID.':'.rawurlencode('s3cr3t:with/special')), $headers);
        $body = $this->body($request['options']);
        self::assertSame('authorization_code', $body['grant_type']);
        self::assertSame('the-code', $body['code']);
        self::assertSame('the-verifier', $body['code_verifier']);
        self::assertArrayNotHasKey('client_id', $body);
    }

    public function testPublicClientSendsClientIdWithoutSecret(): void
    {
        $this->sso->queueTokens();

        $this->client(null)->exchangeCode('the-code', 'the-verifier', 'https://app.test/sso/callback');

        $request = $this->sso->requestsTo('/token')[0];
        self::assertArrayNotHasKey('authorization', $this->headers($request['options']));
        self::assertSame(TokenFactory::CLIENT_ID, $this->body($request['options'])['client_id']);
    }

    public function testRefresh(): void
    {
        $this->sso->queueTokens(refreshToken: 'refresh-2');

        $tokens = $this->client()->refresh('refresh-1');

        self::assertSame('refresh-2', $tokens->refreshToken);
        self::assertSame(['grant_type' => 'refresh_token', 'refresh_token' => 'refresh-1'], $this->body($this->sso->requestsTo('/token')[0]['options']));
    }

    public function testErrorResponseThrows(): void
    {
        $this->sso->queueTokenResponse(['error' => 'invalid_grant', 'error_description' => 'The refresh token is invalid.'], 400);

        $this->expectExceptionObject(new SsoException('The SSO rejected the token request (invalid_grant): The refresh token is invalid.'));

        $this->client()->refresh('refresh-1');
    }

    public function testNonBearerResponseIsRejected(): void
    {
        $this->sso->queueTokenResponse(['access_token' => 'x', 'token_type' => 'mac', 'expires_in' => 600]);

        $this->expectException(SsoException::class);

        $this->client()->refresh('refresh-1');
    }

    public function testDiscoveryIssuerMismatchIsRejected(): void
    {
        $http = new \Symfony\Component\HttpClient\MockHttpClient(new JsonMockResponse(['issuer' => 'https://evil.example']));
        $discovery = new OidcDiscovery($http, new ArrayAdapter(), TokenFactory::ISSUER);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessageMatches('/does not match/');

        $discovery->getTokenEndpoint();
    }

    private function client(?string $secret = 'secret'): OidcClient
    {
        $http = $this->sso->httpClient();

        return new OidcClient($http, new OidcDiscovery($http, new ArrayAdapter(), TokenFactory::ISSUER), new MockClock(), TokenFactory::CLIENT_ID, $secret, ['openid', 'profile', 'email', 'roles']);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, list<string>>
     */
    private function headers(array $options): array
    {
        /** @var array<string, list<string>> $headers */
        $headers = $options['normalized_headers'] ?? [];

        return $headers;
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, string>
     */
    private function body(array $options): array
    {
        parse_str(\is_string($options['body']) ? $options['body'] : '', $body);

        /** @var array<string, string> $body */
        return $body;
    }
}
