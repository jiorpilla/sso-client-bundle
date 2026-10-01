<?php

namespace Jiorpilla\SsoClientBundle\Tests\Unit;

use Jiorpilla\SsoClientBundle\Discovery\OidcDiscovery;
use Jiorpilla\SsoClientBundle\Exception\InvalidTokenException;
use Jiorpilla\SsoClientBundle\Jwt\JwksProvider;
use Jiorpilla\SsoClientBundle\Jwt\TokenVerifier;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\FakeSso;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\TestKey;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\TokenFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;

final class TokenVerifierTest extends TestCase
{
    private FakeSso $sso;
    private MockClock $clock;
    private ArrayAdapter $cache;

    protected function setUp(): void
    {
        $this->sso = new FakeSso();
        $this->clock = new MockClock();
        $this->cache = new ArrayAdapter();
    }

    public function testValidIdToken(): void
    {
        $claims = $this->verifier()->verifyIdToken(TokenFactory::idToken(now: $this->now()), 'test-nonce');

        self::assertSame(TokenFactory::SUB, $claims->sub);
        self::assertSame('jan@example.com', $claims->email);
        self::assertTrue($claims->emailVerified);
        self::assertSame('Jan Test', $claims->name);
        self::assertSame(['ROLE_ADMIN'], $claims->roles);
        self::assertIsInt($claims->get('exp'));
    }

    public function testNonceMismatchIsRejected(): void
    {
        $this->expectExceptionObject(new InvalidTokenException('The ID token nonce does not match the login request.'));

        $this->verifier()->verifyIdToken(TokenFactory::idToken(now: $this->now()), 'another-nonce');
    }

    public function testMissingNonceIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);

        $this->verifier()->verifyIdToken(TokenFactory::idToken(['nonce' => null], now: $this->now()), 'test-nonce');
    }

    public function testSignatureFromAnotherKeyIsRejected(): void
    {
        // Same kid as the published key, but signed with a different private key
        $forged = TokenFactory::idToken(key: $this->impostorKey(), now: $this->now());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageMatches('/signature/i');

        $this->verifier()->verifyIdToken($forged, 'test-nonce');
    }

    public function testTamperedPayloadIsRejected(): void
    {
        [$header, , $signature] = explode('.', TokenFactory::idToken(now: $this->now()));
        $payload = rtrim(strtr(base64_encode((string) json_encode([
            'iss' => TokenFactory::ISSUER, 'aud' => TokenFactory::CLIENT_ID, 'sub' => 'someone-else',
            'iat' => $this->now()->getTimestamp(), 'exp' => $this->now()->getTimestamp() + 600, 'nonce' => 'test-nonce',
        ])), '+/', '-_'), '=');

        $this->expectException(InvalidTokenException::class);

        $this->verifier()->verifyIdToken("$header.$payload.$signature", 'test-nonce');
    }

    public function testHs256AlgorithmConfusionIsRejected(): void
    {
        $this->expectExceptionObject(new InvalidTokenException('Only RS256-signed tokens are accepted.'));

        $this->verifier()->verifyIdToken(TokenFactory::hs256WithPublicKey(), null);
    }

    public function testWrongIssuerIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);

        $this->verifier()->verifyIdToken(TokenFactory::idToken(['iss' => 'https://evil.example'], now: $this->now()), 'test-nonce');
    }

    public function testWrongAudienceIsRejected(): void
    {
        $this->expectExceptionObject(new InvalidTokenException('The token was not issued for this application (audience mismatch).'));

        $this->verifier()->verifyIdToken(TokenFactory::idToken(['aud' => 'another-app'], now: $this->now()), 'test-nonce');
    }

    public function testExpiredTokenIsRejected(): void
    {
        $token = TokenFactory::idToken(now: $this->now());
        $this->clock->modify('+10 minutes +31 seconds');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageMatches('/expired/i');

        $this->verifier()->verifyIdToken($token, 'test-nonce');
    }

    public function testSmallClockDriftIsTolerated(): void
    {
        $token = TokenFactory::idToken(now: $this->now());
        $this->clock->modify('+10 minutes +20 seconds');

        self::assertSame(TokenFactory::SUB, $this->verifier()->verifyIdToken($token, 'test-nonce')->sub);
    }

    public function testTokenWithoutExpiryIsRejected(): void
    {
        $this->expectExceptionObject(new InvalidTokenException('The token has no expiry.'));

        $this->verifier()->verifyIdToken(TokenFactory::idToken(['exp' => null], now: $this->now()), 'test-nonce');
    }

    public function testMalformedTokenIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);

        $this->verifier()->verifyIdToken('not.a.jwt', null);
    }

    public function testUnknownKidTriggersOneJwksRefetch(): void
    {
        $verifier = $this->verifier();
        $verifier->verifyIdToken(TokenFactory::idToken(now: $this->now()), 'test-nonce');
        self::assertCount(1, $this->sso->requestsTo('/jwks'));

        // The SSO rotates to a new key
        $rotated = TestKey::get('rotated-key');
        $this->sso->keys[] = $rotated;
        $this->clock->modify('+2 minutes');

        $claims = $this->verifier()->verifyIdToken(TokenFactory::idToken(key: $rotated, now: $this->now()), 'test-nonce');

        self::assertSame(TokenFactory::SUB, $claims->sub);
        self::assertCount(2, $this->sso->requestsTo('/jwks'));
    }

    public function testUnknownKidsCannotForceRepeatedRefetches(): void
    {
        $this->verifier()->verifyIdToken(TokenFactory::idToken(now: $this->now()), 'test-nonce');
        $unknown = TestKey::get('unpublished-key');

        foreach ([1, 2, 3] as $attempt) {
            try {
                $this->verifier()->verifyIdToken(TokenFactory::idToken(key: $unknown, now: $this->now()), 'test-nonce');
                self::fail('A token signed with an unpublished key was accepted.');
            } catch (InvalidTokenException $e) {
                self::assertStringContainsString('No SSO signing key', $e->getMessage());
            }
        }

        // One initial download + one refetch; the cooldown blocks the rest
        self::assertCount(2, $this->sso->requestsTo('/jwks'));
    }

    public function testAccessTokenAcceptsConfiguredAudiences(): void
    {
        $token = TokenFactory::accessToken(['aud' => 'my-api'], now: $this->now());

        $claims = $this->verifier()->verifyAccessToken($token, ['other-api', 'my-api']);

        self::assertSame(['openid', 'profile', 'email', 'roles'], $claims->scopes);
    }

    public function testAccessTokenDefaultsToClientIdAudience(): void
    {
        $this->expectException(InvalidTokenException::class);

        $this->verifier()->verifyAccessToken(TokenFactory::accessToken(['aud' => 'my-api'], now: $this->now()));
    }

    public function testValidLogoutToken(): void
    {
        $claims = $this->verifier()->verifyLogoutToken(TokenFactory::logoutToken(['sid' => 'session-1'], now: $this->now()));

        self::assertSame(TokenFactory::SUB, $claims->sub);
        self::assertSame('session-1', $claims->get('sid'));
    }

    public function testLogoutTokenWithNonceIsRejected(): void
    {
        $this->expectExceptionObject(new InvalidTokenException('A logout token must not contain a nonce.'));

        $this->verifier()->verifyLogoutToken(TokenFactory::logoutToken(['nonce' => 'x'], now: $this->now()));
    }

    public function testIdTokenIsNotAcceptedAsLogoutToken(): void
    {
        $this->expectExceptionObject(new InvalidTokenException('Not a back-channel logout token.'));

        $this->verifier()->verifyLogoutToken(TokenFactory::idToken(now: $this->now()));
    }

    private function verifier(): TokenVerifier
    {
        $http = $this->sso->httpClient();
        $discovery = new OidcDiscovery($http, $this->cache, TokenFactory::ISSUER);

        return new TokenVerifier(new JwksProvider($http, $this->cache, $discovery, $this->clock), $this->clock, TokenFactory::ISSUER, TokenFactory::CLIENT_ID);
    }

    private function now(): \DateTimeImmutable
    {
        return $this->clock->now();
    }

    private function impostorKey(): TestKey
    {
        $other = TestKey::get('impostor');
        $reflection = new \ReflectionClass(TestKey::class);
        $instance = $reflection->newInstanceWithoutConstructor();
        foreach (['kid' => TestKey::get()->kid, 'privatePem' => $other->privatePem, 'publicPem' => $other->publicPem, 'jwk' => $other->jwk] as $property => $value) {
            $reflection->getProperty($property)->setValue($instance, $value);
        }

        return $instance;
    }
}
