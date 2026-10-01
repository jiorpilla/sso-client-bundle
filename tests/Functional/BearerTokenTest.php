<?php

namespace Jiorpilla\SsoClientBundle\Tests\Functional;

use Jiorpilla\SsoClientBundle\Tests\Fixtures\TestKey;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\TokenFactory;

final class BearerTokenTest extends SsoTestCase
{
    public function testValidAccessTokenIsAccepted(): void
    {
        $this->client->request('GET', '/api/me', server: ['HTTP_AUTHORIZATION' => 'Bearer '.TokenFactory::accessToken()]);

        self::assertResponseIsSuccessful();
        self::assertJsonStringEqualsJsonString(
            (string) json_encode(['sub' => TokenFactory::SUB, 'scopes' => ['openid', 'profile', 'email', 'roles']]),
            (string) $this->client->getResponse()->getContent(),
        );
        self::assertCount(0, $this->sso->requestsTo('/token'), 'Verification must be local.');
    }

    public function testExpiredAccessTokenIsRejected(): void
    {
        $token = TokenFactory::accessToken(now: new \DateTimeImmutable('-1 hour'));

        $this->client->request('GET', '/api/me', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        self::assertResponseStatusCodeSame(401);
        self::assertStringStartsWith('Bearer error="invalid_token"', (string) $this->client->getResponse()->headers->get('WWW-Authenticate'));
    }

    public function testForgedAccessTokenIsRejected(): void
    {
        $this->client->request('GET', '/api/me', server: ['HTTP_AUTHORIZATION' => 'Bearer '.TokenFactory::accessToken(key: TestKey::get('unpublished'))]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testMissingTokenGetsABearerChallenge(): void
    {
        $this->client->request('GET', '/api/me');

        self::assertResponseStatusCodeSame(401);
        self::assertResponseHeaderSame('WWW-Authenticate', 'Bearer');
    }
}
