<?php

namespace Jiorpilla\SsoClientBundle\Tests\Functional;

use Jiorpilla\SsoClientBundle\Tests\Fixtures\TokenFactory;

final class SessionTest extends SsoTestCase
{
    public function testFreshAccessTokenIsReturnedWithoutRefreshing(): void
    {
        $this->login();

        $this->client->request('GET', '/access-token');

        self::assertResponseIsSuccessful();
        self::assertCount(1, $this->sso->requestsTo('/token'));
    }

    public function testExpiredAccessTokenIsRefreshedAndTheRefreshTokenRotated(): void
    {
        // Expires within the 30-second safety margin, so it counts as expired
        $this->login(expiresIn: 10);
        $this->sso->queueTokens(refreshToken: 'refresh-2', expiresIn: 10);
        $this->sso->queueTokens(refreshToken: 'refresh-3');

        $this->client->request('GET', '/access-token');
        self::assertResponseIsSuccessful();
        self::assertSame(['grant_type' => 'refresh_token', 'refresh_token' => 'refresh-1'], $this->tokenRequestBody(1));

        // The next refresh uses the rotated token
        $this->client->request('GET', '/access-token');
        self::assertResponseIsSuccessful();
        self::assertSame(['grant_type' => 'refresh_token', 'refresh_token' => 'refresh-2'], $this->tokenRequestBody(2));
    }

    public function testFailedRefreshSignsTheUserOut(): void
    {
        $this->login(expiresIn: 10);
        $this->sso->queueTokenResponse(['error' => 'invalid_grant'], 400);

        $this->client->request('GET', '/access-token');

        self::assertResponseRedirects('/sso/login');
        $this->client->request('GET', '/protected');
        self::assertResponseRedirects('/sso/login');
    }

    public function testRefreshReturningAnotherUsersIdTokenSignsTheUserOut(): void
    {
        $this->login(expiresIn: 10);
        $this->sso->queueTokens(['sub' => 'someone-else']);

        $this->client->request('GET', '/access-token');

        self::assertResponseRedirects('/sso/login');
    }

    public function testLogoutWithoutEndSessionEndpointIsLocalOnly(): void
    {
        $this->login();
        $this->client->followRedirect();

        $this->client->request('GET', '/sso/logout');

        self::assertResponseRedirects('/');
        $this->client->request('GET', '/protected');
        self::assertResponseRedirects('/sso/login');
    }

    public function testLogoutAlsoSignsOutOfTheSsoWhenSupported(): void
    {
        $this->sso->withEndSession = true;
        $this->login();
        $this->client->followRedirect();

        $this->client->request('GET', '/sso/logout');

        $location = (string) $this->client->getResponse()->headers->get('Location');
        self::assertStringStartsWith('https://sso.test/logout?', $location);
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $params);
        self::assertSame(TokenFactory::CLIENT_ID, $params['client_id']);
        self::assertSame('http://localhost/', $params['post_logout_redirect_uri']);
        self::assertIsString($params['id_token_hint']);
        self::assertCount(3, explode('.', $params['id_token_hint']));

        $this->client->request('GET', '/protected');
        self::assertResponseRedirects('/sso/login');
    }

    public function testBackchannelLogoutEndsTheSession(): void
    {
        $this->login();
        $this->client->followRedirect();
        self::assertResponseIsSuccessful();

        // Issued one second after login, as the SSO would after the user signs out there
        $this->client->request('POST', '/sso/backchannel-logout', ['logout_token' => TokenFactory::logoutToken(now: new \DateTimeImmutable('+1 second'))]);
        self::assertResponseIsSuccessful();
        self::assertStringContainsString('no-store', (string) $this->client->getResponse()->headers->get('Cache-Control'));

        $this->client->request('GET', '/protected');
        self::assertResponseRedirects('/sso/login');
    }

    public function testReplayedOldLogoutTokenDoesNotEndNewerSessions(): void
    {
        $oldToken = TokenFactory::logoutToken(now: new \DateTimeImmutable('-1 hour'));
        $this->login();
        $this->client->followRedirect();

        $this->client->request('POST', '/sso/backchannel-logout', ['logout_token' => $oldToken]);
        self::assertResponseIsSuccessful();

        $this->client->request('GET', '/protected');
        self::assertResponseIsSuccessful();
    }

    public function testInvalidLogoutTokenIsRejected(): void
    {
        $this->client->request('POST', '/sso/backchannel-logout', ['logout_token' => TokenFactory::idToken()]);
        self::assertResponseStatusCodeSame(400);

        $this->client->request('POST', '/sso/backchannel-logout');
        self::assertResponseStatusCodeSame(400);
    }
}
