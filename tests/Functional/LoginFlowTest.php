<?php

namespace Jiorpilla\SsoClientBundle\Tests\Functional;

use Jiorpilla\SsoClientBundle\Tests\Fixtures\TokenFactory;

final class LoginFlowTest extends SsoTestCase
{
    public function testAnonymousUserIsSentToTheSsoWithPkceStateAndNonce(): void
    {
        $this->client->request('GET', '/protected');
        self::assertResponseRedirects('/sso/login');

        $params = $this->startLogin();

        self::assertSame('code', $params['response_type']);
        self::assertSame(TokenFactory::CLIENT_ID, $params['client_id']);
        self::assertSame('http://localhost/sso/callback', $params['redirect_uri']);
        self::assertSame('openid profile email roles', $params['scope']);
        self::assertSame('S256', $params['code_challenge_method']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $params['code_challenge']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $params['state']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $params['nonce']);
        self::assertNotSame($params['state'], $params['nonce']);
    }

    public function testSuccessfulLoginReturnsToTheRequestedPage(): void
    {
        $params = $this->login('/protected');

        self::assertResponseRedirects('/protected');
        $this->client->followRedirect();
        self::assertResponseIsSuccessful();
        self::assertSame('Hello Jan Test ('.TokenFactory::SUB.') ROLE_ADMIN,ROLE_USER', $this->client->getResponse()->getContent());

        // The code was exchanged with the PKCE verifier matching the challenge
        $body = $this->tokenRequestBody(0);
        self::assertSame('authorization_code', $body['grant_type']);
        self::assertSame('auth-code', $body['code']);
        self::assertSame('http://localhost/sso/callback', $body['redirect_uri']);
        self::assertPkceMatches($params['code_challenge'], $body['code_verifier']);
    }

    public function testLoginFromThePublicLoginLinkGoesToTheDefaultPage(): void
    {
        $params = $this->startLogin('/sso/login');
        $this->sso->queueTokens(['nonce' => $params['nonce']]);

        $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => $params['state']]);

        self::assertResponseRedirects('/');
    }

    public function testSafeTargetParameterIsHonoured(): void
    {
        $params = $this->startLogin('/sso/login?target='.urlencode('/protected?page=2'));
        $this->sso->queueTokens(['nonce' => $params['nonce']]);

        $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => $params['state']]);

        self::assertResponseRedirects('/protected?page=2');
    }

    public function testExternalTargetIsIgnored(): void
    {
        foreach (['//evil.example/x', 'https://evil.example', '/\\evil.example'] as $target) {
            $this->client->getCookieJar()->clear();
            $params = $this->startLogin('/sso/login?target='.urlencode($target));
            $this->sso->queueTokens(['nonce' => $params['nonce']]);

            $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => $params['state']]);

            self::assertResponseRedirects('/', message: 'Unsafe target: '.$target);
        }
    }

    public function testPromptLoginIsPassedThrough(): void
    {
        self::assertSame('login', $this->startLogin('/sso/login?prompt=login')['prompt']);
    }

    public function testUnknownPromptIsDropped(): void
    {
        self::assertArrayNotHasKey('prompt', $this->startLogin('/sso/login?prompt=consent'));
    }

    public function testStateMismatchIsRejected(): void
    {
        $this->startLogin();
        $this->sso->queueTokens();

        $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => 'forged-state']);

        self::assertResponseStatusCodeSame(401);
        self::assertStringContainsString('invalid or has expired', (string) $this->client->getResponse()->getContent());
        self::assertCount(0, $this->sso->requestsTo('/token'), 'The code must not be exchanged.');
    }

    public function testStateCanBeUsedOnlyOnce(): void
    {
        $params = $this->login();
        self::assertResponseRedirects('/protected');

        $this->sso->queueTokens(['nonce' => $params['nonce']]);
        $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => $params['state']]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testNonceMismatchIsRejected(): void
    {
        $params = $this->startLogin();
        $this->sso->queueTokens(['nonce' => 'not-the-nonce-we-sent']);

        $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => $params['state']]);

        self::assertResponseStatusCodeSame(401);
        self::assertStringContainsString('nonce', (string) $this->client->getResponse()->getContent());
        $this->client->request('GET', '/protected');
        self::assertResponseRedirects('/sso/login');
    }

    public function testIdTokenForAnotherAppIsRejected(): void
    {
        $params = $this->startLogin();
        $this->sso->queueTokens(['nonce' => $params['nonce'], 'aud' => 'another-app']);

        $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => $params['state']]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testErrorFromTheSsoIsShown(): void
    {
        $params = $this->startLogin();

        $this->client->request('GET', '/sso/callback', ['error' => 'access_denied', 'error_description' => '<b>Nope</b>', 'state' => $params['state']]);

        self::assertResponseStatusCodeSame(401);
        $content = (string) $this->client->getResponse()->getContent();
        self::assertStringContainsString('access_denied', $content);
        self::assertStringContainsString('&lt;b&gt;Nope&lt;/b&gt;', $content, 'SSO error text must be escaped.');
    }

    public function testRejectedCodeIsHandled(): void
    {
        $params = $this->startLogin();
        // No queued response: the fake SSO answers invalid_grant

        $this->client->request('GET', '/sso/callback', ['code' => 'reused-code', 'state' => $params['state']]);

        self::assertResponseStatusCodeSame(401);
        self::assertStringContainsString('invalid_grant', (string) $this->client->getResponse()->getContent());
    }
}
