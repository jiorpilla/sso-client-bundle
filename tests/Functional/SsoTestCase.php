<?php

namespace Jiorpilla\SsoClientBundle\Tests\Functional;

use Jiorpilla\SsoClientBundle\Client\Pkce;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\FakeSso;
use Jiorpilla\SsoClientBundle\Tests\Functional\App\FakeSsoHttpClient;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Contracts\Cache\CacheInterface;

abstract class SsoTestCase extends WebTestCase
{
    protected KernelBrowser $client;
    protected FakeSso $sso;

    protected function setUp(): void
    {
        $this->sso = new FakeSso();
        FakeSsoHttpClient::$sso = $this->sso;
        $this->client = static::createClient();

        /** @var CacheInterface&\Psr\Cache\CacheItemPoolInterface $cache */
        $cache = static::getContainer()->get('cache.app');
        $cache->clear();
    }

    protected function tearDown(): void
    {
        FakeSsoHttpClient::$sso = null;
        parent::tearDown();
    }

    /**
     * Starts the login and returns the authorization request parameters sent to the SSO.
     *
     * @return array<string, string>
     */
    protected function startLogin(string $url = '/protected'): array
    {
        $this->client->request('GET', $url);
        while ($this->client->getResponse()->isRedirect() && !str_starts_with((string) $this->client->getResponse()->headers->get('Location'), 'https://sso.test/')) {
            $this->client->followRedirect();
        }

        $location = (string) $this->client->getResponse()->headers->get('Location');
        self::assertStringStartsWith('https://sso.test/authorize?', $location);
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $params);

        /** @var array<string, string> $params */
        return $params;
    }

    /**
     * Runs the whole login and returns the authorization request parameters.
     *
     * @param array<string, mixed> $idTokenClaims
     *
     * @return array<string, string>
     */
    protected function login(string $url = '/protected', array $idTokenClaims = [], int $expiresIn = 600): array
    {
        $params = $this->startLogin($url);
        $this->sso->queueTokens(['nonce' => $params['nonce'], ...$idTokenClaims], expiresIn: $expiresIn);
        $this->client->request('GET', '/sso/callback', ['code' => 'auth-code', 'state' => $params['state']]);

        return $params;
    }

    /**
     * @return array<string, string>
     */
    protected function tokenRequestBody(int $index): array
    {
        $body = $this->sso->requestsTo('/token')[$index]['options']['body'] ?? '';
        parse_str(\is_string($body) ? $body : '', $parsed);

        /** @var array<string, string> $parsed */
        return $parsed;
    }

    protected static function assertPkceMatches(string $challenge, string $verifier): void
    {
        self::assertSame($challenge, Pkce::challenge($verifier));
    }
}
