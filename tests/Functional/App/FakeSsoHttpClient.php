<?php

namespace Jiorpilla\SsoClientBundle\Tests\Functional\App;

use Jiorpilla\SsoClientBundle\Tests\Fixtures\FakeSso;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

/**
 * Routes the bundle's HTTP calls to the current test's FakeSso. Static, because the test
 * client boots a fresh kernel for each request.
 */
final class FakeSsoHttpClient implements HttpClientInterface
{
    public static ?FakeSso $sso = null;

    /**
     * @param array<mixed> $options
     */
    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        return $this->sso()->httpClient()->request($method, $url, $options);
    }

    public function stream(ResponseInterface|iterable $responses, ?float $timeout = null): ResponseStreamInterface
    {
        return $this->sso()->httpClient()->stream($responses, $timeout);
    }

    /**
     * @param array<mixed> $options
     */
    public function withOptions(array $options): static
    {
        return $this;
    }

    private function sso(): FakeSso
    {
        return self::$sso ?? throw new \LogicException('Set FakeSsoHttpClient::$sso in the test.');
    }
}
