<?php

namespace Jiorpilla\SsoClientBundle\Discovery;

use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Reads the SSO's /.well-known/openid-configuration document, so endpoint URLs never
 * need to be configured by hand. The document is cached.
 */
class OidcDiscovery
{
    /**
     * @var array<string, mixed>|null
     */
    private ?array $document = null;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
        private readonly string $issuer,
        private readonly int $cacheTtl = 3600,
    ) {
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getAuthorizationEndpoint(): string
    {
        return $this->requireString('authorization_endpoint');
    }

    public function getTokenEndpoint(): string
    {
        return $this->requireString('token_endpoint');
    }

    public function getJwksUri(): string
    {
        return $this->requireString('jwks_uri');
    }

    public function getUserinfoEndpoint(): ?string
    {
        return $this->optionalString('userinfo_endpoint');
    }

    /**
     * Null while the SSO doesn't support RP-initiated logout.
     */
    public function getEndSessionEndpoint(): ?string
    {
        return $this->optionalString('end_session_endpoint');
    }

    /**
     * @return array<string, mixed>
     */
    public function getDocument(): array
    {
        if (null !== $this->document) {
            return $this->document;
        }

        /** @var array<string, mixed> $document */
        $document = $this->cache->get($this->cacheKey(), function (ItemInterface $item): array {
            $item->expiresAfter($this->cacheTtl);

            return $this->fetch();
        });

        return $this->document = $document;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(): array
    {
        $url = rtrim($this->issuer, '/').'/.well-known/openid-configuration';

        try {
            /** @var array<string, mixed> $document */
            $document = $this->httpClient->request('GET', $url)->toArray();
        } catch (HttpExceptionInterface $e) {
            throw new SsoException(\sprintf('Could not load the SSO discovery document from "%s": %s', $url, $e->getMessage()), 0, $e);
        }

        // OpenID Connect Discovery 1.0, section 4.3: the issuer must match exactly
        if (($document['issuer'] ?? null) !== $this->issuer) {
            throw new SsoException(\sprintf('The discovery document issuer "%s" does not match the configured issuer "%s".', \is_string($document['issuer'] ?? null) ? $document['issuer'] : '', $this->issuer));
        }

        return $document;
    }

    private function requireString(string $key): string
    {
        $value = $this->optionalString($key);
        if (null === $value) {
            throw new SsoException(\sprintf('The SSO discovery document has no "%s".', $key));
        }

        return $value;
    }

    private function optionalString(string $key): ?string
    {
        $value = $this->getDocument()[$key] ?? null;

        return \is_string($value) && '' !== $value ? $value : null;
    }

    private function cacheKey(): string
    {
        return 'sso_client.discovery.'.hash('xxh128', $this->issuer);
    }
}
