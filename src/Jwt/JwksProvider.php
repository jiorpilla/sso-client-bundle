<?php

namespace Jiorpilla\SsoClientBundle\Jwt;

use Jiorpilla\SsoClientBundle\Discovery\OidcDiscovery;
use Jiorpilla\SsoClientBundle\Exception\InvalidTokenException;
use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Supplies the SSO's public signing keys, by key ID (kid), from its JWKS endpoint.
 *
 * Keys are cached. A token signed with an unknown kid triggers one fresh download, which
 * picks up a newly rotated key. To stop forged kids from hammering the SSO, that forced
 * download happens at most once per $refetchCooldown seconds.
 */
class JwksProvider implements ResetInterface
{
    /**
     * @var array<string, string>|null kid => PEM
     */
    private ?array $keys = null;

    private bool $fetchedThisRequest = false;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
        private readonly OidcDiscovery $discovery,
        private readonly ClockInterface $clock,
        private readonly int $cacheTtl = 3600,
        private readonly int $refetchCooldown = 60,
    ) {
    }

    public function getPublicKey(string $kid): string
    {
        $keys = $this->keys ??= $this->cachedKeys();
        if (isset($keys[$kid])) {
            return $keys[$kid];
        }

        // Keys downloaded moments ago are already fresh: no point downloading again
        if (!$this->fetchedThisRequest && $this->mayRefetch()) {
            $this->cache->delete($this->cacheKey());
            $keys = $this->keys = $this->cachedKeys();
            if (isset($keys[$kid])) {
                return $keys[$kid];
            }
        }

        throw new InvalidTokenException(\sprintf('No SSO signing key with kid "%s".', $kid));
    }

    /**
     * Forgets per-request state, for long-running workers (FrankenPHP, RoadRunner, Messenger).
     */
    public function reset(): void
    {
        $this->keys = null;
        $this->fetchedThisRequest = false;
    }

    /**
     * @return array<string, string>
     */
    private function cachedKeys(): array
    {
        /** @var array<string, string> $keys */
        $keys = $this->cache->get($this->cacheKey(), function (ItemInterface $item): array {
            $item->expiresAfter($this->cacheTtl);
            $this->fetchedThisRequest = true;

            return $this->fetch();
        });

        return $keys;
    }

    /**
     * @return array<string, string>
     */
    private function fetch(): array
    {
        try {
            $jwks = $this->httpClient->request('GET', $this->discovery->getJwksUri())->toArray();
        } catch (HttpExceptionInterface $e) {
            throw new SsoException('Could not load the SSO signing keys: '.$e->getMessage(), 0, $e);
        }

        $keys = [];
        foreach (\is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [] as $jwk) {
            if (!\is_array($jwk) || !\is_string($jwk['kid'] ?? null)) {
                continue;
            }
            try {
                $keys[$jwk['kid']] = JwkConverter::toPem($jwk);
            } catch (InvalidTokenException) {
                // Skip keys we can't use (e.g. encryption keys); keep the rest
            }
        }

        return $keys;
    }

    private function mayRefetch(): bool
    {
        $now = $this->clock->now()->getTimestamp();
        $last = $this->cache->get($this->cacheKey().'.refetch', static fn (): int => 0);

        if ($now - $last < $this->refetchCooldown) {
            return false;
        }

        $this->cache->delete($this->cacheKey().'.refetch');
        $this->cache->get($this->cacheKey().'.refetch', function (ItemInterface $item) use ($now): int {
            $item->expiresAfter($this->refetchCooldown);

            return $now;
        });

        return true;
    }

    private function cacheKey(): string
    {
        return 'sso_client.jwks.'.hash('xxh128', $this->discovery->getIssuer());
    }
}
