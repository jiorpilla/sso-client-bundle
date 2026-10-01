<?php

namespace Jiorpilla\SsoClientBundle\Security;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Remembers which SSO users (sub) and SSO sessions (sid) signed out, and when, so their
 * sessions in this app can be ended on their next request.
 *
 * The time recorded is the logout token's `iat`. A replayed old token therefore can't end
 * sessions that started after it was issued.
 */
final class BackchannelLogoutRegistry
{
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        // Long enough to outlive any session in this app (the SSO's refresh tokens last 30 days)
        private readonly int $ttl = 2_592_000,
    ) {
    }

    public function markLoggedOut(?string $sub, ?string $sid, int $loggedOutAt): void
    {
        foreach (array_filter(['sub' => $sub, 'sid' => $sid]) as $type => $value) {
            $item = $this->cache->getItem($this->key($type, $value));
            $previous = $item->get();
            $item->set(max(\is_int($previous) ? $previous : 0, $loggedOutAt));
            $item->expiresAfter($this->ttl);
            $this->cache->save($item);
        }
    }

    public function isLoggedOut(?string $sub, ?string $sid, int $authenticatedAt): bool
    {
        foreach (array_filter(['sub' => $sub, 'sid' => $sid]) as $type => $value) {
            $loggedOutAt = $this->cache->getItem($this->key($type, $value))->get();
            if (\is_int($loggedOutAt) && $loggedOutAt >= $authenticatedAt) {
                return true;
            }
        }

        return false;
    }

    private function key(string $type, string $value): string
    {
        return \sprintf('sso_client.logout.%s.%s', $type, hash('xxh128', $value));
    }
}
