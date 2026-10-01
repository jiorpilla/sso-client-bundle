<?php

namespace Jiorpilla\SsoClientBundle\Security;

use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Remembers in-flight login requests (state, nonce, PKCE verifier) in the session.
 *
 * Keyed by state, so logins started in several tabs don't overwrite each other. Each
 * entry can be used once and expires after 10 minutes.
 */
final class PendingLoginStore
{
    private const string SESSION_KEY = '_sso_client.pending_logins';
    private const int MAX_PENDING = 5;
    private const int LIFETIME_SECONDS = 600;

    public function __construct(private readonly ClockInterface $clock)
    {
    }

    public function add(SessionInterface $session, string $state, string $nonce, string $codeVerifier, string $redirectUri): void
    {
        $pending = $this->valid($session);
        $pending[$state] = [
            'nonce' => $nonce,
            'code_verifier' => $codeVerifier,
            'redirect_uri' => $redirectUri,
            'created_at' => $this->clock->now()->getTimestamp(),
        ];

        // Keep only the newest few, so the session can't grow without bound
        $session->set(self::SESSION_KEY, \array_slice($pending, -self::MAX_PENDING, null, true));
    }

    /**
     * Returns and removes the login request for $state, or null if there is none.
     *
     * @return array{nonce: string, code_verifier: string, redirect_uri: string}|null
     */
    public function consume(SessionInterface $session, string $state): ?array
    {
        $pending = $this->valid($session);

        $match = null;
        foreach ($pending as $storedState => $request) {
            if (hash_equals($storedState, $state)) {
                $match = $storedState;
            }
        }

        if (null === $match) {
            $session->set(self::SESSION_KEY, $pending);

            return null;
        }

        $request = $pending[$match];
        unset($pending[$match]);
        $session->set(self::SESSION_KEY, $pending);

        return [
            'nonce' => $request['nonce'],
            'code_verifier' => $request['code_verifier'],
            'redirect_uri' => $request['redirect_uri'],
        ];
    }

    /**
     * @return array<string, array{nonce: string, code_verifier: string, redirect_uri: string, created_at: int}>
     */
    private function valid(SessionInterface $session): array
    {
        $pending = $session->get(self::SESSION_KEY, []);
        if (!\is_array($pending)) {
            return [];
        }

        $oldest = $this->clock->now()->getTimestamp() - self::LIFETIME_SECONDS;
        $valid = [];
        foreach ($pending as $state => $request) {
            if (\is_string($state) && \is_array($request) && \is_int($request['created_at'] ?? null) && $request['created_at'] >= $oldest
                && \is_string($request['nonce'] ?? null) && \is_string($request['code_verifier'] ?? null) && \is_string($request['redirect_uri'] ?? null)) {
                $valid[$state] = [
                    'nonce' => $request['nonce'],
                    'code_verifier' => $request['code_verifier'],
                    'redirect_uri' => $request['redirect_uri'],
                    'created_at' => $request['created_at'],
                ];
            }
        }

        return $valid;
    }
}
