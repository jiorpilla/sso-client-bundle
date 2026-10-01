<?php

namespace Jiorpilla\SsoClientBundle\Token;

use Jiorpilla\SsoClientBundle\Client\OidcClient;
use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Jiorpilla\SsoClientBundle\Exception\SsoSessionExpiredException;
use Jiorpilla\SsoClientBundle\Jwt\TokenVerifier;
use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Jiorpilla\SsoClientBundle\Model\TokenSet;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Keeps the signed-in user's SSO tokens in the session.
 *
 * Use getAccessToken() when calling APIs on the user's behalf: it refreshes the access
 * token when it is about to expire, and stores the new (rotated) refresh token. If the
 * refresh fails, the user is signed out of this app and SsoSessionExpiredException is
 * thrown, which sends them through the login flow again.
 */
class SsoTokenStorage
{
    private const string SESSION_KEY = '_sso_client.session';

    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly OidcClient $client,
        private readonly TokenVerifier $verifier,
        private readonly ClockInterface $clock,
        private readonly ?TokenStorageInterface $securityTokenStorage = null,
    ) {
    }

    public function store(TokenSet $tokens, SsoClaims $idTokenClaims): void
    {
        $sid = $idTokenClaims->get('sid');

        $this->session()->set(self::SESSION_KEY, [
            'tokens' => $tokens,
            'sub' => $idTokenClaims->sub,
            'sid' => \is_string($sid) ? $sid : null,
            'authenticated_at' => $this->clock->now()->getTimestamp(),
        ]);
    }

    public function getTokens(): ?TokenSet
    {
        return $this->data()['tokens'] ?? null;
    }

    public function getIdToken(): ?string
    {
        return $this->getTokens()?->idToken;
    }

    /**
     * The SSO user ID (`sub`) of the signed-in user.
     */
    public function getSubject(): ?string
    {
        return $this->data()['sub'] ?? null;
    }

    /**
     * The SSO session ID (`sid` claim), when the SSO provides one.
     */
    public function getSessionId(): ?string
    {
        return $this->data()['sid'] ?? null;
    }

    /**
     * When the user signed in to this app through the SSO (Unix timestamp).
     */
    public function getAuthenticatedAt(): ?int
    {
        return $this->data()['authenticated_at'] ?? null;
    }

    /**
     * A valid access token, refreshed first if needed.
     *
     * @throws SsoSessionExpiredException when there are no tokens or the refresh fails
     */
    public function getAccessToken(): string
    {
        $data = $this->data();
        $tokens = $data['tokens'] ?? null;
        if (null === $tokens) {
            throw new SsoSessionExpiredException('No SSO tokens in the session.');
        }

        if (!$tokens->isExpired($this->clock->now())) {
            return $tokens->accessToken;
        }

        if (null === $tokens->refreshToken) {
            $this->signOut();

            throw new SsoSessionExpiredException('The access token expired and there is no refresh token.');
        }

        try {
            $refreshed = $this->client->refresh($tokens->refreshToken)->withPreviousIdToken($tokens->idToken);

            // A new ID token must describe the same user (OIDC Core 1.0, section 12.2)
            if (null !== $refreshed->idToken && $refreshed->idToken !== $tokens->idToken) {
                $claims = $this->verifier->verifyIdToken($refreshed->idToken, null);
                if ($claims->sub !== ($data['sub'] ?? null)) {
                    throw new SsoException('The refreshed ID token is for a different user.');
                }
            }
        } catch (SsoException $e) {
            $this->signOut();

            throw new SsoSessionExpiredException('The SSO session could not be refreshed: '.$e->getMessage(), 0, $e);
        }

        $data['tokens'] = $refreshed;
        $this->session()->set(self::SESSION_KEY, $data);

        return $refreshed->accessToken;
    }

    public function clear(): void
    {
        $this->requestStack->getCurrentRequest()?->getSession()->remove(self::SESSION_KEY);
    }

    /**
     * Forgets the SSO tokens and the app's own authentication.
     */
    public function signOut(): void
    {
        $this->clear();
        $this->securityTokenStorage?->setToken(null);
    }

    /**
     * @return array{tokens?: TokenSet, sub?: string, sid?: string|null, authenticated_at?: int}
     */
    private function data(): array
    {
        $request = $this->requestStack->getCurrentRequest();
        if (null === $request || !$request->hasSession()) {
            return [];
        }

        $data = $request->getSession()->get(self::SESSION_KEY);
        if (!\is_array($data) || !($data['tokens'] ?? null) instanceof TokenSet) {
            return [];
        }

        /** @var array{tokens?: TokenSet, sub?: string, sid?: string|null, authenticated_at?: int} $data */
        return $data;
    }

    private function session(): SessionInterface
    {
        return $this->requestStack->getSession();
    }
}
