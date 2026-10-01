<?php

namespace Jiorpilla\SsoClientBundle\Model;

/**
 * Tokens returned by the SSO's token endpoint.
 */
final readonly class TokenSet
{
    public function __construct(
        public string $accessToken,
        public \DateTimeImmutable $expiresAt,
        public ?string $refreshToken = null,
        public ?string $idToken = null,
    ) {
    }

    /**
     * @param array<string, mixed> $response decoded token endpoint response
     */
    public static function fromTokenResponse(array $response, \DateTimeImmutable $now): self
    {
        $accessToken = $response['access_token'] ?? null;
        if (!\is_string($accessToken) || '' === $accessToken) {
            throw new \InvalidArgumentException('The token response has no access_token.');
        }

        $tokenType = $response['token_type'] ?? null;
        if (!\is_string($tokenType) || 0 !== strcasecmp($tokenType, 'Bearer')) {
            throw new \InvalidArgumentException('The token response is not a Bearer token.');
        }

        $expiresIn = $response['expires_in'] ?? null;
        $expiresIn = \is_int($expiresIn) || (\is_string($expiresIn) && ctype_digit($expiresIn)) ? (int) $expiresIn : 0;

        $refreshToken = $response['refresh_token'] ?? null;
        $idToken = $response['id_token'] ?? null;

        return new self(
            accessToken: $accessToken,
            expiresAt: $now->modify(\sprintf('+%d seconds', $expiresIn)),
            refreshToken: \is_string($refreshToken) && '' !== $refreshToken ? $refreshToken : null,
            idToken: \is_string($idToken) && '' !== $idToken ? $idToken : null,
        );
    }

    /**
     * True when the access token is expired or about to expire within $skewSeconds.
     */
    public function isExpired(\DateTimeImmutable $now, int $skewSeconds = 30): bool
    {
        return $now->modify(\sprintf('+%d seconds', $skewSeconds)) >= $this->expiresAt;
    }

    /**
     * A refreshed token set keeps the previous ID token when the SSO doesn't send a new one.
     */
    public function withPreviousIdToken(?string $idToken): self
    {
        return null !== $this->idToken ? $this : new self($this->accessToken, $this->expiresAt, $this->refreshToken, $idToken);
    }
}
