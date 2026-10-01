<?php

namespace Jiorpilla\SsoClientBundle\Jwt;

use Jiorpilla\SsoClientBundle\Exception\InvalidTokenException;
use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Exception as JwtException;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Psr\Clock\ClockInterface;

/**
 * Verifies the SSO's RS256 JWTs locally, using its published public keys.
 *
 * Checks: RS256 signature with the key named by `kid`, issuer, audience, and expiry
 * (with a small leeway for clock drift). ID tokens are also checked against the nonce
 * sent in the login request.
 */
class TokenVerifier
{
    /**
     * @var non-empty-string
     */
    private readonly string $issuer;

    /**
     * @var non-empty-string
     */
    private readonly string $clientId;

    public function __construct(
        private readonly JwksProvider $jwks,
        private readonly ClockInterface $clock,
        string $issuer,
        string $clientId,
        private readonly int $leewaySeconds = 30,
    ) {
        if ('' === $issuer || '' === $clientId) {
            throw new \InvalidArgumentException('The SSO issuer and client ID must not be empty.');
        }
        $this->issuer = $issuer;
        $this->clientId = $clientId;
    }

    /**
     * @param string|null $expectedNonce the nonce from the login request; null when refreshing
     */
    public function verifyIdToken(string $jwt, ?string $expectedNonce): SsoClaims
    {
        $token = $this->verify($jwt, [$this->clientId]);

        if (null !== $expectedNonce) {
            $nonce = $token->claims()->get('nonce');
            if (!\is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
                throw new InvalidTokenException('The ID token nonce does not match the login request.');
            }
        }

        return SsoClaims::fromArray($this->claims($token));
    }

    /**
     * @param list<string>|null $audiences accepted `aud` values; defaults to this app's client ID
     */
    public function verifyAccessToken(string $jwt, ?array $audiences = null): SsoClaims
    {
        $audiences = array_values(array_filter($audiences ?? [], static fn (string $audience): bool => '' !== $audience));

        return SsoClaims::fromArray($this->claims($this->verify($jwt, $audiences ?: [$this->clientId])));
    }

    /**
     * Verifies a back-channel logout token (OpenID Connect Back-Channel Logout 1.0, section 2.6).
     */
    public function verifyLogoutToken(string $jwt): SsoClaims
    {
        $token = $this->verify($jwt, [$this->clientId], requireExpiry: false);
        $claims = $token->claims();

        $events = $claims->get('events');
        if (!\is_array($events) || !\array_key_exists('http://schemas.openid.net/event/backchannel-logout', $events)) {
            throw new InvalidTokenException('Not a back-channel logout token.');
        }
        if ($claims->has('nonce')) {
            throw new InvalidTokenException('A logout token must not contain a nonce.');
        }
        if (!$claims->has('sub') && !$claims->has('sid')) {
            throw new InvalidTokenException('A logout token must contain "sub" or "sid".');
        }
        if (!$claims->has('iat')) {
            throw new InvalidTokenException('A logout token must contain "iat".');
        }

        $all = $this->claims($token);

        // A sid-only token is valid, so sub may be empty here
        return new SsoClaims(sub: \is_string($all['sub'] ?? null) ? $all['sub'] : '', all: $all);
    }

    /**
     * @param non-empty-list<non-empty-string> $audiences
     */
    private function verify(string $jwt, array $audiences, bool $requireExpiry = true): UnencryptedToken
    {
        if ('' === $jwt) {
            throw new InvalidTokenException('Empty token.');
        }

        try {
            $token = (new Parser(new JoseEncoder()))->parse($jwt);
        } catch (JwtException $e) {
            throw new InvalidTokenException('Malformed token: '.$e->getMessage(), 0, $e);
        }
        \assert($token instanceof UnencryptedToken);

        // Only RS256 is accepted. Pinning the algorithm blocks "alg: none" and HS256/RS256 confusion.
        if ('RS256' !== $token->headers()->get('alg')) {
            throw new InvalidTokenException('Only RS256-signed tokens are accepted.');
        }
        $kid = $token->headers()->get('kid');
        if (!\is_string($kid) || '' === $kid) {
            throw new InvalidTokenException('The token has no key ID (kid).');
        }
        if ($requireExpiry && !$token->claims()->has('exp')) {
            throw new InvalidTokenException('The token has no expiry.');
        }

        $pem = $this->jwks->getPublicKey($kid);
        if ('' === $pem) {
            throw new InvalidTokenException('Empty signing key.');
        }

        $validator = new Validator();

        try {
            $validator->assert(
                $token,
                new SignedWith(new Sha256(), InMemory::plainText($pem)),
                new IssuedBy($this->issuer),
                new LooseValidAt($this->clock, new \DateInterval(\sprintf('PT%dS', $this->leewaySeconds))),
            );

            foreach ($audiences as $audience) {
                if ($validator->validate($token, new PermittedFor($audience))) {
                    return $token;
                }
            }
        } catch (JwtException $e) {
            throw new InvalidTokenException('Invalid token: '.$e->getMessage(), 0, $e);
        }

        throw new InvalidTokenException('The token was not issued for this application (audience mismatch).');
    }

    /**
     * Claims as plain values; lcobucci turns registered date claims into DateTimeImmutable.
     *
     * @return array<string, mixed>
     */
    private function claims(UnencryptedToken $token): array
    {
        $claims = [];
        foreach ($token->claims()->all() as $name => $value) {
            $claims[$name] = $value instanceof \DateTimeImmutable ? $value->getTimestamp() : $value;
        }

        return $claims;
    }
}
