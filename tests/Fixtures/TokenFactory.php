<?php

namespace Jiorpilla\SsoClientBundle\Tests\Fixtures;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;

/**
 * Builds JWTs the way the SSO does, for tests.
 */
final class TokenFactory
{
    public const string ISSUER = 'https://sso.test';
    public const string CLIENT_ID = 'test-client';
    public const string SUB = '01a0f616-560f-7c09-8707-06b564f7aae8';

    /**
     * @param array<string, mixed> $claims overrides; null removes a claim
     */
    public static function idToken(array $claims = [], ?TestKey $key = null, ?\DateTimeImmutable $now = null): string
    {
        return self::sign([
            'sub' => self::SUB,
            'email' => 'jan@example.com',
            'email_verified' => true,
            'name' => 'Jan Test',
            'roles' => ['ROLE_ADMIN'],
            'nonce' => 'test-nonce',
            ...$claims,
        ], $key, $now);
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function accessToken(array $claims = [], ?TestKey $key = null, ?\DateTimeImmutable $now = null): string
    {
        return self::sign([
            'sub' => self::SUB,
            'scopes' => ['openid', 'profile', 'email', 'roles'],
            'client_id' => self::CLIENT_ID,
            'jti' => bin2hex(random_bytes(8)),
            ...$claims,
        ], $key, $now);
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function logoutToken(array $claims = [], ?\DateTimeImmutable $now = null): string
    {
        return self::sign([
            'sub' => self::SUB,
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()],
            'jti' => bin2hex(random_bytes(8)),
            'exp' => null,
            ...$claims,
        ], null, $now);
    }

    /**
     * A token signed with HS256 using the public key as the secret: the classic
     * algorithm confusion attack.
     */
    public static function hs256WithPublicKey(): string
    {
        $key = TestKey::get();
        $now = new \DateTimeImmutable();

        return (new Builder(new JoseEncoder(), ChainedFormatter::default()))
            ->withHeader('kid', $key->kid)
            ->issuedBy(self::ISSUER)
            ->permittedFor(self::CLIENT_ID)
            ->relatedTo(self::SUB)
            ->issuedAt($now)
            ->expiresAt($now->modify('+10 minutes'))
            ->getToken(new HmacSha256(), InMemory::plainText(self::str($key->publicPem)))
            ->toString();
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function sign(array $claims, ?TestKey $key, ?\DateTimeImmutable $now): string
    {
        $key ??= TestKey::get();
        $now ??= new \DateTimeImmutable();

        $claims = [
            'iss' => self::ISSUER,
            'aud' => self::CLIENT_ID,
            'iat' => $now,
            'exp' => $now->modify('+10 minutes'),
            ...$claims,
        ];

        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::default()))->withHeader('kid', $key->kid);

        foreach ($claims as $name => $value) {
            if (null === $value) {
                continue;
            }
            $builder = match ($name) {
                'iss' => $builder->issuedBy(self::str($value)),
                'aud' => $builder->permittedFor(...array_map(self::str(...), (array) $value)),
                'sub' => $builder->relatedTo(self::str($value)),
                'jti' => $builder->identifiedBy(self::str($value)),
                'iat' => $builder->issuedAt(self::date($value)),
                'exp' => $builder->expiresAt(self::date($value)),
                'nbf' => $builder->canOnlyBeUsedAfter(self::date($value)),
                default => $builder->withClaim(self::str($name), $value),
            };
        }

        return $builder->getToken(new Sha256(), InMemory::plainText(self::str($key->privatePem)))->toString();
    }

    /**
     * @return non-empty-string
     */
    private static function str(mixed $value): string
    {
        \assert(\is_string($value) && '' !== $value);

        return $value;
    }

    private static function date(mixed $value): \DateTimeImmutable
    {
        \assert($value instanceof \DateTimeImmutable);

        return $value;
    }
}
