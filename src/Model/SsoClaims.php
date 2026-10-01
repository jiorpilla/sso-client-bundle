<?php

namespace Jiorpilla\SsoClientBundle\Model;

/**
 * Verified claims about the signed-in user, taken from an ID token or access token.
 *
 * `sub` is the stable user key: it never changes, unlike the email address.
 */
final readonly class SsoClaims
{
    /**
     * @param list<string>         $roles
     * @param list<string>         $scopes
     * @param array<string, mixed> $all    every claim in the token, for app-specific needs
     */
    public function __construct(
        public string $sub,
        public ?string $email = null,
        public bool $emailVerified = false,
        public ?string $name = null,
        public array $roles = [],
        public array $scopes = [],
        public array $all = [],
    ) {
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function fromArray(array $claims): self
    {
        $sub = $claims['sub'] ?? null;
        if (!\is_string($sub) || '' === $sub) {
            throw new \InvalidArgumentException('The token has no "sub" claim.');
        }

        return new self(
            sub: $sub,
            email: \is_string($claims['email'] ?? null) ? $claims['email'] : null,
            emailVerified: true === ($claims['email_verified'] ?? false),
            name: \is_string($claims['name'] ?? null) ? $claims['name'] : null,
            roles: self::stringList($claims['roles'] ?? []),
            scopes: self::scopes($claims),
            all: $claims,
        );
    }

    public function has(string $claim): bool
    {
        return \array_key_exists($claim, $this->all);
    }

    public function get(string $claim): mixed
    {
        return $this->all[$claim] ?? null;
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return list<string>
     */
    private static function scopes(array $claims): array
    {
        // league/oauth2-server uses "scopes" (array); RFC 9068 uses "scope" (space separated)
        if (isset($claims['scopes'])) {
            return self::stringList($claims['scopes']);
        }

        $scope = $claims['scope'] ?? null;

        return \is_string($scope) ? array_values(array_filter(explode(' ', $scope))) : [];
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (!\is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, is_string(...)));
    }
}
