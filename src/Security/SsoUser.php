<?php

namespace Jiorpilla\SsoClientBundle\Security;

use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A user that lives only in the session, built from SSO claims. Used by apps that don't
 * keep their own users table.
 */
final class SsoUser implements UserInterface, EquatableInterface
{
    /**
     * @param non-empty-string $sub
     * @param list<string>     $roles
     */
    public function __construct(
        private readonly string $sub,
        private readonly ?string $email = null,
        private readonly ?string $name = null,
        private readonly array $roles = [],
    ) {
    }

    public static function fromClaims(SsoClaims $claims): self
    {
        if ('' === $claims->sub) {
            throw new \InvalidArgumentException('Claims without a subject.');
        }

        // Only ROLE_* values become Symfony roles
        $roles = array_values(array_filter($claims->roles, static fn (string $role): bool => str_starts_with($role, 'ROLE_')));

        return new self($claims->sub, $claims->email, $claims->name, $roles);
    }

    /**
     * The SSO user ID (`sub`).
     */
    public function getUserIdentifier(): string
    {
        return $this->sub;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return array_values(array_unique([...$this->roles, 'ROLE_USER']));
    }

    public function isEqualTo(UserInterface $user): bool
    {
        return $user instanceof self && $user->sub === $this->sub && $user->getRoles() === $this->getRoles();
    }
}
