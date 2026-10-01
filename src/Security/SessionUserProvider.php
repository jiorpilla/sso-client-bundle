<?php

namespace Jiorpilla\SsoClientBundle\Security;

use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Default provider for apps without a users table: the user is built from the claims and
 * kept in the session.
 *
 * @implements UserProviderInterface<SsoUser>
 */
final class SessionUserProvider implements SsoUserProviderInterface, UserProviderInterface
{
    public function loadOrCreateUser(SsoClaims $claims): UserInterface
    {
        return SsoUser::fromClaims($claims);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof SsoUser) {
            throw new UnsupportedUserException(\sprintf('Instances of "%s" are not supported.', $user::class));
        }

        // Nothing to reload: the session copy is the only copy
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return SsoUser::class === $class;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        throw new UserNotFoundException('Session-only SSO users can only be created from a login.');
    }
}
