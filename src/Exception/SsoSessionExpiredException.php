<?php

namespace Jiorpilla\SsoClientBundle\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * The SSO session can no longer be used (refresh failed or no tokens stored).
 *
 * It extends AuthenticationException so that, when thrown during a request, Symfony's
 * security layer sends the user through the login flow again.
 */
final class SsoSessionExpiredException extends AuthenticationException
{
    public function getMessageKey(): string
    {
        return 'Your session has expired. Please sign in again.';
    }
}
