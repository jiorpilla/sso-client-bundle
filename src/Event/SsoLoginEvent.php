<?php

namespace Jiorpilla\SsoClientBundle\Event;

use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Jiorpilla\SsoClientBundle\Model\TokenSet;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Dispatched after a successful SSO login, once the user is authenticated in this app.
 */
final readonly class SsoLoginEvent
{
    public function __construct(
        public UserInterface $user,
        public SsoClaims $claims,
        public TokenSet $tokens,
        public Request $request,
    ) {
    }
}
