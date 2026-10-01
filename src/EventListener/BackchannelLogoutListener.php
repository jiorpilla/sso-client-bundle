<?php

namespace Jiorpilla\SsoClientBundle\EventListener;

use Jiorpilla\SsoClientBundle\Security\BackchannelLogoutRegistry;
use Jiorpilla\SsoClientBundle\Token\SsoTokenStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Ends the session of a user the SSO reported as signed out (back-channel logout).
 *
 * Runs before the firewall (priority 9 > 8), so the request is handled as anonymous.
 */
final readonly class BackchannelLogoutListener
{
    public function __construct(
        private SsoTokenStorage $tokenStorage,
        private BackchannelLogoutRegistry $registry,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if (!$event->isMainRequest() || !$request->hasPreviousSession()) {
            return;
        }

        $authenticatedAt = $this->tokenStorage->getAuthenticatedAt();
        if (null === $authenticatedAt) {
            return;
        }

        if ($this->registry->isLoggedOut($this->tokenStorage->getSubject(), $this->tokenStorage->getSessionId(), $authenticatedAt)) {
            // Same as a normal logout: drop everything in this app's session
            $request->getSession()->invalidate();
        }
    }
}
