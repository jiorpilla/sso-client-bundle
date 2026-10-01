<?php

namespace Jiorpilla\SsoClientBundle\EventListener;

use Jiorpilla\SsoClientBundle\Discovery\OidcDiscovery;
use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Jiorpilla\SsoClientBundle\Token\SsoTokenStorage;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * On logout, also signs the user out of the SSO (RP-initiated logout), when the SSO
 * supports it. Otherwise only the local logout happens.
 *
 * Priority 32: after Symfony's default logout redirect (64), before the session is
 * invalidated (0), so the ID token is still readable.
 */
final readonly class SsoLogoutListener
{
    public function __construct(
        private SsoTokenStorage $tokenStorage,
        private OidcDiscovery $discovery,
        private UrlGeneratorInterface $urlGenerator,
        private string $clientId,
        private ?string $postLogoutRedirectRoute = null,
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $idToken = $this->tokenStorage->getIdToken();
        $this->tokenStorage->clear();

        if (null === $idToken) {
            return;
        }

        try {
            $endSessionEndpoint = $this->discovery->getEndSessionEndpoint();
        } catch (SsoException) {
            // SSO unreachable: the local logout still happens
            return;
        }
        if (null === $endSessionEndpoint) {
            return;
        }

        $postLogoutRedirectUri = null !== $this->postLogoutRedirectRoute
            ? $this->urlGenerator->generate($this->postLogoutRedirectRoute, [], UrlGeneratorInterface::ABSOLUTE_URL)
            : $event->getRequest()->getSchemeAndHttpHost().$event->getRequest()->getBasePath().'/';

        $query = http_build_query([
            'id_token_hint' => $idToken,
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
        ], '', '&', \PHP_QUERY_RFC3986);

        $event->setResponse(new RedirectResponse($endSessionEndpoint.(str_contains($endSessionEndpoint, '?') ? '&' : '?').$query));
    }
}
