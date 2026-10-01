<?php

namespace Jiorpilla\SsoClientBundle\Controller;

use Jiorpilla\SsoClientBundle\Client\OidcClient;
use Jiorpilla\SsoClientBundle\Client\Pkce;
use Jiorpilla\SsoClientBundle\Event\SsoBackchannelLogoutEvent;
use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Jiorpilla\SsoClientBundle\Jwt\TokenVerifier;
use Jiorpilla\SsoClientBundle\Security\BackchannelLogoutRegistry;
use Jiorpilla\SsoClientBundle\Security\OidcAuthenticator;
use Jiorpilla\SsoClientBundle\Security\PendingLoginStore;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

final class SsoController
{
    use TargetPathTrait;

    private const array ALLOWED_PROMPTS = ['login', 'none'];

    public function __construct(
        private readonly OidcClient $client,
        private readonly PendingLoginStore $pendingLogins,
        private readonly TokenVerifier $verifier,
        private readonly BackchannelLogoutRegistry $logoutRegistry,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly string $firewallName,
    ) {
    }

    /**
     * Starts the login: redirects to the SSO with state, nonce and a PKCE challenge.
     *
     * Optional query parameters:
     *  - target: a path on this app to return to after login (e.g. "/orders?page=2")
     *  - prompt: "login" to force re-entering the password, "none" for a silent check
     */
    public function login(Request $request): Response
    {
        $session = $request->getSession();

        $target = $request->query->getString('target');
        if ($this->isSafeLocalPath($target)) {
            $this->saveTargetPath($session, $this->firewallName, $target);
        }

        $state = Pkce::randomToken();
        $nonce = Pkce::randomToken();
        $verifier = Pkce::generateVerifier();
        $redirectUri = $this->urlGenerator->generate(OidcAuthenticator::CALLBACK_ROUTE, [], UrlGeneratorInterface::ABSOLUTE_URL);

        $this->pendingLogins->add($session, $state, $nonce, $verifier, $redirectUri);

        $extra = [];
        $prompt = $request->query->getString('prompt');
        if (\in_array($prompt, self::ALLOWED_PROMPTS, true)) {
            $extra['prompt'] = $prompt;
        }

        $response = new RedirectResponse($this->client->getAuthorizationUrl($redirectUri, $state, $nonce, Pkce::challenge($verifier), $extra));
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    /**
     * Handled by OidcAuthenticator; reaching this means it isn't on the firewall.
     */
    public function callback(): never
    {
        throw new \LogicException('Add "sso_client.authenticator" to "custom_authenticators" on your firewall to handle the SSO callback.');
    }

    /**
     * Handled by the firewall's logout listener.
     */
    public function logout(): never
    {
        throw new \LogicException('Configure "logout: { path: sso_client_logout }" on your firewall.');
    }

    /**
     * OpenID Connect Back-Channel Logout: the SSO calls this, server to server, when a user
     * signs out. Their sessions in this app end on their next request.
     */
    public function backchannelLogout(Request $request): Response
    {
        $headers = ['Cache-Control' => 'no-store'];
        $logoutToken = $request->request->getString('logout_token');
        if ('' === $logoutToken) {
            return new JsonResponse(['error' => 'invalid_request', 'error_description' => 'Missing logout_token.'], 400, $headers);
        }

        try {
            $claims = $this->verifier->verifyLogoutToken($logoutToken);
        } catch (SsoException $e) {
            return new JsonResponse(['error' => 'invalid_request', 'error_description' => $e->getMessage()], 400, $headers);
        }

        $sub = '' !== $claims->sub ? $claims->sub : null;
        $sid = \is_string($claims->get('sid')) ? $claims->get('sid') : null;

        $issuedAt = $claims->get('iat');
        \assert(\is_int($issuedAt)); // verifyLogoutToken() requires iat
        $this->logoutRegistry->markLoggedOut($sub, $sid, $issuedAt);
        $this->eventDispatcher->dispatch(new SsoBackchannelLogoutEvent($sub, $sid, $claims));

        return new Response('', Response::HTTP_OK, $headers);
    }

    /**
     * Only paths on this app: blocks open redirects such as "//evil.example" or "https://…".
     */
    private function isSafeLocalPath(string $path): bool
    {
        return str_starts_with($path, '/')
            && !str_starts_with($path, '//')
            && !str_contains($path, '\\')
            && 1 !== preg_match('/[\x00-\x1F\x7F]/', $path);
    }
}
