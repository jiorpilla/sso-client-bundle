<?php

namespace Jiorpilla\SsoClientBundle\Security;

use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Jiorpilla\SsoClientBundle\Jwt\TokenVerifier;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * For APIs: authenticates `Authorization: Bearer <access token>` requests by verifying
 * the SSO access token locally (signature, issuer, audience, expiry). No call to the SSO.
 *
 * Use it on a stateless firewall.
 */
final class BearerTokenAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    /**
     * @param list<string> $audiences accepted `aud` values; empty means this app's client ID
     */
    public function __construct(
        private readonly TokenVerifier $verifier,
        private readonly SsoUserProviderInterface $userProvider,
        private readonly array $audiences = [],
    ) {
    }

    public function supports(Request $request): bool
    {
        return str_starts_with((string) $request->headers->get('Authorization'), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $jwt = trim(substr((string) $request->headers->get('Authorization'), 7));
        if ('' === $jwt) {
            throw new CustomUserMessageAuthenticationException('Missing bearer token.');
        }

        try {
            $claims = $this->verifier->verifyAccessToken($jwt, $this->audiences ?: null);
        } catch (SsoException $e) {
            throw new CustomUserMessageAuthenticationException('Invalid access token.', [], 0, $e);
        }

        $passport = new SelfValidatingPassport(new UserBadge(
            $claims->sub,
            fn () => $this->userProvider->loadOrCreateUser($claims),
        ));
        $passport->setAttribute('sso_claims', $claims);

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $token = parent::createToken($passport, $firewallName);
        // Lets controllers read scopes: $token->getAttribute('sso_claims')->scopes
        $token->setAttribute('sso_claims', $passport->getAttribute('sso_claims'));

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $this->unauthorized('invalid_token', strtr($exception->getMessageKey(), $exception->getMessageData()));
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return $this->unauthorized(null, 'Authentication required.');
    }

    private function unauthorized(?string $error, string $description): JsonResponse
    {
        // RFC 6750, section 3
        $challenge = null === $error ? 'Bearer' : \sprintf('Bearer error="%s", error_description="%s"', $error, addcslashes($description, '"\\'));

        return new JsonResponse(
            ['error' => $error ?? 'unauthorized', 'error_description' => $description],
            Response::HTTP_UNAUTHORIZED,
            ['WWW-Authenticate' => $challenge],
        );
    }
}
