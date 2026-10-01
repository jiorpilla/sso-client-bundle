<?php

namespace Jiorpilla\SsoClientBundle\Security;

use Jiorpilla\SsoClientBundle\Client\OidcClient;
use Jiorpilla\SsoClientBundle\Event\SsoLoginEvent;
use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Jiorpilla\SsoClientBundle\Jwt\TokenVerifier;
use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Jiorpilla\SsoClientBundle\Model\TokenSet;
use Jiorpilla\SsoClientBundle\Token\SsoTokenStorage;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Completes the SSO login on the callback route (/sso/callback): checks state, exchanges
 * the code (with the PKCE verifier), verifies the ID token and nonce, then signs the user
 * in. Also acts as the firewall entry point, sending anonymous users to /sso/login.
 */
final class OidcAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    public const string LOGIN_ROUTE = 'sso_client_login';
    public const string CALLBACK_ROUTE = 'sso_client_callback';

    public function __construct(
        private readonly OidcClient $client,
        private readonly TokenVerifier $verifier,
        private readonly PendingLoginStore $pendingLogins,
        private readonly SsoTokenStorage $tokenStorage,
        private readonly SsoUserProviderInterface $userProvider,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly string $defaultTargetPath = '/',
        private readonly ?string $failurePath = null,
    ) {
    }

    public function supports(Request $request): bool
    {
        return self::CALLBACK_ROUTE === $request->attributes->get('_route');
    }

    public function authenticate(Request $request): Passport
    {
        $session = $request->getSession();

        $state = $request->query->getString('state');
        $login = '' !== $state ? $this->pendingLogins->consume($session, $state) : null;
        if (null === $login) {
            throw new CustomUserMessageAuthenticationException('This sign-in link is invalid or has expired. Please try again.');
        }

        if ($request->query->has('error')) {
            $error = $request->query->getString('error');
            $description = $request->query->getString('error_description');

            throw new CustomUserMessageAuthenticationException(\sprintf('The SSO refused the sign-in (%s)%s', $error, '' !== $description ? ': '.$description : '.'), ['error' => $error]);
        }

        $code = $request->query->getString('code');
        if ('' === $code) {
            throw new CustomUserMessageAuthenticationException('The SSO did not return an authorization code.');
        }

        try {
            $tokens = $this->client->exchangeCode($code, $login['code_verifier'], $login['redirect_uri']);
            if (null === $tokens->idToken) {
                throw new SsoException('The SSO did not return an ID token. Is the "openid" scope enabled for this client?');
            }
            $claims = $this->verifier->verifyIdToken($tokens->idToken, $login['nonce']);
        } catch (SsoException $e) {
            throw new CustomUserMessageAuthenticationException('Sign-in failed: '.$e->getMessage(), [], 0, $e);
        }

        $passport = new SelfValidatingPassport(new UserBadge(
            $claims->sub,
            fn () => $this->userProvider->loadOrCreateUser($claims),
        ));
        $passport->setAttribute('sso_claims', $claims);
        $passport->setAttribute('sso_tokens', $tokens);

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $token = parent::createToken($passport, $firewallName);
        $token->setAttribute('sso_claims', $passport->getAttribute('sso_claims'));
        $token->setAttribute('sso_tokens', $passport->getAttribute('sso_tokens'));

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        $claims = $token->getAttribute('sso_claims');
        $tokens = $token->getAttribute('sso_tokens');
        \assert($claims instanceof SsoClaims && $tokens instanceof TokenSet);

        // Not needed on the security token once stored in the session
        $token->setAttribute('sso_tokens', null);

        $this->tokenStorage->store($tokens, $claims);

        $user = $token->getUser();
        \assert(null !== $user);
        $this->eventDispatcher->dispatch(new SsoLoginEvent($user, $claims, $tokens, $request));

        $session = $request->getSession();
        $targetPath = $this->getTargetPath($session, $firewallName);
        $this->removeTargetPath($session, $firewallName);

        return new RedirectResponse($targetPath ?? $this->defaultTargetPath);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        if (null !== $this->failurePath) {
            $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

            return new RedirectResponse($this->failurePath);
        }

        $message = htmlspecialchars(strtr($exception->getMessageKey(), $exception->getMessageData()), \ENT_QUOTES);
        $retry = htmlspecialchars($this->urlGenerator->generate(self::LOGIN_ROUTE), \ENT_QUOTES);

        return new Response(
            \sprintf('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Sign-in failed</title></head><body><h1>Sign-in failed</h1><p>%s</p><p><a href="%s">Try again</a></p></body></html>', $message, $retry),
            Response::HTTP_UNAUTHORIZED,
        );
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        // Symfony has already saved the requested URL as the target path
        return new RedirectResponse($this->urlGenerator->generate(self::LOGIN_ROUTE));
    }
}
