<?php

namespace Jiorpilla\SsoClientBundle\Tests\Functional\App;

use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Jiorpilla\SsoClientBundle\Security\SsoUser;
use Jiorpilla\SsoClientBundle\Token\SsoTokenStorage;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class TestController
{
    #[Route('/', name: 'home')]
    public function home(): Response
    {
        return new Response('home');
    }

    #[Route('/protected', name: 'protected')]
    public function protected(Security $security): Response
    {
        $user = $security->getUser();
        \assert($user instanceof SsoUser);

        return new Response(\sprintf('Hello %s (%s) %s', $user->getName(), $user->getUserIdentifier(), implode(',', $user->getRoles())));
    }

    #[Route('/access-token', name: 'access_token')]
    public function accessToken(SsoTokenStorage $tokens): Response
    {
        return new Response($tokens->getAccessToken());
    }

    #[Route('/api/me', name: 'api_me')]
    public function apiMe(Security $security): JsonResponse
    {
        $claims = $security->getToken()?->getAttribute('sso_claims');
        \assert($claims instanceof SsoClaims);

        return new JsonResponse(['sub' => $claims->sub, 'scopes' => $claims->scopes]);
    }
}
