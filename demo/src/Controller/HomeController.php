<?php

namespace App\Controller;

use Jiorpilla\SsoClientBundle\Token\SsoTokenStorage;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class HomeController extends AbstractController
{
    #[Route('/', name: 'home')]
    public function __invoke(SsoTokenStorage $tokens): Response
    {
        try {
            $hasAccessToken = '' !== $tokens->getAccessToken();
        } catch (\Throwable) {
            $hasAccessToken = false;
        }

        return $this->render('home.html.twig', [
            'subject' => $tokens->getSubject(),
            'has_access_token' => $hasAccessToken,
        ]);
    }
}
