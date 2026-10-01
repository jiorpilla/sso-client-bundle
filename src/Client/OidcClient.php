<?php

namespace Jiorpilla\SsoClientBundle\Client;

use Jiorpilla\SsoClientBundle\Discovery\OidcDiscovery;
use Jiorpilla\SsoClientBundle\Exception\SsoException;
use Jiorpilla\SsoClientBundle\Model\TokenSet;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Talks to the SSO's authorization and token endpoints.
 */
class OidcClient
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly OidcDiscovery $discovery,
        private readonly ClockInterface $clock,
        private readonly string $clientId,
        private readonly ?string $clientSecret,
        private readonly array $scopes,
    ) {
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * @param array<string, string> $extraParameters e.g. ['prompt' => 'login']
     */
    public function getAuthorizationUrl(string $redirectUri, string $state, string $nonce, string $codeChallenge, array $extraParameters = []): string
    {
        $parameters = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ] + $extraParameters;

        $endpoint = $this->discovery->getAuthorizationEndpoint();

        return $endpoint.(str_contains($endpoint, '?') ? '&' : '?').http_build_query($parameters, '', '&', \PHP_QUERY_RFC3986);
    }

    public function exchangeCode(string $code, string $codeVerifier, string $redirectUri): TokenSet
    {
        return $this->requestTokens([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ]);
    }

    /**
     * The SSO rotates refresh tokens: the returned set holds a new refresh token, and the
     * old one stops working.
     */
    public function refresh(string $refreshToken): TokenSet
    {
        return $this->requestTokens([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);
    }

    /**
     * @param array<string, string> $body
     */
    private function requestTokens(array $body): TokenSet
    {
        $options = ['headers' => ['Accept' => 'application/json']];

        if (null !== $this->clientSecret && '' !== $this->clientSecret) {
            // client_secret_basic: RFC 6749 section 2.3.1 says to form-encode both parts first
            $options['auth_basic'] = [rawurlencode($this->clientId), rawurlencode($this->clientSecret)];
        } else {
            // Public client: identified by client_id, protected by PKCE
            $body['client_id'] = $this->clientId;
        }
        $options['body'] = $body;

        try {
            $response = $this->httpClient->request('POST', $this->discovery->getTokenEndpoint(), $options);
            /** @var array<string, mixed> $data */
            $data = $response->toArray(false);
            $status = $response->getStatusCode();
        } catch (HttpExceptionInterface $e) {
            throw new SsoException('The SSO token endpoint could not be reached: '.$e->getMessage(), 0, $e);
        }

        if ($status >= 400) {
            $error = \is_string($data['error'] ?? null) ? $data['error'] : 'unknown_error';
            $description = \is_string($data['error_description'] ?? null) ? $data['error_description'] : '';

            throw new SsoException(trim(\sprintf('The SSO rejected the token request (%s): %s', $error, $description)));
        }

        try {
            return TokenSet::fromTokenResponse($data, $this->clock->now());
        } catch (\InvalidArgumentException $e) {
            throw new SsoException($e->getMessage(), 0, $e);
        }
    }
}
