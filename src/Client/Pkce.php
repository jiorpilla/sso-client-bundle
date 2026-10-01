<?php

namespace Jiorpilla\SsoClientBundle\Client;

/**
 * PKCE (RFC 7636) with the S256 method only.
 */
final class Pkce
{
    /**
     * 32 random bytes → 43-character verifier (the RFC minimum length is 43).
     */
    public static function generateVerifier(): string
    {
        return self::base64UrlEncode(random_bytes(32));
    }

    public static function challenge(string $verifier): string
    {
        return self::base64UrlEncode(hash('sha256', $verifier, true));
    }

    /**
     * Random value for `state` and `nonce`.
     */
    public static function randomToken(): string
    {
        return self::base64UrlEncode(random_bytes(32));
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
