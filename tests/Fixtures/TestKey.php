<?php

namespace Jiorpilla\SsoClientBundle\Tests\Fixtures;

/**
 * RSA key pairs generated at test runtime; nothing secret is committed.
 */
final class TestKey
{
    /**
     * @var array<string, self>
     */
    private static array $keys = [];

    private function __construct(
        public readonly string $kid,
        public readonly string $privatePem,
        public readonly string $publicPem,
        /** @var array{kty: string, kid: string, use: string, alg: string, n: string, e: string} */
        public readonly array $jwk,
    ) {
    }

    public static function get(string $kid = 'test-key-1', int $bits = 2048): self
    {
        return self::$keys[$kid.$bits] ??= self::generate($kid, $bits);
    }

    private static function generate(string $kid, int $bits): self
    {
        $key = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
        \assert(false !== $key);
        openssl_pkey_export($key, $privatePem);
        \assert(\is_string($privatePem));
        $details = openssl_pkey_get_details($key);
        \assert(\is_array($details));

        /** @var array{n: string, e: string} $rsa */
        $rsa = $details['rsa'];
        /** @var string $publicPem */
        $publicPem = $details['key'];

        return new self($kid, $privatePem, $publicPem, [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => self::base64Url($rsa['n']),
            'e' => self::base64Url($rsa['e']),
        ]);
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
