<?php

namespace Jiorpilla\SsoClientBundle\Jwt;

use Jiorpilla\SsoClientBundle\Exception\InvalidTokenException;

/**
 * Converts an RSA public JWK (RFC 7517) into a PEM public key that OpenSSL and
 * lcobucci/jwt understand.
 *
 * This only re-encodes the modulus and exponent into the standard DER structure
 * (SubjectPublicKeyInfo); no cryptography happens here. OpenSSL then parses and
 * validates the result.
 */
final class JwkConverter
{
    private const int MIN_KEY_BITS = 2048;

    // DER: SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
    private const string RSA_ALGORITHM_IDENTIFIER = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

    /**
     * @param array<mixed> $jwk
     */
    public static function toPem(array $jwk): string
    {
        if ('RSA' !== ($jwk['kty'] ?? null)) {
            throw new InvalidTokenException('Only RSA keys are supported.');
        }
        if (isset($jwk['use']) && 'sig' !== $jwk['use']) {
            throw new InvalidTokenException('The key is not meant for signatures.');
        }
        if (isset($jwk['alg']) && 'RS256' !== $jwk['alg']) {
            throw new InvalidTokenException('The key is not meant for RS256.');
        }
        if (!\is_string($jwk['n'] ?? null) || !\is_string($jwk['e'] ?? null)) {
            throw new InvalidTokenException('The RSA key is missing "n" or "e".');
        }

        $modulus = self::base64UrlDecode($jwk['n']);
        $exponent = self::base64UrlDecode($jwk['e']);

        $rsaPublicKey = self::sequence(self::integer($modulus).self::integer($exponent));
        // BIT STRING with 0 unused bits
        $bitString = "\x03".self::length(\strlen($rsaPublicKey) + 1)."\x00".$rsaPublicKey;
        $der = self::sequence(self::RSA_ALGORITHM_IDENTIFIER.$bitString);

        $pem = "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";

        $key = openssl_pkey_get_public($pem);
        if (false === $key) {
            throw new InvalidTokenException('The RSA key could not be parsed.');
        }
        $details = openssl_pkey_get_details($key);
        if (false === $details || \OPENSSL_KEYTYPE_RSA !== $details['type'] || $details['bits'] < self::MIN_KEY_BITS) {
            throw new InvalidTokenException(\sprintf('RSA keys must be at least %d bits.', self::MIN_KEY_BITS));
        }

        return $pem;
    }

    private static function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if (false === $decoded || '' === $decoded) {
            throw new InvalidTokenException('Invalid base64url value in JWK.');
        }

        return $decoded;
    }

    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        // A leading 1 bit would make the INTEGER negative, so pad with a zero byte
        if ('' === $bytes || \ord($bytes[0]) > 0x7F) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".self::length(\strlen($bytes)).$bytes;
    }

    private static function sequence(string $content): string
    {
        return "\x30".self::length(\strlen($content)).$content;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return \chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return \chr(0x80 | \strlen($bytes)).$bytes;
    }
}
