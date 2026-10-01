<?php

namespace Jiorpilla\SsoClientBundle\Tests\Unit;

use Jiorpilla\SsoClientBundle\Exception\InvalidTokenException;
use Jiorpilla\SsoClientBundle\Jwt\JwkConverter;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\TestKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class JwkConverterTest extends TestCase
{
    #[DataProvider('keySizes')]
    public function testProducesTheSamePublicKeyAsOpenssl(int $bits): void
    {
        $key = TestKey::get('size-'.$bits, $bits);

        self::assertSame($key->publicPem, JwkConverter::toPem($key->jwk));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function keySizes(): iterable
    {
        yield '2048' => [2048];
        yield '3072' => [3072];
        yield '4096' => [4096];
    }

    public function testRejectsWeakKeys(): void
    {
        $this->expectExceptionObject(new InvalidTokenException('RSA keys must be at least 2048 bits.'));

        JwkConverter::toPem(TestKey::get('weak', 1024)->jwk);
    }

    public function testRejectsNonRsaKeys(): void
    {
        $this->expectException(InvalidTokenException::class);

        JwkConverter::toPem(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'abc', 'y' => 'def']);
    }

    public function testRejectsEncryptionKeys(): void
    {
        $this->expectException(InvalidTokenException::class);

        JwkConverter::toPem(['use' => 'enc'] + TestKey::get()->jwk);
    }

    public function testRejectsGarbage(): void
    {
        $this->expectException(InvalidTokenException::class);

        JwkConverter::toPem(['kty' => 'RSA', 'n' => 'AAAA', 'e' => 'AQAB']);
    }
}
