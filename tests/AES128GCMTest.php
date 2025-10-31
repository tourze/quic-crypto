<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\AES128GCM;
use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * AES-128-GCM 测试类
 *
 * @internal
 */
#[CoversClass(AES128GCM::class)]
final class AES128GCMTest extends TestCase
{
    private AES128GCM $aes128gcm;

    protected function setUp(): void
    {
        parent::setUp();

        if (!AES128GCM::isSupported()) {
            self::markTestSkipped('AES-128-GCM 不被系统支持');
        }

        // 使用测试密钥
        $key = str_repeat("\x00", 16);
        $this->aes128gcm = new AES128GCM($key);
    }

    public function testBasicEncryptionDecryption(): void
    {
        $plaintext = 'Hello, QUIC!';
        $nonce = str_repeat("\x01", 12);
        $aad = 'additional authenticated data';

        $ciphertext = $this->aes128gcm->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->aes128gcm->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext));
    }

    public function testEmptyPlaintext(): void
    {
        $plaintext = '';
        $nonce = str_repeat("\x02", 12);
        $aad = '';

        $ciphertext = $this->aes128gcm->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->aes128gcm->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertEquals(16, strlen($ciphertext)); // 只有认证标签
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        new AES128GCM('invalid_key_length');
    }

    public function testInvalidNonceLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_NONCE);

        $plaintext = 'test';
        $invalidNonce = str_repeat("\x01", 11); // 错误长度
        $aad = '';

        $this->aes128gcm->encrypt($plaintext, $invalidNonce, $aad);
    }

    public function testAuthenticationFailure(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, QUIC!';
        $nonce = str_repeat("\x03", 12);
        $aad = 'original aad';

        $ciphertext = $this->aes128gcm->encrypt($plaintext, $nonce, $aad);

        // 尝试用不同的 AAD 解密
        $this->aes128gcm->decrypt($ciphertext, $nonce, 'modified aad');
    }

    public function testCiphertextTampering(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, QUIC!';
        $nonce = str_repeat("\x04", 12);
        $aad = '';

        $ciphertext = $this->aes128gcm->encrypt($plaintext, $nonce, $aad);

        // 篡改密文的第一个字节
        $tamperedCiphertext = chr(ord($ciphertext[0]) ^ 0x01) . substr($ciphertext, 1);

        $this->aes128gcm->decrypt($tamperedCiphertext, $nonce, $aad);
    }

    public function testGetters(): void
    {
        $this->assertEquals(16, $this->aes128gcm->getKeyLength());
        $this->assertEquals(12, $this->aes128gcm->getNonceLength());
        $this->assertEquals(16, $this->aes128gcm->getTagLength());
        $this->assertEquals('AES-128-GCM', $this->aes128gcm->getAlgorithmName());
    }

    public function testKnownVector(): void
    {
        // RFC 5116 测试向量
        $key = hex2bin('00000000000000000000000000000000');
        $nonce = hex2bin('000000000000000000000000');

        $this->assertIsString($key);
        $this->assertIsString($nonce);
        $plaintext = '';
        $aad = '';

        $aes = new AES128GCM($key);
        $ciphertext = $aes->encrypt($plaintext, $nonce, $aad);

        // 期望的认证标签
        $expectedTag = hex2bin('58e2fccefa7e3061367f1d57a4e7455a');
        $actualTag = substr($ciphertext, -16);

        $this->assertEquals($expectedTag, $actualTag);
    }

    public function testStaticSupport(): void
    {
        $this->assertTrue(AES128GCM::isSupported());
    }

    public function testEncrypt(): void
    {
        $plaintext = 'Test encrypt method';
        $nonce = str_repeat("\x01", 12);
        $aad = 'test aad';

        $ciphertext = $this->aes128gcm->encrypt($plaintext, $nonce, $aad);

        $this->assertIsString($ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext));
        $this->assertNotEquals($plaintext, $ciphertext);
    }

    public function testDecrypt(): void
    {
        $plaintext = 'Test decrypt method';
        $nonce = str_repeat("\x02", 12);
        $aad = 'test aad';

        $ciphertext = $this->aes128gcm->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->aes128gcm->decrypt($ciphertext, $nonce, $aad);

        $this->assertIsString($decrypted);
        $this->assertEquals($plaintext, $decrypted);
    }
}
