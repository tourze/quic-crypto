<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\AES256GCM;
use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * AES-256-GCM 测试类
 *
 * @internal
 */
#[CoversClass(AES256GCM::class)]
final class AES256GCMTest extends TestCase
{
    private AES256GCM $aes256gcm;

    protected function setUp(): void
    {
        parent::setUp();

        if (!AES256GCM::isSupported()) {
            self::markTestSkipped('AES-256-GCM 不被系统支持');
        }

        // 使用测试密钥
        $key = str_repeat("\x00", 32);
        $this->aes256gcm = new AES256GCM($key);
    }

    public function testBasicEncryptionDecryption(): void
    {
        $plaintext = 'Hello, QUIC with AES-256-GCM!';
        $nonce = str_repeat("\x01", 12);
        $aad = 'additional authenticated data for 256';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->aes256gcm->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext));
    }

    public function testEmptyPlaintext(): void
    {
        $plaintext = '';
        $nonce = str_repeat("\x02", 12);
        $aad = '';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->aes256gcm->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertEquals(16, strlen($ciphertext)); // 只有认证标签
    }

    public function testLargeData(): void
    {
        $plaintext = str_repeat('A', 1024 * 64); // 64KB 数据
        $nonce = str_repeat("\x03", 12);
        $aad = 'large data test';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->aes256gcm->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDifferentNonces(): void
    {
        $plaintext = 'same plaintext';
        $aad = 'same aad';
        $nonce1 = str_repeat("\x01", 12);
        $nonce2 = str_repeat("\x02", 12);

        $ciphertext1 = $this->aes256gcm->encrypt($plaintext, $nonce1, $aad);
        $ciphertext2 = $this->aes256gcm->encrypt($plaintext, $nonce2, $aad);

        // 相同明文用不同nonce应该产生不同密文
        $this->assertNotEquals($ciphertext1, $ciphertext2);

        // 都应该能正确解密
        $this->assertEquals($plaintext, $this->aes256gcm->decrypt($ciphertext1, $nonce1, $aad));
        $this->assertEquals($plaintext, $this->aes256gcm->decrypt($ciphertext2, $nonce2, $aad));
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        new AES256GCM('invalid_key_length');
    }

    public function testShortKey(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        new AES256GCM(str_repeat("\x00", 16)); // AES-128 key for AES-256
    }

    public function testLongKey(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        new AES256GCM(str_repeat("\x00", 48)); // 过长的密钥
    }

    public function testInvalidNonceLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_NONCE);

        $plaintext = 'test';
        $invalidNonce = str_repeat("\x01", 11); // 错误长度
        $aad = '';

        $this->aes256gcm->encrypt($plaintext, $invalidNonce, $aad);
    }

    public function testShortNonce(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_NONCE);

        $this->aes256gcm->encrypt('test', str_repeat("\x01", 8), '');
    }

    public function testLongNonce(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_NONCE);

        $this->aes256gcm->encrypt('test', str_repeat("\x01", 16), '');
    }

    public function testAuthenticationFailure(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, QUIC!';
        $nonce = str_repeat("\x03", 12);
        $aad = 'original aad';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);

        // 尝试用不同的 AAD 解密
        $this->aes256gcm->decrypt($ciphertext, $nonce, 'modified aad');
    }

    public function testNonceReuse(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, QUIC!';
        $nonce = str_repeat("\x04", 12);
        $aad = 'original aad';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);

        // 尝试用不同的 nonce 解密
        $wrongNonce = str_repeat("\x05", 12);
        $this->aes256gcm->decrypt($ciphertext, $wrongNonce, $aad);
    }

    public function testCiphertextTampering(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, QUIC!';
        $nonce = str_repeat("\x04", 12);
        $aad = '';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);

        // 篡改密文的第一个字节
        $tamperedCiphertext = chr(ord($ciphertext[0]) ^ 0x01) . substr($ciphertext, 1);

        $this->aes256gcm->decrypt($tamperedCiphertext, $nonce, $aad);
    }

    public function testTagTampering(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, QUIC!';
        $nonce = str_repeat("\x05", 12);
        $aad = '';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);

        // 篡改认证标签的最后一个字节
        $tamperedCiphertext = substr($ciphertext, 0, -1) . chr(ord($ciphertext[-1]) ^ 0x01);

        $this->aes256gcm->decrypt($tamperedCiphertext, $nonce, $aad);
    }

    public function testShortCiphertext(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::DECRYPTION_FAILED);

        $nonce = str_repeat("\x06", 12);
        $shortCiphertext = str_repeat("\x00", 10); // 小于16字节标签长度

        $this->aes256gcm->decrypt($shortCiphertext, $nonce, '');
    }

    public function testGetters(): void
    {
        $this->assertEquals(32, $this->aes256gcm->getKeyLength());
        $this->assertEquals(12, $this->aes256gcm->getNonceLength());
        $this->assertEquals(16, $this->aes256gcm->getTagLength());
        $this->assertEquals('AES-256-GCM', $this->aes256gcm->getAlgorithmName());
    }

    public function testStaticSupport(): void
    {
        $this->assertTrue(AES256GCM::isSupported());
    }

    public function testWithRandomKey(): void
    {
        $randomKey = random_bytes(32);
        $aes = new AES256GCM($randomKey);

        $plaintext = 'Test with random key';
        $nonce = random_bytes(12);
        $aad = 'random test aad';

        $ciphertext = $aes->encrypt($plaintext, $nonce, $aad);
        $decrypted = $aes->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testMultipleInstancesWithSameKey(): void
    {
        $key = str_repeat("\xAA", 32);
        $aes1 = new AES256GCM($key);
        $aes2 = new AES256GCM($key);

        $plaintext = 'Test multiple instances';
        $nonce = str_repeat("\x07", 12);
        $aad = 'multi instance test';

        $ciphertext1 = $aes1->encrypt($plaintext, $nonce, $aad);
        $decrypted2 = $aes2->decrypt($ciphertext1, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted2);
    }

    public function testEncrypt(): void
    {
        $plaintext = 'Test encrypt method for AES256';
        $nonce = str_repeat("\x01", 12);
        $aad = 'test aad for aes256';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);

        $this->assertIsString($ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext));
        $this->assertNotEquals($plaintext, $ciphertext);
    }

    public function testDecrypt(): void
    {
        $plaintext = 'Test decrypt method for AES256';
        $nonce = str_repeat("\x02", 12);
        $aad = 'test aad for aes256';

        $ciphertext = $this->aes256gcm->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->aes256gcm->decrypt($ciphertext, $nonce, $aad);

        $this->assertIsString($decrypted);
        $this->assertEquals($plaintext, $decrypted);
    }
}
