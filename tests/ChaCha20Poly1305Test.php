<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\ChaCha20Poly1305;
use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * ChaCha20-Poly1305 测试类
 *
 * @internal
 */
#[CoversClass(ChaCha20Poly1305::class)]
final class ChaCha20Poly1305Test extends TestCase
{
    private ChaCha20Poly1305 $chacha20poly1305;

    protected function setUp(): void
    {
        parent::setUp();

        if (!ChaCha20Poly1305::isSupported()) {
            self::markTestSkipped('ChaCha20-Poly1305 不被系统支持');
        }

        // 使用测试密钥
        $key = str_repeat("\x00", 32);
        $this->chacha20poly1305 = new ChaCha20Poly1305($key);
    }

    public function testBasicEncryptionDecryption(): void
    {
        $plaintext = 'Hello, QUIC with ChaCha20-Poly1305!';
        $nonce = str_repeat("\x01", 12);
        $aad = 'additional authenticated data for chacha20';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext));
    }

    public function testEmptyPlaintext(): void
    {
        $plaintext = '';
        $nonce = str_repeat("\x02", 12);
        $aad = '';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertEquals(16, strlen($ciphertext)); // 只有认证标签
    }

    public function testLargeData(): void
    {
        $plaintext = str_repeat('C', 1024 * 128); // 128KB 数据
        $nonce = str_repeat("\x03", 12);
        $aad = 'large data test for chacha20';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDifferentNonces(): void
    {
        $plaintext = 'same plaintext for chacha20';
        $aad = 'same aad';
        $nonce1 = str_repeat("\x01", 12);
        $nonce2 = str_repeat("\x02", 12);

        $ciphertext1 = $this->chacha20poly1305->encrypt($plaintext, $nonce1, $aad);
        $ciphertext2 = $this->chacha20poly1305->encrypt($plaintext, $nonce2, $aad);

        // 相同明文用不同nonce应该产生不同密文
        $this->assertNotEquals($ciphertext1, $ciphertext2);

        // 都应该能正确解密
        $this->assertEquals($plaintext, $this->chacha20poly1305->decrypt($ciphertext1, $nonce1, $aad));
        $this->assertEquals($plaintext, $this->chacha20poly1305->decrypt($ciphertext2, $nonce2, $aad));
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        new ChaCha20Poly1305('invalid_key_length');
    }

    public function testShortKey(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        new ChaCha20Poly1305(str_repeat("\x00", 16)); // 短密钥
    }

    public function testLongKey(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        new ChaCha20Poly1305(str_repeat("\x00", 64)); // 过长的密钥
    }

    public function testInvalidNonceLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_NONCE);

        $plaintext = 'test';
        $invalidNonce = str_repeat("\x01", 11); // 错误长度
        $aad = '';

        $this->chacha20poly1305->encrypt($plaintext, $invalidNonce, $aad);
    }

    public function testShortNonce(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_NONCE);

        $this->chacha20poly1305->encrypt('test', str_repeat("\x01", 8), '');
    }

    public function testLongNonce(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_NONCE);

        $this->chacha20poly1305->encrypt('test', str_repeat("\x01", 16), '');
    }

    public function testAuthenticationFailure(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, ChaCha20!';
        $nonce = str_repeat("\x03", 12);
        $aad = 'original aad';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);

        // 尝试用不同的 AAD 解密
        $this->chacha20poly1305->decrypt($ciphertext, $nonce, 'modified aad');
    }

    public function testNonceReuse(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, ChaCha20!';
        $nonce = str_repeat("\x04", 12);
        $aad = 'original aad';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);

        // 尝试用不同的 nonce 解密
        $wrongNonce = str_repeat("\x05", 12);
        $this->chacha20poly1305->decrypt($ciphertext, $wrongNonce, $aad);
    }

    public function testCiphertextTampering(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, ChaCha20!';
        $nonce = str_repeat("\x04", 12);
        $aad = '';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);

        // 篡改密文的第一个字节
        $tamperedCiphertext = chr(ord($ciphertext[0]) ^ 0x01) . substr($ciphertext, 1);

        $this->chacha20poly1305->decrypt($tamperedCiphertext, $nonce, $aad);
    }

    public function testTagTampering(): void
    {
        $this->expectException(CryptoException::class);

        $plaintext = 'Hello, ChaCha20!';
        $nonce = str_repeat("\x05", 12);
        $aad = '';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);

        // 篡改认证标签的最后一个字节
        $tamperedCiphertext = substr($ciphertext, 0, -1) . chr(ord($ciphertext[-1]) ^ 0x01);

        $this->chacha20poly1305->decrypt($tamperedCiphertext, $nonce, $aad);
    }

    public function testShortCiphertext(): void
    {
        $this->expectException(CryptoException::class);

        $nonce = str_repeat("\x06", 12);
        $shortCiphertext = str_repeat("\x00", 10); // 小于16字节标签长度

        $this->chacha20poly1305->decrypt($shortCiphertext, $nonce, '');
    }

    public function testGetters(): void
    {
        $this->assertEquals(32, $this->chacha20poly1305->getKeyLength());
        $this->assertEquals(12, $this->chacha20poly1305->getNonceLength());
        $this->assertEquals(16, $this->chacha20poly1305->getTagLength());
        $this->assertEquals('ChaCha20-Poly1305', $this->chacha20poly1305->getAlgorithmName());
    }

    public function testStaticSupport(): void
    {
        $this->assertTrue(ChaCha20Poly1305::isSupported());
    }

    public function testWithRandomKey(): void
    {
        $randomKey = random_bytes(32);
        $chacha = new ChaCha20Poly1305($randomKey);

        $plaintext = 'Test with random key';
        $nonce = random_bytes(12);
        $aad = 'random test aad';

        $ciphertext = $chacha->encrypt($plaintext, $nonce, $aad);
        $decrypted = $chacha->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testMultipleInstancesWithSameKey(): void
    {
        $key = str_repeat("\xCC", 32);
        $chacha1 = new ChaCha20Poly1305($key);
        $chacha2 = new ChaCha20Poly1305($key);

        $plaintext = 'Test multiple instances';
        $nonce = str_repeat("\x07", 12);
        $aad = 'multi instance test';

        $ciphertext1 = $chacha1->encrypt($plaintext, $nonce, $aad);
        $decrypted2 = $chacha2->decrypt($ciphertext1, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted2);
    }

    public function testEmptyAAD(): void
    {
        $plaintext = 'Test without AAD';
        $nonce = str_repeat("\x08", 12);
        $aad = '';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testLongAAD(): void
    {
        $plaintext = 'Test with long AAD';
        $nonce = str_repeat("\x09", 12);
        $aad = str_repeat('additional authenticated data ', 100); // 长AAD

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testBinaryData(): void
    {
        $plaintext = "\x00\x01\x02\x03\x04\x05\xFF\xFE\xFD";
        $nonce = str_repeat("\x0A", 12);
        $aad = "\xFF\x00\xAA\x55";

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testPerformanceBaseline(): void
    {
        $plaintext = str_repeat('performance test data ', 1000); // ~22KB
        $nonce = str_repeat("\x0B", 12);
        $aad = 'performance test';

        $startTime = microtime(true);

        for ($i = 0; $i < 10; ++$i) {
            $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
            $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);
            $this->assertEquals($plaintext, $decrypted);
        }

        $endTime = microtime(true);
        $duration = $endTime - $startTime;

        // 确保性能在合理范围内（10次加解密操作应该在1秒内完成）
        $this->assertLessThan(1.0, $duration, 'ChaCha20-Poly1305 性能测试超时');
    }

    public function testEncrypt(): void
    {
        $plaintext = 'Test encrypt method for ChaCha20';
        $nonce = str_repeat("\x01", 12);
        $aad = 'test aad for chacha20';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);

        $this->assertIsString($ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext));
        $this->assertNotEquals($plaintext, $ciphertext);
    }

    public function testDecrypt(): void
    {
        $plaintext = 'Test decrypt method for ChaCha20';
        $nonce = str_repeat("\x02", 12);
        $aad = 'test aad for chacha20';

        $ciphertext = $this->chacha20poly1305->encrypt($plaintext, $nonce, $aad);
        $decrypted = $this->chacha20poly1305->decrypt($ciphertext, $nonce, $aad);

        $this->assertIsString($decrypted);
        $this->assertEquals($plaintext, $decrypted);
    }
}
