<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\AES128GCM;
use Tourze\QUIC\Crypto\AES256GCM;
use Tourze\QUIC\Crypto\ChaCha20Poly1305;
use Tourze\QUIC\Crypto\CryptoSuite;
use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * 密码套件管理测试类
 *
 * @internal
 */
#[CoversClass(CryptoSuite::class)]
final class CryptoSuiteTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // 没有特殊设置要求
    }

    public function testCreateAES128GCM(): void
    {
        $key = str_repeat("\x01", 16);
        $suite = CryptoSuite::createAES128GCM($key);

        $this->assertEquals('TLS_AES_128_GCM_SHA256', $suite->getName());
        $this->assertEquals('sha256', $suite->getHashAlgorithm());
        $this->assertEquals(16, $suite->getKeyLength());
        $this->assertEquals(12, $suite->getNonceLength());
        $this->assertEquals(16, $suite->getTagLength());
        $this->assertEquals(32, $suite->getHashLength());
        $this->assertTrue($suite->isSupported());
    }

    public function testCreateAES256GCM(): void
    {
        $key = str_repeat("\x02", 32);
        $suite = CryptoSuite::createAES256GCM($key);

        $this->assertEquals('TLS_AES_256_GCM_SHA384', $suite->getName());
        $this->assertEquals('sha384', $suite->getHashAlgorithm());
        $this->assertEquals(32, $suite->getKeyLength());
        $this->assertEquals(12, $suite->getNonceLength());
        $this->assertEquals(16, $suite->getTagLength());
        $this->assertEquals(48, $suite->getHashLength());
        $this->assertTrue($suite->isSupported());
    }

    public function testCreateChaCha20Poly1305(): void
    {
        if (!ChaCha20Poly1305::isSupported()) {
            self::markTestSkipped('ChaCha20-Poly1305 不被系统支持');
        }

        $key = str_repeat("\x03", 32);
        $suite = CryptoSuite::createChaCha20Poly1305($key);

        $this->assertEquals('TLS_CHACHA20_POLY1305_SHA256', $suite->getName());
        $this->assertEquals('sha256', $suite->getHashAlgorithm());
        $this->assertEquals(32, $suite->getKeyLength());
        $this->assertEquals(12, $suite->getNonceLength());
        $this->assertEquals(16, $suite->getTagLength());
        $this->assertEquals(32, $suite->getHashLength());
        $this->assertTrue($suite->isSupported());
    }

    public function testFromName(): void
    {
        $key128 = str_repeat("\x04", 16);
        $key256 = str_repeat("\x05", 32);

        $suite128 = CryptoSuite::fromName('TLS_AES_128_GCM_SHA256', $key128);
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $suite128->getName());
        $this->assertInstanceOf(AES128GCM::class, $suite128->getAEAD());

        $suite256 = CryptoSuite::fromName('TLS_AES_256_GCM_SHA384', $key256);
        $this->assertEquals('TLS_AES_256_GCM_SHA384', $suite256->getName());
        $this->assertInstanceOf(AES256GCM::class, $suite256->getAEAD());

        if (ChaCha20Poly1305::isSupported()) {
            $suiteChacha = CryptoSuite::fromName('TLS_CHACHA20_POLY1305_SHA256', $key256);
            $this->assertEquals('TLS_CHACHA20_POLY1305_SHA256', $suiteChacha->getName());
            $this->assertInstanceOf(ChaCha20Poly1305::class, $suiteChacha->getAEAD());
        }
    }

    public function testGetSupportedSuites(): void
    {
        $supportedSuites = CryptoSuite::getSupportedSuites();

        $this->assertContains('TLS_AES_128_GCM_SHA256', $supportedSuites);
        $this->assertContains('TLS_AES_256_GCM_SHA384', $supportedSuites);

        if (ChaCha20Poly1305::isSupported()) {
            $this->assertContains('TLS_CHACHA20_POLY1305_SHA256', $supportedSuites);
        }
    }

    public function testSelectBestSuite(): void
    {
        $bestSuite = CryptoSuite::selectBestSuite();
        $this->assertNotNull($bestSuite);

        $supportedSuites = CryptoSuite::getSupportedSuites();
        $this->assertContains($bestSuite, $supportedSuites);
    }

    public function testSelectBestSuiteWithPreferences(): void
    {
        $preferences = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'];
        $selectedSuite = CryptoSuite::selectBestSuite($preferences);

        $this->assertEquals('TLS_AES_128_GCM_SHA256', $selectedSuite);
    }

    public function testSelectBestSuiteUnsupportedPreferences(): void
    {
        $preferences = ['UNSUPPORTED_SUITE', 'ANOTHER_UNSUPPORTED'];
        $selectedSuite = CryptoSuite::selectBestSuite($preferences);

        // 不支持的套件应该返回 null，然后尝试默认套件
        if (null === $selectedSuite) {
            $defaultSuite = CryptoSuite::selectBestSuite();
            $this->assertNotNull($defaultSuite, '系统应该至少支持一个默认套件');
            $selectedSuite = $defaultSuite;
        }

        // 应该返回默认支持的套件
        $supportedSuites = CryptoSuite::getSupportedSuites();
        $this->assertContains($selectedSuite, $supportedSuites);
    }

    public function testIsCompatible(): void
    {
        $this->assertTrue(CryptoSuite::isCompatible('TLS_AES_128_GCM_SHA256'));
        $this->assertTrue(CryptoSuite::isCompatible('TLS_AES_256_GCM_SHA384'));
        $this->assertFalse(CryptoSuite::isCompatible('UNSUPPORTED_SUITE'));

        if (ChaCha20Poly1305::isSupported()) {
            $this->assertTrue(CryptoSuite::isCompatible('TLS_CHACHA20_POLY1305_SHA256'));
        }
    }

    public function testGetInfo(): void
    {
        $key = str_repeat("\x06", 16);
        $suite = CryptoSuite::createAES128GCM($key);
        $info = $suite->getInfo();

        $this->assertArrayHasKey('name', $info);
        $this->assertArrayHasKey('aead_algorithm', $info);
        $this->assertArrayHasKey('hash_algorithm', $info);
        $this->assertArrayHasKey('key_length', $info);
        $this->assertArrayHasKey('nonce_length', $info);
        $this->assertArrayHasKey('tag_length', $info);
        $this->assertArrayHasKey('hash_length', $info);
        $this->assertArrayHasKey('supported', $info);

        $this->assertEquals('TLS_AES_128_GCM_SHA256', $info['name']);
        $this->assertEquals('AES-128-GCM', $info['aead_algorithm']);
        $this->assertEquals('sha256', $info['hash_algorithm']);
        $this->assertEquals(16, $info['key_length']);
        $this->assertEquals(12, $info['nonce_length']);
        $this->assertEquals(16, $info['tag_length']);
        $this->assertEquals(32, $info['hash_length']);
        $this->assertTrue($info['supported']);
    }

    public function testGetAEAD(): void
    {
        $key = str_repeat("\x07", 16);
        $suite = CryptoSuite::createAES128GCM($key);
        $aead = $suite->getAEAD();

        $this->assertInstanceOf(AES128GCM::class, $aead);
        $this->assertEquals('AES-128-GCM', $aead->getAlgorithmName());
    }

    public function testFunctionalEncryptionDecryption(): void
    {
        $key = str_repeat("\x08", 16);
        $suite = CryptoSuite::createAES128GCM($key);
        $aead = $suite->getAEAD();

        $plaintext = 'Test message for suite';
        $nonce = str_repeat("\x09", 12);
        $aad = 'test aad';

        $ciphertext = $aead->encrypt($plaintext, $nonce, $aad);
        $decrypted = $aead->decrypt($ciphertext, $nonce, $aad);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testCustomSuiteCreation(): void
    {
        $key = str_repeat("\x0A", 16);
        $aead = new AES128GCM($key);
        $suite = new CryptoSuite('CUSTOM_AES_128_GCM', $aead, 'sha1');

        $this->assertEquals('CUSTOM_AES_128_GCM', $suite->getName());
        $this->assertEquals('sha1', $suite->getHashAlgorithm());
        $this->assertEquals(20, $suite->getHashLength()); // SHA-1 输出长度
    }

    public function testDifferentKeysProduceDifferentResults(): void
    {
        $key1 = str_repeat("\x0B", 16);
        $key2 = str_repeat("\x0C", 16);

        $suite1 = CryptoSuite::createAES128GCM($key1);
        $suite2 = CryptoSuite::createAES128GCM($key2);

        $plaintext = 'Same message';
        $nonce = str_repeat("\x0D", 12);
        $aad = '';

        $ciphertext1 = $suite1->getAEAD()->encrypt($plaintext, $nonce, $aad);
        $ciphertext2 = $suite2->getAEAD()->encrypt($plaintext, $nonce, $aad);

        // 不同密钥应该产生不同的密文
        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }

    // 异常测试
    public function testEmptyName(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $key = str_repeat("\x0E", 16);
        $aead = new AES128GCM($key);
        new CryptoSuite('', $aead, 'sha256');
    }

    public function testUnsupportedHashAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::ALGORITHM_NOT_SUPPORTED);

        $key = str_repeat("\x0F", 16);
        $aead = new AES128GCM($key);
        new CryptoSuite('TEST_SUITE', $aead, 'unsupported_hash');
    }

    public function testFromNameUnsupportedSuite(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::ALGORITHM_NOT_SUPPORTED);

        $key = str_repeat("\x10", 16);
        CryptoSuite::fromName('UNSUPPORTED_SUITE', $key);
    }

    public function testCreateAES128GCMInvalidKey(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        CryptoSuite::createAES128GCM('invalid_key_length');
    }

    public function testCreateAES256GCMInvalidKey(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        CryptoSuite::createAES256GCM('invalid_key_length');
    }

    public function testCreateChaCha20Poly1305InvalidKey(): void
    {
        if (!ChaCha20Poly1305::isSupported()) {
            self::markTestSkipped('ChaCha20-Poly1305 不被系统支持');
        }

        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        CryptoSuite::createChaCha20Poly1305('invalid_key_length');
    }

    public function testSuiteComparison(): void
    {
        $key = str_repeat("\x11", 16);
        $suite1 = CryptoSuite::createAES128GCM($key);
        $suite2 = CryptoSuite::createAES128GCM($key);

        // 相同参数创建的套件应该有相同的属性
        $this->assertEquals($suite1->getName(), $suite2->getName());
        $this->assertEquals($suite1->getHashAlgorithm(), $suite2->getHashAlgorithm());
        $this->assertEquals($suite1->getKeyLength(), $suite2->getKeyLength());
    }

    public function testPerformanceComparison(): void
    {
        $key128 = str_repeat("\x12", 16);
        $key256 = str_repeat("\x13", 32);

        $suite128 = CryptoSuite::createAES128GCM($key128);
        $suite256 = CryptoSuite::createAES256GCM($key256);

        $plaintext = str_repeat('performance test ', 1000); // ~17KB
        $nonce = str_repeat("\x14", 12);
        $aad = 'performance';

        $start128 = microtime(true);
        for ($i = 0; $i < 10; ++$i) {
            $ciphertext = $suite128->getAEAD()->encrypt($plaintext, $nonce, $aad);
            $decrypted = $suite128->getAEAD()->decrypt($ciphertext, $nonce, $aad);
            $this->assertEquals($plaintext, $decrypted);
        }
        $time128 = microtime(true) - $start128;

        $start256 = microtime(true);
        for ($i = 0; $i < 10; ++$i) {
            $ciphertext = $suite256->getAEAD()->encrypt($plaintext, $nonce, $aad);
            $decrypted = $suite256->getAEAD()->decrypt($ciphertext, $nonce, $aad);
            $this->assertEquals($plaintext, $decrypted);
        }
        $time256 = microtime(true) - $start256;

        // 确保性能在合理范围内
        $this->assertLessThan(2.0, $time128, 'AES-128 性能测试超时');
        $this->assertLessThan(2.0, $time256, 'AES-256 性能测试超时');
    }

    public function testAllSupportedSuitesWork(): void
    {
        $supportedSuites = CryptoSuite::getSupportedSuites();

        foreach ($supportedSuites as $suiteName) {
            $keyLength = match ($suiteName) {
                'TLS_AES_128_GCM_SHA256' => 16,
                'TLS_AES_256_GCM_SHA384' => 32,
                'TLS_CHACHA20_POLY1305_SHA256' => 32,
                default => 16,
            };

            $key = str_repeat("\x15", $keyLength);
            $suite = CryptoSuite::fromName($suiteName, $key);

            $this->assertTrue($suite->isSupported());
            $this->assertTrue(CryptoSuite::isCompatible($suiteName));

            // 测试基本加密解密
            $plaintext = 'Test for ' . $suiteName;
            $nonce = str_repeat("\x16", 12);
            $aad = $suiteName;

            $ciphertext = $suite->getAEAD()->encrypt($plaintext, $nonce, $aad);
            $decrypted = $suite->getAEAD()->decrypt($ciphertext, $nonce, $aad);

            $this->assertEquals($plaintext, $decrypted);
        }
    }
}
