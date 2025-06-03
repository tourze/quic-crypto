<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\CryptoException;
use Tourze\QUIC\Crypto\SecureRandom;

/**
 * 安全随机数生成器测试类
 */
class SecureRandomTest extends TestCase
{
    public function testBasicRandomGeneration(): void
    {
        $length = 16;
        $randomBytes = SecureRandom::generate($length);

        $this->assertEquals($length, strlen($randomBytes));
    }

    public function testDifferentRandomValues(): void
    {
        $random1 = SecureRandom::generate(32);
        $random2 = SecureRandom::generate(32);

        $this->assertEquals(32, strlen($random1));
        $this->assertEquals(32, strlen($random2));
        $this->assertNotEquals($random1, $random2);
    }

    public function testGenerateNonce(): void
    {
        $nonce = SecureRandom::generateNonce();
        $this->assertEquals(12, strlen($nonce)); // 默认长度

        $nonce8 = SecureRandom::generateNonce(8);
        $this->assertEquals(8, strlen($nonce8));

        $nonce16 = SecureRandom::generateNonce(16);
        $this->assertEquals(16, strlen($nonce16));
    }

    public function testGenerateNonceDifferentValues(): void
    {
        $nonce1 = SecureRandom::generateNonce();
        $nonce2 = SecureRandom::generateNonce();

        $this->assertNotEquals($nonce1, $nonce2);
    }

    public function testGenerateAESKey(): void
    {
        $key128 = SecureRandom::generateAESKey(128);
        $this->assertEquals(16, strlen($key128));

        $key256 = SecureRandom::generateAESKey(256);
        $this->assertEquals(32, strlen($key256));

        $this->assertNotEquals($key128, substr($key256, 0, 16));
    }

    public function testGenerateAESKeyDefault(): void
    {
        $key = SecureRandom::generateAESKey();
        $this->assertEquals(16, strlen($key)); // 默认128位
    }

    public function testGenerateChaCha20Key(): void
    {
        $key = SecureRandom::generateChaCha20Key();
        $this->assertEquals(32, strlen($key));

        $key2 = SecureRandom::generateChaCha20Key();
        $this->assertNotEquals($key, $key2);
    }

    public function testGenerateSalt(): void
    {
        $salt = SecureRandom::generateSalt();
        $this->assertEquals(32, strlen($salt)); // 默认长度

        $salt16 = SecureRandom::generateSalt(16);
        $this->assertEquals(16, strlen($salt16));

        $salt64 = SecureRandom::generateSalt(64);
        $this->assertEquals(64, strlen($salt64));
    }

    public function testGenerateConnectionId(): void
    {
        $connId = SecureRandom::generateConnectionId();
        $this->assertEquals(8, strlen($connId)); // 默认长度

        $connId0 = SecureRandom::generateConnectionId(0);
        $this->assertEquals(0, strlen($connId0));

        $connId20 = SecureRandom::generateConnectionId(20);
        $this->assertEquals(20, strlen($connId20));

        // 测试不同的连接ID应该不同
        $connId1 = SecureRandom::generateConnectionId(8);
        $connId2 = SecureRandom::generateConnectionId(8);
        $this->assertNotEquals($connId1, $connId2);
    }

    public function testGenerateInt(): void
    {
        $randomInt = SecureRandom::generateInt(1, 100);
        $this->assertGreaterThanOrEqual(1, $randomInt);
        $this->assertLessThanOrEqual(100, $randomInt);

        // 测试多个随机数应该有差异
        $ints = [];
        for ($i = 0; $i < 10; $i++) {
            $ints[] = SecureRandom::generateInt(1, 1000);
        }
        $uniqueInts = array_unique($ints);
        $this->assertGreaterThan(1, count($uniqueInts)); // 至少有一些不同的值
    }

    public function testGenerateIntDefault(): void
    {
        $randomInt = SecureRandom::generateInt();
        $this->assertGreaterThanOrEqual(0, $randomInt);
        $this->assertLessThanOrEqual(PHP_INT_MAX, $randomInt);
    }

    public function testGenerateUuid(): void
    {
        $uuid = SecureRandom::generateUuid();
        
        // UUID v4 格式验证
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $uuid
        );

        // 测试多个UUID应该不同
        $uuid2 = SecureRandom::generateUuid();
        $this->assertNotEquals($uuid, $uuid2);
    }

    public function testIsSecure(): void
    {
        $this->assertTrue(SecureRandom::isSecure());
    }

    public function testGetRandomSourceInfo(): void
    {
        $info = SecureRandom::getRandomSourceInfo();
        
        $this->assertIsArray($info);
        $this->assertArrayHasKey('random_bytes_available', $info);
        $this->assertArrayHasKey('openssl_available', $info);
        $this->assertArrayHasKey('sodium_available', $info);
        
        $this->assertTrue($info['random_bytes_available']);
    }

    public function testTimingSafeEquals(): void
    {
        $string1 = 'hello world';
        $string2 = 'hello world';
        $string3 = 'hello worlD';
        $string4 = 'different';

        $this->assertTrue(SecureRandom::timingSafeEquals($string1, $string2));
        $this->assertFalse(SecureRandom::timingSafeEquals($string1, $string3));
        $this->assertFalse(SecureRandom::timingSafeEquals($string1, $string4));
        
        // 测试不同长度
        $this->assertFalse(SecureRandom::timingSafeEquals('short', 'longer string'));
    }

    public function testTimingSafeEqualsWithBinaryData(): void
    {
        $binary1 = "\x00\x01\x02\x03\xFF";
        $binary2 = "\x00\x01\x02\x03\xFF";
        $binary3 = "\x00\x01\x02\x03\xFE";

        $this->assertTrue(SecureRandom::timingSafeEquals($binary1, $binary2));
        $this->assertFalse(SecureRandom::timingSafeEquals($binary1, $binary3));
    }

    // 异常测试
    public function testInvalidLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generate(0);
    }

    public function testNegativeLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generate(-1);
    }

    public function testTooLargeLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generate(1024 * 1024 + 1); // 超过1MB
    }

    public function testInvalidNonceLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateNonce(7); // 太短
    }

    public function testInvalidNonceLengthTooLong(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateNonce(17); // 太长
    }

    public function testInvalidAESKeySize(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateAESKey(192); // 不支持的大小
    }

    public function testInvalidSaltLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateSalt(15); // 太短
    }

    public function testInvalidConnectionIdLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateConnectionId(-1); // 负数
    }

    public function testInvalidConnectionIdLengthTooLong(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateConnectionId(21); // 超过最大长度
    }

    public function testInvalidIntRange(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateInt(100, 50); // min >= max
    }

    public function testInvalidIntRangeEqual(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        SecureRandom::generateInt(50, 50); // min >= max
    }

    // 分布性测试
    public function testRandomnessDistribution(): void
    {
        $bytes = SecureRandom::generate(1000);
        $byteFreq = array_count_values(str_split($bytes));
        
        // 检查是否有合理的字节分布（不应该全是同一个值）
        $this->assertGreaterThan(100, count($byteFreq));
    }

    public function testIntDistribution(): void
    {
        $values = [];
        for ($i = 0; $i < 100; $i++) {
            $values[] = SecureRandom::generateInt(1, 10);
        }
        
        $distribution = array_count_values($values);
        
        // 应该有多个不同的值
        $this->assertGreaterThan(5, count($distribution));
        
        // 每个值都应该在范围内
        foreach ($values as $value) {
            $this->assertGreaterThanOrEqual(1, $value);
            $this->assertLessThanOrEqual(10, $value);
        }
    }

    public function testLargeRandomData(): void
    {
        $largeData = SecureRandom::generate(1024 * 100); // 100KB
        $this->assertEquals(1024 * 100, strlen($largeData));
        
        // 检查数据不全为零
        $this->assertNotEquals(str_repeat("\x00", 1024 * 100), $largeData);
    }
} 