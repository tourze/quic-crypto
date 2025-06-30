<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\Exception\CryptoException;
use Tourze\QUIC\Crypto\KeyDerivation;

/**
 * HKDF 密钥派生测试类
 */
class KeyDerivationTest extends TestCase
{
    public function testHkdfExtractBasic(): void
    {
        $salt = hex2bin('000102030405060708090a0b0c');
        $ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        
        $prk = KeyDerivation::hkdfExtract($salt, $ikm);
        
        // RFC 5869 测试向量 1 期望结果
        $expected = hex2bin('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
        
        $this->assertEquals($expected, $prk);
    }

    public function testHkdfExpandBasic(): void
    {
        $prk = hex2bin('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        $length = 42;
        
        $okm = KeyDerivation::hkdfExpand($prk, $info, $length);
        
        // RFC 5869 测试向量 1 期望结果
        $expected = hex2bin('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
        
        $this->assertEquals($expected, $okm);
    }

    public function testHkdfComplete(): void
    {
        $ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $salt = hex2bin('000102030405060708090a0b0c');
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        $length = 42;
        
        $okm = KeyDerivation::hkdf($ikm, $length, $info, $salt);
        
        // RFC 5869 测试向量 1 期望结果
        $expected = hex2bin('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
        
        $this->assertEquals($expected, $okm);
    }

    public function testHkdfWithoutSalt(): void
    {
        $ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $info = '';
        $salt = '';
        $length = 42;
        
        $okm = KeyDerivation::hkdf($ikm, $length, $info, $salt);
        
        // RFC 5869 测试向量 2 期望结果
        $expected = hex2bin('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');
        
        $this->assertEquals($expected, $okm);
    }

    public function testHkdfLongOutput(): void
    {
        $ikm = hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f');
        $salt = hex2bin('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf');
        $info = hex2bin('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
        $length = 82;
        
        $okm = KeyDerivation::hkdf($ikm, $length, $info, $salt);
        
        // RFC 5869 测试向量 3 期望结果
        $expected = hex2bin('b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87');
        
        $this->assertEquals($expected, $okm);
    }

    public function testQuicKDF(): void
    {
        $secret = str_repeat("\x01", 32);
        $label = 'quic key';
        $length = 16;
        
        $derivedKey = KeyDerivation::quicKDF($secret, $label, $length);
        
        $this->assertEquals($length, strlen($derivedKey));
        $this->assertNotEquals($secret, $derivedKey);
    }

    public function testQuicInitialSalt(): void
    {
        $salt = KeyDerivation::getQuicInitialSalt();
        
        // RFC 9001 Section 5.2 定义的初始盐值
        $expected = hex2bin('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');
        
        $this->assertEquals($expected, $salt);
        $this->assertEquals(20, strlen($salt));
    }

    public function testInvalidLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);
        
        $prk = str_repeat("\x01", 32);
        KeyDerivation::hkdfExpand($prk, '', 0);
    }

    public function testTooLongOutput(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);
        
        $prk = str_repeat("\x01", 32);
        $maxLength = 255 * 32 + 1; // 超过最大长度
        
        KeyDerivation::hkdfExpand($prk, '', $maxLength);
    }

    public function testUnsupportedHashAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::ALGORITHM_NOT_SUPPORTED);
        
        $salt = 'salt';
        $ikm = 'input key material';
        
        KeyDerivation::hkdfExtract($salt, $ikm, 'unsupported_hash');
    }

    public function testSecureClear(): void
    {
        $sensitiveData = 'secret key material';
        $originalLength = strlen($sensitiveData);
        
        KeyDerivation::secureClear($sensitiveData);
        
        // 验证数据长度保持不变但内容已被清理
        $this->assertEquals($originalLength, strlen($sensitiveData));
        $this->assertNotEquals('secret key material', $sensitiveData);
    }

    public function testDifferentHashAlgorithms(): void
    {
        $ikm = 'input key material';
        $length = 32;
        
        $sha256Result = KeyDerivation::hkdf($ikm, $length, '', '', 'sha256');
        $sha384Result = KeyDerivation::hkdf($ikm, $length, '', '', 'sha384');
        $sha512Result = KeyDerivation::hkdf($ikm, $length, '', '', 'sha512');
        
        // 不同哈希算法应该产生不同的结果
        $this->assertNotEquals($sha256Result, $sha384Result);
        $this->assertNotEquals($sha256Result, $sha512Result);
        $this->assertNotEquals($sha384Result, $sha512Result);
        
        // 但长度应该相同
        $this->assertEquals($length, strlen($sha256Result));
        $this->assertEquals($length, strlen($sha384Result));
        $this->assertEquals($length, strlen($sha512Result));
    }
} 