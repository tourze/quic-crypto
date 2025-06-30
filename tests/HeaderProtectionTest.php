<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\AES128GCM;
use Tourze\QUIC\Crypto\AES256GCM;
use Tourze\QUIC\Crypto\ChaCha20Poly1305;
use Tourze\QUIC\Crypto\Exception\CryptoException;
use Tourze\QUIC\Crypto\HeaderProtection;

/**
 * QUIC 包头保护测试类
 */
class HeaderProtectionTest extends TestCase
{
    private HeaderProtection $headerProtectionAES128;
    private HeaderProtection $headerProtectionAES256;
    private HeaderProtection $headerProtectionChaCha20;

    protected function setUp(): void
    {
        // AES-128 包头保护
        $aes128Key = str_repeat("\x01", 16);
        $aes128Hp = str_repeat("\x02", 16);
        $aes128 = new AES128GCM($aes128Key);
        $this->headerProtectionAES128 = new HeaderProtection($aes128, $aes128Hp);

        // AES-256 包头保护
        $aes256Key = str_repeat("\x03", 32);
        $aes256Hp = str_repeat("\x04", 32);
        $aes256 = new AES256GCM($aes256Key);
        $this->headerProtectionAES256 = new HeaderProtection($aes256, $aes256Hp);

        // ChaCha20 包头保护
        if (ChaCha20Poly1305::isSupported()) {
            $chachaKey = str_repeat("\x05", 32);
            $chachaHp = str_repeat("\x06", 32);
            $chacha = new ChaCha20Poly1305($chachaKey);
            $this->headerProtectionChaCha20 = new HeaderProtection($chacha, $chachaHp);
        }
    }

    public function testBasicProtectionAndUnprotection(): void
    {
        $header = "\x40\x01\x02\x03\x04"; // 示例包头
        $sample = str_repeat("\x07", 16); // 16字节样本

        $protectedHeader = $this->headerProtectionAES128->protect($header, $sample);
        $unprotectedHeader = $this->headerProtectionAES128->unprotect($protectedHeader, $sample);

        $this->assertEquals($header, $unprotectedHeader);
        $this->assertEquals(strlen($header), strlen($protectedHeader));
    }

    public function testProtectionWithAES256(): void
    {
        $header = "\x41\x11\x22\x33\x44\x55"; 
        $sample = str_repeat("\x08", 16);

        $protectedHeader = $this->headerProtectionAES256->protect($header, $sample);
        $unprotectedHeader = $this->headerProtectionAES256->unprotect($protectedHeader, $sample);

        $this->assertEquals($header, $unprotectedHeader);
        $this->assertNotEquals($header, $protectedHeader);
    }

    public function testProtectionWithChaCha20(): void
    {
        if (!ChaCha20Poly1305::isSupported()) {
            $this->markTestSkipped('ChaCha20-Poly1305 不被系统支持');
        }

        $header = "\x42\xAA\xBB\xCC\xDD\xEE\xFF";
        $sample = str_repeat("\x09", 16);

        $protectedHeader = $this->headerProtectionChaCha20->protect($header, $sample);
        $unprotectedHeader = $this->headerProtectionChaCha20->unprotect($protectedHeader, $sample);

        $this->assertEquals($header, $unprotectedHeader);
        $this->assertNotEquals($header, $protectedHeader);
    }

    public function testLongHeader(): void
    {
        // 长包头格式 (首字节第7位为1)
        $longHeader = "\xC0\x01\x02\x03\x04\x05\x06\x07\x08\x09"; 
        $sample = str_repeat("\x0A", 16);

        $protectedHeader = $this->headerProtectionAES128->protect($longHeader, $sample);
        $unprotectedHeader = $this->headerProtectionAES128->unprotect($protectedHeader, $sample);

        $this->assertEquals($longHeader, $unprotectedHeader);
        
        // 长包头应该只保护第一个字节的低4位
        $firstByteOriginal = ord($longHeader[0]);
        $firstByteProtected = ord($protectedHeader[0]);
        $this->assertEquals($firstByteOriginal & 0xF0, $firstByteProtected & 0xF0); // 高4位应该不变
    }

    public function testShortHeader(): void
    {
        // 短包头格式 (首字节第7位为0)
        $shortHeader = "\x40\x01\x02\x03\x04"; 
        $sample = str_repeat("\x0B", 16);

        $protectedHeader = $this->headerProtectionAES128->protect($shortHeader, $sample);
        $unprotectedHeader = $this->headerProtectionAES128->unprotect($protectedHeader, $sample);

        $this->assertEquals($shortHeader, $unprotectedHeader);
        
        // 短包头应该保护第一个字节的低5位
        $firstByteOriginal = ord($shortHeader[0]);
        $firstByteProtected = ord($protectedHeader[0]);
        $this->assertEquals($firstByteOriginal & 0xE0, $firstByteProtected & 0xE0); // 高3位应该不变
    }

    public function testDifferentSamplesSameMask(): void
    {
        $header = "\x40\x01\x02\x03\x04";
        $sample1 = str_repeat("\x0C", 16);
        $sample2 = str_repeat("\x0D", 16);

        $protected1 = $this->headerProtectionAES128->protect($header, $sample1);
        $protected2 = $this->headerProtectionAES128->protect($header, $sample2);

        // 不同的样本应该产生不同的保护结果
        $this->assertNotEquals($protected1, $protected2);
    }

    public function testGenerateMask(): void
    {
        $sample = str_repeat("\x0E", 16);
        
        $mask = $this->headerProtectionAES128->generateMask($sample);
        $this->assertEquals(5, strlen($mask)); // 掩码应该是5字节
        
        // 相同样本应该产生相同掩码
        $mask2 = $this->headerProtectionAES128->generateMask($sample);
        $this->assertEquals($mask, $mask2);
    }

    public function testValidateSample(): void
    {
        $validSample = str_repeat("\x0F", 16);
        
        // 这个方法不应该抛出异常
        $this->headerProtectionAES128->validateSample($validSample);
        $this->assertTrue(true); // 如果没有异常则测试通过
    }

    public function testGetAlgorithmName(): void
    {
        $this->assertEquals('AES-128-GCM Header Protection', $this->headerProtectionAES128->getAlgorithmName());
        $this->assertEquals('AES-256-GCM Header Protection', $this->headerProtectionAES256->getAlgorithmName());
        
        if (ChaCha20Poly1305::isSupported()) {
            $this->assertEquals('ChaCha20-Poly1305 Header Protection', $this->headerProtectionChaCha20->getAlgorithmName());
        }
    }

    public function testMinimalHeader(): void
    {
        $minimalHeader = "\x40"; // 只有一个字节
        $sample = str_repeat("\x10", 16);

        $protectedHeader = $this->headerProtectionAES128->protect($minimalHeader, $sample);
        $unprotectedHeader = $this->headerProtectionAES128->unprotect($protectedHeader, $sample);

        $this->assertEquals($minimalHeader, $unprotectedHeader);
        $this->assertEquals(1, strlen($protectedHeader));
    }

    public function testLargeHeader(): void
    {
        $largeHeader = str_repeat("\x40", 1000); // 1000字节的包头
        $sample = str_repeat("\x11", 16);

        $protectedHeader = $this->headerProtectionAES128->protect($largeHeader, $sample);
        $unprotectedHeader = $this->headerProtectionAES128->unprotect($protectedHeader, $sample);

        $this->assertEquals($largeHeader, $unprotectedHeader);
        $this->assertEquals(strlen($largeHeader), strlen($protectedHeader));
    }

    // 异常测试
    public function testInvalidKeyLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_KEY);

        $aes128 = new AES128GCM(str_repeat("\x00", 16));
        $invalidKey = str_repeat("\x01", 15); // 错误长度
        new HeaderProtection($aes128, $invalidKey);
    }

    public function testEmptyHeader(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $sample = str_repeat("\x12", 16);
        $this->headerProtectionAES128->protect('', $sample);
    }

    public function testInvalidSampleLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $header = "\x40\x01\x02\x03";
        $invalidSample = str_repeat("\x13", 15); // 错误长度
        $this->headerProtectionAES128->protect($header, $invalidSample);
    }

    public function testInvalidSampleLengthLong(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $header = "\x40\x01\x02\x03";
        $invalidSample = str_repeat("\x14", 17); // 错误长度
        $this->headerProtectionAES128->protect($header, $invalidSample);
    }

    public function testInvalidSampleLengthInGenerate(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $invalidSample = str_repeat("\x15", 10);
        $this->headerProtectionAES128->generateMask($invalidSample);
    }

    public function testInvalidSampleInValidate(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $invalidSample = str_repeat("\x16", 20);
        $this->headerProtectionAES128->validateSample($invalidSample);
    }

    public function testEmptyProtectedHeader(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $sample = str_repeat("\x17", 16);
        $this->headerProtectionAES128->unprotect('', $sample);
    }

    public function testConsistencyAcrossAlgorithms(): void
    {
        $header = "\x41\x01\x02\x03\x04\x05";
        $sample = str_repeat("\x18", 16);

        // 每种算法都应该能正确处理相同的输入
        $protectedAES128 = $this->headerProtectionAES128->protect($header, $sample);
        $unprotectedAES128 = $this->headerProtectionAES128->unprotect($protectedAES128, $sample);

        $protectedAES256 = $this->headerProtectionAES256->protect($header, $sample);
        $unprotectedAES256 = $this->headerProtectionAES256->unprotect($protectedAES256, $sample);

        $this->assertEquals($header, $unprotectedAES128);
        $this->assertEquals($header, $unprotectedAES256);

        if (ChaCha20Poly1305::isSupported()) {
            $protectedChaCha20 = $this->headerProtectionChaCha20->protect($header, $sample);
            $unprotectedChaCha20 = $this->headerProtectionChaCha20->unprotect($protectedChaCha20, $sample);
            $this->assertEquals($header, $unprotectedChaCha20);
        }
    }

    public function testBinaryHeaderData(): void
    {
        $binaryHeader = "\x00\x01\xFF\xFE\x7F\x80\x40\x20";
        $sample = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";

        $protectedHeader = $this->headerProtectionAES128->protect($binaryHeader, $sample);
        $unprotectedHeader = $this->headerProtectionAES128->unprotect($protectedHeader, $sample);

        $this->assertEquals($binaryHeader, $unprotectedHeader);
    }

    public function testMaskGeneration(): void
    {
        // 测试掩码生成的一致性
        $sample = str_repeat("\x19", 16);
        
        $mask1 = $this->headerProtectionAES128->generateMask($sample);
        $mask2 = $this->headerProtectionAES128->generateMask($sample);
        
        $this->assertEquals($mask1, $mask2);
        $this->assertEquals(5, strlen($mask1));
        
        // 不同样本应该产生不同掩码
        $differentSample = str_repeat("\x1A", 16);
        $differentMask = $this->headerProtectionAES128->generateMask($differentSample);
        
        $this->assertNotEquals($mask1, $differentMask);
    }
} 