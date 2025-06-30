<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * CryptoException 测试类
 */
class CryptoExceptionTest extends TestCase
{
    public function testConstructor(): void
    {
        $exception = new CryptoException('Test message', 123);
        
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertEquals('Test message', $exception->getMessage());
        $this->assertEquals(123, $exception->getCode());
    }

    public function testEncryptionFailed(): void
    {
        $exception = CryptoException::encryptionFailed();
        
        $this->assertEquals('加密失败', $exception->getMessage());
        $this->assertEquals(CryptoException::ENCRYPTION_FAILED, $exception->getCode());
    }

    public function testEncryptionFailedWithReason(): void
    {
        $exception = CryptoException::encryptionFailed('密钥长度不正确');
        
        $this->assertEquals('加密失败: 密钥长度不正确', $exception->getMessage());
        $this->assertEquals(CryptoException::ENCRYPTION_FAILED, $exception->getCode());
    }

    public function testDecryptionFailed(): void
    {
        $exception = CryptoException::decryptionFailed();
        
        $this->assertEquals('解密失败', $exception->getMessage());
        $this->assertEquals(CryptoException::DECRYPTION_FAILED, $exception->getCode());
    }

    public function testDecryptionFailedWithReason(): void
    {
        $exception = CryptoException::decryptionFailed('认证标签验证失败');
        
        $this->assertEquals('解密失败: 认证标签验证失败', $exception->getMessage());
        $this->assertEquals(CryptoException::DECRYPTION_FAILED, $exception->getCode());
    }

    public function testInvalidKey(): void
    {
        $exception = CryptoException::invalidKey();
        
        $this->assertEquals('无效的密钥', $exception->getMessage());
        $this->assertEquals(CryptoException::INVALID_KEY, $exception->getCode());
    }

    public function testInvalidKeyWithReason(): void
    {
        $exception = CryptoException::invalidKey('密钥长度必须为 32 字节');
        
        $this->assertEquals('无效的密钥: 密钥长度必须为 32 字节', $exception->getMessage());
        $this->assertEquals(CryptoException::INVALID_KEY, $exception->getCode());
    }

    public function testInvalidNonce(): void
    {
        $exception = CryptoException::invalidNonce();
        
        $this->assertEquals('无效的随机数', $exception->getMessage());
        $this->assertEquals(CryptoException::INVALID_NONCE, $exception->getCode());
    }

    public function testInvalidNonceWithReason(): void
    {
        $exception = CryptoException::invalidNonce('随机数长度必须为 12 字节');
        
        $this->assertEquals('无效的随机数: 随机数长度必须为 12 字节', $exception->getMessage());
        $this->assertEquals(CryptoException::INVALID_NONCE, $exception->getCode());
    }

    public function testInvalidParameter(): void
    {
        $exception = CryptoException::invalidParameter();
        
        $this->assertEquals('无效的参数', $exception->getMessage());
        $this->assertEquals(CryptoException::INVALID_PARAMETER, $exception->getCode());
    }

    public function testInvalidParameterWithReason(): void
    {
        $exception = CryptoException::invalidParameter('参数不能为空');
        
        $this->assertEquals('无效的参数: 参数不能为空', $exception->getMessage());
        $this->assertEquals(CryptoException::INVALID_PARAMETER, $exception->getCode());
    }

    public function testAlgorithmNotSupported(): void
    {
        $exception = CryptoException::algorithmNotSupported('XYZ-256');
        
        $this->assertEquals('不支持的算法: XYZ-256', $exception->getMessage());
        $this->assertEquals(CryptoException::ALGORITHM_NOT_SUPPORTED, $exception->getCode());
    }

    public function testKeyDerivationFailed(): void
    {
        $exception = CryptoException::keyDerivationFailed();
        
        $this->assertEquals('密钥派生失败', $exception->getMessage());
        $this->assertEquals(CryptoException::KEY_DERIVATION_FAILED, $exception->getCode());
    }

    public function testKeyDerivationFailedWithReason(): void
    {
        $exception = CryptoException::keyDerivationFailed('输入参数无效');
        
        $this->assertEquals('密钥派生失败: 输入参数无效', $exception->getMessage());
        $this->assertEquals(CryptoException::KEY_DERIVATION_FAILED, $exception->getCode());
    }

    /**
     * 测试所有错误代码常量
     */
    public function testErrorCodeConstants(): void
    {
        $this->assertEquals(1001, CryptoException::ENCRYPTION_FAILED);
        $this->assertEquals(1002, CryptoException::DECRYPTION_FAILED);
        $this->assertEquals(1003, CryptoException::INVALID_KEY);
        $this->assertEquals(1004, CryptoException::INVALID_NONCE);
        $this->assertEquals(1005, CryptoException::INVALID_PARAMETER);
        $this->assertEquals(1006, CryptoException::ALGORITHM_NOT_SUPPORTED);
        $this->assertEquals(1007, CryptoException::OPENSSL_ERROR);
        $this->assertEquals(1008, CryptoException::KEY_DERIVATION_FAILED);
    }
}