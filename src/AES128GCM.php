<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * AES-128-GCM AEAD 实现
 *
 * 使用 OpenSSL 实现的 AES-128-GCM 认证加密算法
 * 符合 RFC 5116 和 QUIC 协议要求
 */
class AES128GCM implements AEADInterface
{
    private const ALGORITHM = 'aes-128-gcm';
    private const KEY_LENGTH = 16; // 128 bits
    private const NONCE_LENGTH = 12; // 96 bits
    private const TAG_LENGTH = 16; // 128 bits

    /**
     * 加密密钥
     */
    private readonly string $key;

    /**
     * 构造函数
     *
     * @param string $key 128位密钥（16字节）
     * @throws CryptoException 如果密钥长度不正确
     */
    public function __construct(string $key)
    {
        if (strlen($key) !== self::KEY_LENGTH) {
            throw CryptoException::invalidKey(
                sprintf('AES-128-GCM 密钥长度必须为 %d 字节，实际为 %d 字节', self::KEY_LENGTH, strlen($key))
            );
        }

        if (!in_array(self::ALGORITHM, openssl_get_cipher_methods(), true)) {
            throw CryptoException::algorithmNotSupported(self::ALGORITHM);
        }

        $this->key = $key;
    }

    /**
     * 销毁时清理敏感数据
     */
    public function __destruct()
    {
        // readonly 属性不能被修改，所以这里不需要手动清理
        // PHP 会在对象销毁时自动清理内存
    }

    public function encrypt(string $plaintext, string $nonce, string $aad): string
    {
        $this->validateNonce($nonce);

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::ALGORITHM,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw CryptoException::opensslError('AES-128-GCM 加密');
        }

        if (strlen($tag) !== self::TAG_LENGTH) {
            throw CryptoException::encryptionFailed('认证标签长度不正确');
        }

        // 返回密文 + 认证标签
        return $ciphertext . $tag;
    }

    public function decrypt(string $ciphertext, string $nonce, string $aad): string
    {
        $this->validateNonce($nonce);

        if (strlen($ciphertext) < self::TAG_LENGTH) {
            throw CryptoException::decryptionFailed('密文长度过短，缺少认证标签');
        }

        // 分离密文和认证标签
        $actualCiphertext = substr($ciphertext, 0, -self::TAG_LENGTH);
        $tag = substr($ciphertext, -self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $actualCiphertext,
            self::ALGORITHM,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad
        );

        if ($plaintext === false) {
            throw CryptoException::opensslError('AES-128-GCM 解密');
        }

        return $plaintext;
    }

    public function getKeyLength(): int
    {
        return self::KEY_LENGTH;
    }

    public function getNonceLength(): int
    {
        return self::NONCE_LENGTH;
    }

    public function getTagLength(): int
    {
        return self::TAG_LENGTH;
    }

    public function getAlgorithmName(): string
    {
        return 'AES-128-GCM';
    }

    /**
     * 验证随机数长度
     *
     * @param string $nonce 随机数
     * @throws CryptoException 如果随机数长度不正确
     */
    private function validateNonce(string $nonce): void
    {
        if (strlen($nonce) !== self::NONCE_LENGTH) {
            throw CryptoException::invalidNonce(
                sprintf('AES-128-GCM 随机数长度必须为 %d 字节，实际为 %d 字节', self::NONCE_LENGTH, strlen($nonce))
            );
        }
    }

    /**
     * 检查系统是否支持 AES-128-GCM
     */
    public static function isSupported(): bool
    {
        return in_array(self::ALGORITHM, openssl_get_cipher_methods(), true);
    }
} 