<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

/**
 * ChaCha20-Poly1305 AEAD 实现
 * 
 * 使用 OpenSSL 或 libsodium 实现的 ChaCha20-Poly1305 认证加密算法
 * 符合 RFC 8439 和 QUIC 协议要求
 */
class ChaCha20Poly1305 implements AEADInterface
{
    private const OPENSSL_ALGORITHM = 'chacha20-poly1305';
    private const KEY_LENGTH = 32; // 256 bits
    private const NONCE_LENGTH = 12; // 96 bits
    private const TAG_LENGTH = 16; // 128 bits

    /**
     * 加密密钥
     */
    private readonly string $key;

    /**
     * 是否使用 libsodium 实现
     */
    private readonly bool $useSodium;

    /**
     * 构造函数
     *
     * @param string $key 256位密钥（32字节）
     * @throws CryptoException 如果密钥长度不正确或算法不支持
     */
    public function __construct(string $key)
    {
        if (strlen($key) !== self::KEY_LENGTH) {
            throw CryptoException::invalidKey(
                sprintf('ChaCha20-Poly1305 密钥长度必须为 %d 字节，实际为 %d 字节', self::KEY_LENGTH, strlen($key))
            );
        }

        // 优先使用 libsodium，如果不可用则使用 OpenSSL
        $this->useSodium = function_exists('sodium_crypto_aead_chacha20poly1305_ietf_encrypt');
        
        if (!$this->useSodium && !in_array(self::OPENSSL_ALGORITHM, openssl_get_cipher_methods(), true)) {
            throw CryptoException::algorithmNotSupported('ChaCha20-Poly1305');
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

        if ($this->useSodium) {
            return $this->encryptWithSodium($plaintext, $nonce, $aad);
        }

        return $this->encryptWithOpenSSL($plaintext, $nonce, $aad);
    }

    public function decrypt(string $ciphertext, string $nonce, string $aad): string
    {
        $this->validateNonce($nonce);

        if ($this->useSodium) {
            return $this->decryptWithSodium($ciphertext, $nonce, $aad);
        }

        return $this->decryptWithOpenSSL($ciphertext, $nonce, $aad);
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
        return 'ChaCha20-Poly1305';
    }

    /**
     * 使用 libsodium 进行加密
     */
    private function encryptWithSodium(string $plaintext, string $nonce, string $aad): string
    {
        $result = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $this->key);
        
        // sodium_crypto_aead_chacha20poly1305_ietf_encrypt 失败时会抛出异常，不会返回 false
        return $result;
    }

    /**
     * 使用 libsodium 进行解密
     */
    private function decryptWithSodium(string $ciphertext, string $nonce, string $aad): string
    {
        $result = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $this->key);
        
        if ($result === false) {
            throw CryptoException::decryptionFailed('libsodium ChaCha20-Poly1305 解密失败');
        }

        return $result;
    }

    /**
     * 使用 OpenSSL 进行加密
     */
    private function encryptWithOpenSSL(string $plaintext, string $nonce, string $aad): string
    {
        /** @var string $tag */
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::OPENSSL_ALGORITHM,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw CryptoException::opensslError('ChaCha20-Poly1305 加密');
        }

        /** @phpstan-ignore-next-line */
        if (strlen($tag) !== self::TAG_LENGTH) {
            throw CryptoException::encryptionFailed('认证标签长度不正确');
        }

        // 返回密文 + 认证标签
        return $ciphertext . $tag;
    }

    /**
     * 使用 OpenSSL 进行解密
     */
    private function decryptWithOpenSSL(string $ciphertext, string $nonce, string $aad): string
    {
        if (strlen($ciphertext) < self::TAG_LENGTH) {
            throw CryptoException::decryptionFailed('密文长度过短，缺少认证标签');
        }

        // 分离密文和认证标签
        $actualCiphertext = substr($ciphertext, 0, -self::TAG_LENGTH);
        $tag = substr($ciphertext, -self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $actualCiphertext,
            self::OPENSSL_ALGORITHM,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad
        );

        if ($plaintext === false) {
            throw CryptoException::opensslError('ChaCha20-Poly1305 解密');
        }

        return $plaintext;
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
                sprintf('ChaCha20-Poly1305 随机数长度必须为 %d 字节，实际为 %d 字节', self::NONCE_LENGTH, strlen($nonce))
            );
        }
    }

    /**
     * 检查系统是否支持 ChaCha20-Poly1305
     */
    public static function isSupported(): bool
    {
        return function_exists('sodium_crypto_aead_chacha20poly1305_ietf_encrypt') ||
               in_array(self::OPENSSL_ALGORITHM, openssl_get_cipher_methods(), true);
    }
} 