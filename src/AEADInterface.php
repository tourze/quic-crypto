<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * AEAD (Authenticated Encryption with Associated Data) 接口
 *
 * 实现 QUIC 协议所需的认证加密功能
 * 支持 AES-GCM 和 ChaCha20-Poly1305 算法
 */
interface AEADInterface
{
    /**
     * 加密明文数据
     *
     * @param string $plaintext 明文数据
     * @param string $nonce     随机数，长度必须符合算法要求
     * @param string $aad       关联附加数据（Additional Authenticated Data）
     *
     * @return string 密文（包含认证标签）
     *
     * @throws CryptoException 加密失败时抛出异常
     */
    public function encrypt(string $plaintext, string $nonce, string $aad): string;

    /**
     * 解密密文数据
     *
     * @param string $ciphertext 密文数据（包含认证标签）
     * @param string $nonce      随机数，必须与加密时相同
     * @param string $aad        关联附加数据，必须与加密时相同
     *
     * @return string 明文数据
     *
     * @throws CryptoException 解密或验证失败时抛出异常
     */
    public function decrypt(string $ciphertext, string $nonce, string $aad): string;

    /**
     * 获取密钥长度（字节）
     */
    public function getKeyLength(): int;

    /**
     * 获取随机数长度（字节）
     */
    public function getNonceLength(): int;

    /**
     * 获取认证标签长度（字节）
     */
    public function getTagLength(): int;

    /**
     * 获取算法名称
     */
    public function getAlgorithmName(): string;
}
