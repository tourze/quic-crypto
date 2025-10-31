<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * QUIC 包头保护实现
 *
 * 根据 RFC 9001 Section 5.4 实现包头保护功能
 * 保护 QUIC 包头中的关键信息，防止流量分析
 */
class HeaderProtection
{
    private const MASK_LENGTH = 5; // 掩码长度

    /**
     * 构造函数
     *
     * @param AEADInterface $aead      AEAD 算法实例
     * @param string        $headerKey 包头保护密钥
     *
     * @throws CryptoException 如果密钥无效
     */
    public function __construct(
        private readonly AEADInterface $aead,
        private readonly string $headerKey,
    ) {
        $expectedKeyLength = $aead->getKeyLength();
        if (strlen($headerKey) !== $expectedKeyLength) {
            throw CryptoException::invalidKey(sprintf('包头保护密钥长度必须为 %d 字节，实际为 %d 字节', $expectedKeyLength, strlen($headerKey)));
        }
    }

    /**
     * 销毁时清理敏感数据
     */
    public function __destruct()
    {
        // readonly 属性不能被修改，所以这里不需要手动清理
        // PHP 会在对象销毁时自动清理内存
    }

    /**
     * 保护包头
     *
     * @param string $header 未保护的包头
     * @param string $sample 包头保护样本（来自包负载的前16字节）
     *
     * @return string 受保护的包头
     *
     * @throws CryptoException 如果保护失败
     */
    public function protect(string $header, string $sample): string
    {
        if (0 === strlen($header)) {
            throw CryptoException::invalidParameter('包头不能为空');
        }

        $mask = $this->generateMask($sample);

        return $this->applyMask($header, $mask);
    }

    /**
     * 取消包头保护
     *
     * @param string $protectedHeader 受保护的包头
     * @param string $sample          包头保护样本
     *
     * @return string 未保护的包头
     *
     * @throws CryptoException 如果取消保护失败
     */
    public function unprotect(string $protectedHeader, string $sample): string
    {
        if (0 === strlen($protectedHeader)) {
            throw CryptoException::invalidParameter('受保护的包头不能为空');
        }

        $mask = $this->generateMask($sample);

        return $this->applyMask($protectedHeader, $mask);
    }

    /**
     * 生成包头保护掩码
     *
     * @param string $sample 包头保护样本（16字节）
     *
     * @return string 5字节掩码
     *
     * @throws CryptoException 如果生成失败
     */
    public function generateMask(string $sample): string
    {
        if (16 !== strlen($sample)) {
            throw CryptoException::invalidParameter(sprintf('包头保护样本长度必须为 16 字节，实际为 %d 字节', strlen($sample)));
        }

        $algorithmName = $this->aead->getAlgorithmName();

        if (str_contains($algorithmName, 'AES')) {
            return $this->generateAESMask($sample);
        }

        if (str_contains($algorithmName, 'ChaCha20')) {
            return $this->generateChaCha20Mask($sample);
        }

        throw CryptoException::algorithmNotSupported("不支持的包头保护算法: {$algorithmName}");
    }

    /**
     * 生成 AES 掩码
     *
     * @param string $sample 16字节样本
     *
     * @return string 5字节掩码
     *
     * @throws CryptoException 如果生成失败
     */
    private function generateAESMask(string $sample): string
    {
        // 对于 AES，使用 ECB 模式加密样本
        $algorithm = 16 === strlen($this->headerKey) ? 'aes-128-ecb' : 'aes-256-ecb';

        if (!in_array($algorithm, openssl_get_cipher_methods(), true)) {
            throw CryptoException::algorithmNotSupported($algorithm);
        }

        $encrypted = openssl_encrypt($sample, $algorithm, $this->headerKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        if (false === $encrypted) {
            throw CryptoException::opensslError('AES 包头保护掩码生成');
        }

        return substr($encrypted, 0, self::MASK_LENGTH);
    }

    /**
     * 生成 ChaCha20 掩码
     *
     * @param string $sample 16字节样本
     *
     * @return string 5字节掩码
     *
     * @throws CryptoException 如果生成失败
     */
    private function generateChaCha20Mask(string $sample): string
    {
        // 使用样本的前12字节作为nonce，后4字节作为计数器的一部分
        $nonce = substr($sample, 0, 12);

        // 创建一个零填充的明文用于生成密钥流
        $plaintext = str_repeat("\x00", self::MASK_LENGTH);

        // 使用 ChaCha20 算法生成密钥流（通过加密零字节）
        if (in_array('chacha20', openssl_get_cipher_methods(), true)) {
            // OpenSSL 的 ChaCha20 需要 16 字节的 IV，所以需要填充 4 个零字节
            $paddedNonce = $nonce . str_repeat("\x00", 4);
            $encrypted = openssl_encrypt(
                $plaintext,
                'chacha20',
                $this->headerKey,
                OPENSSL_RAW_DATA,
                $paddedNonce
            );

            if (false === $encrypted) {
                throw CryptoException::opensslError('ChaCha20 包头保护掩码生成');
            }

            return substr($encrypted, 0, self::MASK_LENGTH);
        }

        // 如果 ChaCha20 不可用，尝试使用 ChaCha20-Poly1305 的密钥部分
        throw CryptoException::algorithmNotSupported('ChaCha20 算法不可用于包头保护');
    }

    /**
     * 应用掩码到包头
     *
     * @param string $header 包头数据
     * @param string $mask   5字节掩码
     *
     * @return string 应用掩码后的包头
     */
    private function applyMask(string $header, string $mask): string
    {
        if (self::MASK_LENGTH !== strlen($mask)) {
            throw CryptoException::invalidParameter(sprintf('掩码长度必须为 %d 字节，实际为 %d 字节', self::MASK_LENGTH, strlen($mask)));
        }

        $result = $header;
        $headerLength = strlen($header);

        // 保护第一个字节（包含标志位）
        if ($headerLength > 0) {
            $firstByte = ord($header[0]);
            $longHeader = ($firstByte & 0x80) !== 0;

            if ($longHeader) {
                // 长包头：保护第一个字节的低4位
                $result[0] = chr($firstByte ^ (ord($mask[0]) & 0x0F));
            } else {
                // 短包头：保护第一个字节的低5位
                $result[0] = chr($firstByte ^ (ord($mask[0]) & 0x1F));
            }
        }

        // 保护包号字节
        $maskOffset = 1;
        for ($i = 1; $i < $headerLength && $maskOffset < self::MASK_LENGTH; $i++, $maskOffset++) {
            $result[$i] = chr(ord($header[$i]) ^ ord($mask[$maskOffset]));
        }

        return $result;
    }

    /**
     * 获取包头保护算法名称
     */
    public function getAlgorithmName(): string
    {
        return $this->aead->getAlgorithmName() . ' Header Protection';
    }

    /**
     * 验证包头保护参数
     *
     * @param string $sample 样本数据
     *
     * @throws CryptoException 如果参数无效
     */
    public function validateSample(string $sample): void
    {
        if (16 !== strlen($sample)) {
            throw CryptoException::invalidParameter(sprintf('包头保护样本必须为 16 字节，实际为 %d 字节', strlen($sample)));
        }
    }
}
