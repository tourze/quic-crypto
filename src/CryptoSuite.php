<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

use Tourze\QUIC\Crypto\Exception\CryptoException;

/**
 * 密码套件管理
 *
 * 管理和选择 QUIC 协议支持的密码套件
 * 包括 AEAD 算法和哈希算法的组合
 */
class CryptoSuite
{
    /**
     * 构造函数
     *
     * @param string        $name          套件名称
     * @param AEADInterface $aead          AEAD 算法实例
     * @param string        $hashAlgorithm 哈希算法名称
     *
     * @throws CryptoException 如果参数无效
     */
    public function __construct(
        private readonly string $name,
        private readonly AEADInterface $aead,
        private readonly string $hashAlgorithm,
    ) {
        if ('' === $name) {
            throw CryptoException::invalidParameter('套件名称不能为空');
        }

        if (!in_array($hashAlgorithm, hash_algos(), true)) {
            throw CryptoException::algorithmNotSupported("哈希算法不支持: {$hashAlgorithm}");
        }
    }

    /**
     * 获取套件名称
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * 获取 AEAD 算法实例
     */
    public function getAEAD(): AEADInterface
    {
        return $this->aead;
    }

    /**
     * 获取哈希算法名称
     */
    public function getHashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    /**
     * 检查套件是否被系统支持
     */
    public function isSupported(): bool
    {
        // 检查 AEAD 算法是否支持
        $aeadSupported = match ($this->aead::class) {
            AES128GCM::class => AES128GCM::isSupported(),
            AES256GCM::class => AES256GCM::isSupported(),
            ChaCha20Poly1305::class => ChaCha20Poly1305::isSupported(),
            default => false,
        };

        // 检查哈希算法是否支持
        $hashSupported = in_array($this->hashAlgorithm, hash_algos(), true);

        return $aeadSupported && $hashSupported;
    }

    /**
     * 获取密钥长度
     */
    public function getKeyLength(): int
    {
        return $this->aead->getKeyLength();
    }

    /**
     * 获取随机数长度
     */
    public function getNonceLength(): int
    {
        return $this->aead->getNonceLength();
    }

    /**
     * 获取认证标签长度
     */
    public function getTagLength(): int
    {
        return $this->aead->getTagLength();
    }

    /**
     * 获取哈希输出长度
     */
    public function getHashLength(): int
    {
        return strlen(hash($this->hashAlgorithm, '', true));
    }

    /**
     * 创建 AES-128-GCM 套件
     *
     * @param string $key 128位密钥
     *
     * @throws CryptoException 如果创建失败
     */
    public static function createAES128GCM(string $key): self
    {
        return new self(
            'TLS_AES_128_GCM_SHA256',
            new AES128GCM($key),
            'sha256'
        );
    }

    /**
     * 创建 AES-256-GCM 套件
     *
     * @param string $key 256位密钥
     *
     * @throws CryptoException 如果创建失败
     */
    public static function createAES256GCM(string $key): self
    {
        return new self(
            'TLS_AES_256_GCM_SHA384',
            new AES256GCM($key),
            'sha384'
        );
    }

    /**
     * 创建 ChaCha20-Poly1305 套件
     *
     * @param string $key 256位密钥
     *
     * @throws CryptoException 如果创建失败
     */
    public static function createChaCha20Poly1305(string $key): self
    {
        return new self(
            'TLS_CHACHA20_POLY1305_SHA256',
            new ChaCha20Poly1305($key),
            'sha256'
        );
    }

    /**
     * 从套件名称创建套件（需要提供密钥）
     *
     * @param string $suiteName 套件名称
     * @param string $key       密钥
     *
     * @throws CryptoException 如果套件不支持
     */
    public static function fromName(string $suiteName, string $key): self
    {
        return match ($suiteName) {
            'TLS_AES_128_GCM_SHA256' => self::createAES128GCM($key),
            'TLS_AES_256_GCM_SHA384' => self::createAES256GCM($key),
            'TLS_CHACHA20_POLY1305_SHA256' => self::createChaCha20Poly1305($key),
            default => throw CryptoException::algorithmNotSupported("不支持的密码套件: {$suiteName}"),
        };
    }

    /**
     * 获取所有支持的密码套件
     *
     * @return string[] 支持的密码套件名称列表
     */
    public static function getSupportedSuites(): array
    {
        $suites = [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
        ];

        if (ChaCha20Poly1305::isSupported()) {
            $suites[] = 'TLS_CHACHA20_POLY1305_SHA256';
        }

        return $suites;
    }

    /**
     * 选择最佳密码套件
     *
     * @param string[] $preferredSuites 首选的密码套件列表
     *
     * @return string|null 选择的密码套件，如果没有可用的则返回null
     */
    public static function selectBestSuite(array $preferredSuites = []): ?string
    {
        $supportedSuites = self::getSupportedSuites();

        // 如果有首选列表，优先选择
        foreach ($preferredSuites as $preferred) {
            if (in_array($preferred, $supportedSuites, true)) {
                return $preferred;
            }
        }

        // 按照优先级顺序选择默认套件
        $priorityOrder = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
        ];

        foreach ($priorityOrder as $suite) {
            if (in_array($suite, $supportedSuites, true)) {
                return $suite;
            }
        }

        return null;
    }

    /**
     * 验证套件兼容性
     *
     * @param string $suiteName 套件名称
     *
     * @return bool 如果兼容则返回 true
     */
    public static function isCompatible(string $suiteName): bool
    {
        $supportedSuites = self::getSupportedSuites();

        return in_array($suiteName, $supportedSuites, true);
    }

    /**
     * 获取密码套件信息
     *
     * @return array{
     *   name: string,
     *   aead_algorithm: string,
     *   hash_algorithm: string,
     *   key_length: int,
     *   nonce_length: int,
     *   tag_length: int,
     *   hash_length: int,
     *   supported: bool
     * } 密码套件的详细信息
     */
    public function getInfo(): array
    {
        return [
            'name' => $this->name,
            'aead_algorithm' => $this->aead->getAlgorithmName(),
            'hash_algorithm' => $this->hashAlgorithm,
            'key_length' => $this->aead->getKeyLength(),
            'nonce_length' => $this->aead->getNonceLength(),
            'tag_length' => $this->aead->getTagLength(),
            'hash_length' => $this->getHashLength(),
            'supported' => $this->isSupported(),
        ];
    }
}
