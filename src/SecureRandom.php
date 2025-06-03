<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

/**
 * 安全随机数生成器
 * 
 * 提供密码学安全的随机数生成功能
 * 用于密钥生成、随机数生成等安全相关操作
 */
class SecureRandom
{
    /**
     * 生成指定长度的安全随机字节
     *
     * @param int $length 随机字节长度
     * @return string 随机字节串
     * @throws CryptoException 如果无法生成安全随机数
     */
    public static function generate(int $length): string
    {
        if ($length <= 0) {
            throw CryptoException::invalidParameter('随机数长度必须大于 0');
        }

        if ($length > 1024 * 1024) { // 1MB 限制
            throw CryptoException::invalidParameter('单次随机数生成长度不能超过 1MB');
        }

        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            throw CryptoException::opensslError('安全随机数生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 生成 AEAD 随机数 (Nonce)
     *
     * @param int $length 随机数长度，默认 12 字节（96位）
     * @return string 随机数
     * @throws CryptoException 如果生成失败
     */
    public static function generateNonce(int $length = 12): string
    {
        if ($length < 8 || $length > 16) {
            throw CryptoException::invalidParameter('Nonce 长度应在 8-16 字节之间');
        }

        return self::generate($length);
    }

    /**
     * 生成 AES 密钥
     *
     * @param int $keySize 密钥大小（128 或 256 位）
     * @return string 密钥
     * @throws CryptoException 如果参数无效或生成失败
     */
    public static function generateAESKey(int $keySize = 128): string
    {
        $validSizes = [128, 256];
        if (!in_array($keySize, $validSizes, true)) {
            throw CryptoException::invalidParameter('AES 密钥大小必须为 128 或 256 位');
        }

        return self::generate($keySize / 8);
    }

    /**
     * 生成 ChaCha20 密钥
     *
     * @return string 256位密钥（32字节）
     * @throws CryptoException 如果生成失败
     */
    public static function generateChaCha20Key(): string
    {
        return self::generate(32);
    }

    /**
     * 生成盐值
     *
     * @param int $length 盐值长度，默认 32 字节
     * @return string 盐值
     * @throws CryptoException 如果生成失败
     */
    public static function generateSalt(int $length = 32): string
    {
        if ($length < 16) {
            throw CryptoException::invalidParameter('盐值长度不应少于 16 字节');
        }

        return self::generate($length);
    }

    /**
     * 生成 QUIC 连接 ID
     *
     * @param int $length 连接 ID 长度（0-20字节）
     * @return string 连接 ID
     * @throws CryptoException 如果参数无效或生成失败
     */
    public static function generateConnectionId(int $length = 8): string
    {
        if ($length < 0 || $length > 20) {
            throw CryptoException::invalidParameter('QUIC 连接 ID 长度必须在 0-20 字节之间');
        }

        if ($length === 0) {
            return '';
        }

        return self::generate($length);
    }

    /**
     * 生成随机整数
     *
     * @param int $min 最小值
     * @param int $max 最大值
     * @return int 随机整数
     * @throws CryptoException 如果参数无效或生成失败
     */
    public static function generateInt(int $min = 0, int $max = PHP_INT_MAX): int
    {
        if ($min >= $max) {
            throw CryptoException::invalidParameter('最小值必须小于最大值');
        }

        try {
            return random_int($min, $max);
        } catch (\Exception $e) {
            throw CryptoException::opensslError('安全随机整数生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 生成随机 UUID v4
     *
     * @return string UUID 字符串
     * @throws CryptoException 如果生成失败
     */
    public static function generateUuid(): string
    {
        $data = self::generate(16);

        // 设置版本号和变体
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // 版本 4
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // 变体

        return sprintf(
            '%08s-%04s-%04s-%04s-%12s',
            bin2hex(substr($data, 0, 4)),
            bin2hex(substr($data, 4, 2)),
            bin2hex(substr($data, 6, 2)),
            bin2hex(substr($data, 8, 2)),
            bin2hex(substr($data, 10, 6))
        );
    }

    /**
     * 检查系统随机数生成器是否安全
     *
     * @return bool 如果安全则返回 true
     */
    public static function isSecure(): bool
    {
        // 检查是否有可用的安全随机数源
        if (function_exists('random_bytes')) {
            try {
                random_bytes(1);
                return true;
            } catch (\Exception) {
                return false;
            }
        }

        return false;
    }

    /**
     * 获取随机数源信息
     *
     * @return array 随机数源信息
     */
    public static function getRandomSourceInfo(): array
    {
        $info = [
            'random_bytes_available' => function_exists('random_bytes'),
            'openssl_available' => extension_loaded('openssl'),
            'sodium_available' => extension_loaded('sodium'),
        ];

        // 检查操作系统随机数源
        if (PHP_OS_FAMILY === 'Linux') {
            $info['urandom_available'] = is_readable('/dev/urandom');
            $info['random_available'] = is_readable('/dev/random');
        } elseif (PHP_OS_FAMILY === 'Windows') {
            $info['cryptgenrandom_available'] = true; // Windows 默认支持
        }

        return $info;
    }

    /**
     * 常数时间字符串比较
     * 
     * 防止时序攻击的安全字符串比较
     *
     * @param string $known 已知字符串
     * @param string $user 用户提供的字符串
     * @return bool 如果相等则返回 true
     */
    public static function timingSafeEquals(string $known, string $user): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($known, $user);
        }

        // 手工实现常数时间比较
        if (strlen($known) !== strlen($user)) {
            return false;
        }

        $result = 0;
        $length = strlen($known);
        
        for ($i = 0; $i < $length; $i++) {
            $result |= ord($known[$i]) ^ ord($user[$i]);
        }

        return $result === 0;
    }
} 