<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

/**
 * HKDF 密钥派生功能
 * 
 * 基于 RFC 5869 实现的 HMAC-based Key Derivation Function
 * 提供安全的密钥派生和扩展功能
 */
class KeyDerivation
{
    /**
     * HKDF-Extract 步骤：从输入密钥材料中提取伪随机密钥
     *
     * @param string $salt 盐值（可选）
     * @param string $ikm 输入密钥材料 (Input Keying Material)
     * @param string $hash 哈希算法名称
     * @return string 伪随机密钥 (PRK)
     * @throws CryptoException 如果哈希算法不支持或计算失败
     */
    public static function hkdfExtract(string $salt, string $ikm, string $hash = 'sha256'): string
    {
        if (!in_array($hash, hash_algos(), true)) {
            throw CryptoException::algorithmNotSupported($hash);
        }

        // 如果没有提供盐值，使用零填充的字符串，长度为哈希函数输出长度
        if ($salt === '') {
            $hashLength = strlen(hash($hash, '', true));
            $salt = str_repeat("\x00", $hashLength);
        }

        $prk = hash_hmac($hash, $ikm, $salt, true);
        
        if ($prk === false) {
            throw CryptoException::keyDerivationFailed('HKDF-Extract 计算失败');
        }

        return $prk;
    }

    /**
     * HKDF-Expand 步骤：将伪随机密钥扩展为所需长度的输出密钥材料
     *
     * @param string $prk 伪随机密钥
     * @param string $info 上下文信息
     * @param int $length 输出密钥材料长度
     * @param string $hash 哈希算法名称
     * @return string 输出密钥材料 (OKM)
     * @throws CryptoException 如果参数无效或计算失败
     */
    public static function hkdfExpand(string $prk, string $info, int $length, string $hash = 'sha256'): string
    {
        if (!in_array($hash, hash_algos(), true)) {
            throw CryptoException::algorithmNotSupported($hash);
        }

        if ($length <= 0) {
            throw CryptoException::invalidParameter('输出长度必须大于 0');
        }

        $hashLength = strlen(hash($hash, '', true));
        $maxLength = 255 * $hashLength;

        if ($length > $maxLength) {
            throw CryptoException::invalidParameter(
                sprintf('输出长度不能超过 %d 字节 (255 * %d)', $maxLength, $hashLength)
            );
        }

        $n = (int) ceil($length / $hashLength);
        $okm = '';
        $t = '';

        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac($hash, $t . $info . chr($i), $prk, true);
            
            if ($t === false) {
                throw CryptoException::keyDerivationFailed('HKDF-Expand 计算失败');
            }
            
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }

    /**
     * 完整的 HKDF 操作（Extract + Expand）
     *
     * @param string $ikm 输入密钥材料
     * @param int $length 输出密钥材料长度
     * @param string $info 上下文信息
     * @param string $salt 盐值
     * @param string $hash 哈希算法名称
     * @return string 派生的密钥材料
     * @throws CryptoException 如果派生失败
     */
    public static function hkdf(
        string $ikm, 
        int $length, 
        string $info = '', 
        string $salt = '', 
        string $hash = 'sha256'
    ): string {
        $prk = self::hkdfExtract($salt, $ikm, $hash);
        return self::hkdfExpand($prk, $info, $length, $hash);
    }

    /**
     * QUIC 专用的密钥派生
     * 
     * 根据 RFC 9001 实现 QUIC 协议的密钥派生
     *
     * @param string $secret 共享密钥
     * @param string $label 标签
     * @param int $length 输出长度
     * @return string 派生的密钥
     * @throws CryptoException 如果派生失败
     */
    public static function quicKDF(string $secret, string $label, int $length): string
    {
        // QUIC 使用 TLS 1.3 的标签格式
        $quicLabel = self::buildQuicLabel($label, $length);
        return self::hkdfExpand($secret, $quicLabel, $length, 'sha256');
    }

    /**
     * 构建 QUIC 标签
     * 
     * 根据 TLS 1.3 格式构建 HKDF 标签
     *
     * @param string $label 标签字符串
     * @param int $length 输出长度
     * @return string 编码后的标签
     */
    private static function buildQuicLabel(string $label, int $length): string
    {
        $fullLabel = 'tls13 ' . $label;
        
        // 构建 HkdfLabel 结构
        // struct {
        //     uint16 length;
        //     opaque label<7..255>;
        //     opaque context<0..255>;
        // } HkdfLabel;
        
        $labelLength = strlen($fullLabel);
        if ($labelLength > 255) {
            throw CryptoException::invalidParameter('标签长度不能超过 255 字节');
        }

        return pack('n', $length) .           // length (2 bytes)
               chr($labelLength) .            // label length (1 byte)
               $fullLabel .                   // label
               chr(0);                        // context length (1 byte, 空上下文)
    }

    /**
     * 生成初始盐值
     * 
     * QUIC v1 使用的初始盐值
     */
    public static function getQuicInitialSalt(): string
    {
        // RFC 9001 Section 5.2: Initial Secrets
        $result = hex2bin('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');
        
        if ($result === false) {
            throw CryptoException::keyDerivationFailed('初始盐值解码失败');
        }
        
        return $result;
    }

    /**
     * 清理敏感数据
     * 
     * 安全地清除内存中的敏感数据
     *
     * @param string &$data 要清理的数据
     */
    public static function secureClear(string &$data): void
    {
        $length = strlen($data);
        if ($length > 0) {
            if (function_exists('sodium_memzero') && extension_loaded('sodium')) {
                // sodium_memzero 会修改原始字符串内容但不会改变引用
                $temp = $data;
                sodium_memzero($temp);
                $data = str_repeat("\x00", $length);
            } else {
                // 回退方案：用随机数据覆盖然后清零
                $data = random_bytes($length);
                $data = str_repeat("\x00", $length);
            }
        }
    }
} 