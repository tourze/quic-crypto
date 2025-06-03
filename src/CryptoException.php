<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

use Exception;

/**
 * 加密操作异常类
 * 
 * 用于处理所有加密、解密、密钥派生等操作中的错误
 */
class CryptoException extends Exception
{
    /**
     * 加密失败
     */
    public const ENCRYPTION_FAILED = 1001;

    /**
     * 解密失败
     */
    public const DECRYPTION_FAILED = 1002;

    /**
     * 无效的密钥
     */
    public const INVALID_KEY = 1003;

    /**
     * 无效的随机数
     */
    public const INVALID_NONCE = 1004;

    /**
     * 无效的参数
     */
    public const INVALID_PARAMETER = 1005;

    /**
     * 算法不支持
     */
    public const ALGORITHM_NOT_SUPPORTED = 1006;

    /**
     * OpenSSL 错误
     */
    public const OPENSSL_ERROR = 1007;

    /**
     * 密钥派生失败
     */
    public const KEY_DERIVATION_FAILED = 1008;

    /**
     * 创建加密异常
     *
     * @param string $message 错误消息
     * @param int $code 错误代码
     * @param Exception|null $previous 前一个异常
     */
    public function __construct(string $message = "", int $code = 0, ?Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    /**
     * 创建加密失败异常
     */
    public static function encryptionFailed(string $reason = ''): self
    {
        $message = '加密失败';
        if ($reason) {
            $message .= ": {$reason}";
        }
        return new self($message, self::ENCRYPTION_FAILED);
    }

    /**
     * 创建解密失败异常
     */
    public static function decryptionFailed(string $reason = ''): self
    {
        $message = '解密失败';
        if ($reason) {
            $message .= ": {$reason}";
        }
        return new self($message, self::DECRYPTION_FAILED);
    }

    /**
     * 创建无效密钥异常
     */
    public static function invalidKey(string $reason = ''): self
    {
        $message = '无效的密钥';
        if ($reason) {
            $message .= ": {$reason}";
        }
        return new self($message, self::INVALID_KEY);
    }

    /**
     * 创建无效随机数异常
     */
    public static function invalidNonce(string $reason = ''): self
    {
        $message = '无效的随机数';
        if ($reason) {
            $message .= ": {$reason}";
        }
        return new self($message, self::INVALID_NONCE);
    }

    /**
     * 创建无效参数异常
     */
    public static function invalidParameter(string $reason = ''): self
    {
        $message = '无效的参数';
        if ($reason) {
            $message .= ": {$reason}";
        }
        return new self($message, self::INVALID_PARAMETER);
    }

    /**
     * 创建算法不支持异常
     */
    public static function algorithmNotSupported(string $algorithm): self
    {
        return new self("不支持的算法: {$algorithm}", self::ALGORITHM_NOT_SUPPORTED);
    }

    /**
     * 创建 OpenSSL 错误异常
     */
    public static function opensslError(string $operation): self
    {
        $errors = [];
        while ($error = openssl_error_string()) {
            $errors[] = $error;
        }
        $errorDetails = implode('; ', $errors);
        return new self("OpenSSL 操作失败 ({$operation}): {$errorDetails}", self::OPENSSL_ERROR);
    }

    /**
     * 创建密钥派生失败异常
     */
    public static function keyDerivationFailed(string $reason = ''): self
    {
        $message = '密钥派生失败';
        if ($reason) {
            $message .= ": {$reason}";
        }
        return new self($message, self::KEY_DERIVATION_FAILED);
    }
} 