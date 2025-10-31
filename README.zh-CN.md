# QUIC 加密库

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/quic-crypto.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-crypto)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-blue.svg?style=flat-square)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square)](https://github.com/tourze/php-monorepo)
[![Code Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg?style=flat-square)](https://github.com/tourze/php-monorepo)

全面的 QUIC 协议加密库，提供 AEAD 加密、包头保护、密钥派生等核心安全功能。

## 目录

- [功能特性](#功能特性)
- [安装](#安装)
- [依赖要求](#依赖要求)
- [快速开始](#快速开始)
- [基本使用](#基本使用)
  - [AEAD 加密](#aead-加密)
  - [密钥派生](#密钥派生)
  - [包头保护](#包头保护)
  - [密码套件管理](#密码套件管理)
  - [密钥管理器](#密钥管理器)
  - [安全随机数](#安全随机数)
- [API 文档](#api-文档)
  - [异常处理](#异常处理)
  - [支持的算法](#支持的算法)
- [安全考虑](#安全考虑)
- [测试](#测试)
- [贡献指南](#贡献指南)
- [参考文档](#参考文档)
- [许可证](#许可证)

## 功能特性

- **AEAD 加密算法**：支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305
- **包头保护**：QUIC 数据包头保护实现
- **密钥派生**：基于 RFC 5869 的 HKDF 密钥派生功能
- **密钥管理**：完整的 QUIC 密钥生命周期管理
- **密码套件**：标准 QUIC 密码套件管理和选择
- **安全随机数**：密码学安全的随机数生成
- **RFC 合规**：严格遵循 RFC 9001 (QUIC-TLS) 和相关标准

## 安装

```bash
composer require tourze/quic-crypto
```

## 依赖要求

- PHP 8.1 或更高版本
- OpenSSL 扩展（必需）
- Sodium 扩展（可选，提供更好的安全性）
- Hash 扩展（必需）

## 快速开始

快速开始使用 QUIC 加密库的基本功能：

```php
<?php
require_once 'vendor/autoload.php';

use Tourze\QUIC\Crypto\AES128GCM;
use Tourze\QUIC\Crypto\KeyDerivation;
use Tourze\QUIC\Crypto\SecureRandom;

// 1. 生成安全的加密密钥
$key = SecureRandom::generateAESKey(128);

// 2. 创建 AEAD 加密实例
$aes = new AES128GCM($key);

// 3. 加密数据
$plaintext = 'Hello, QUIC!';
$nonce = SecureRandom::generateNonce(12);
$aad = 'additional authenticated data';
$ciphertext = $aes->encrypt($plaintext, $nonce, $aad);

// 4. 解密数据
$decrypted = $aes->decrypt($ciphertext, $nonce, $aad);
echo $decrypted; // 输出: Hello, QUIC!

// 5. 密钥派生示例
$secret = SecureRandom::generate(32);
$derivedKey = KeyDerivation::quicKDF($secret, 'quic key', 16);
```

## 基本使用

### AEAD 加密

```php
use Tourze\QUIC\Crypto\AES128GCM;

// 创建 AES-128-GCM 实例
$key = random_bytes(16);
$aes = new AES128GCM($key);

// 加密数据
$plaintext = 'Hello, QUIC!';
$nonce = random_bytes(12);
$aad = 'additional data';
$ciphertext = $aes->encrypt($plaintext, $nonce, $aad);

// 解密数据
$decrypted = $aes->decrypt($ciphertext, $nonce, $aad);
```

### 密钥派生

```php
use Tourze\QUIC\Crypto\KeyDerivation;

// HKDF 密钥派生
$ikm = 'input key material';
$salt = 'optional salt';
$info = 'context info';
$length = 32;

$derivedKey = KeyDerivation::hkdf($ikm, $length, $info, $salt);

// QUIC 专用密钥派生
$secret = random_bytes(32);
$label = 'quic key';
$quicKey = KeyDerivation::quicKDF($secret, $label, 16);
```

### 包头保护

```php
use Tourze\QUIC\Crypto\HeaderProtection;
use Tourze\QUIC\Crypto\AES128GCM;

$aesKey = random_bytes(16);
$hpKey = random_bytes(16);
$aes = new AES128GCM($aesKey);

$hp = new HeaderProtection($aes, $hpKey);

// 保护包头
$header = "\x40\x01\x02\x03\x04";
$sample = random_bytes(16);
$protectedHeader = $hp->protect($header, $sample);

// 取消保护
$originalHeader = $hp->unprotect($protectedHeader, $sample);
```

### 密码套件管理

```php
use Tourze\QUIC\Crypto\CryptoSuite;

// 创建密码套件
$key = random_bytes(16);
$suite = CryptoSuite::createAES128GCM($key);

// 获取套件信息
echo $suite->getName(); // TLS_AES_128_GCM_SHA256
echo $suite->getKeyLength(); // 16
echo $suite->getHashAlgorithm(); // sha256

// 检查支持的套件
$supported = CryptoSuite::getSupportedSuites();
$best = CryptoSuite::selectBestSuite();
```

### 密钥管理器

```php
use Tourze\QUIC\Crypto\KeyManager;
use Tourze\QUIC\Crypto\CryptoSuite;

$suite = CryptoSuite::createAES128GCM(random_bytes(16));
$keyManager = new KeyManager($suite);

// 派生初始密钥
$connectionId = random_bytes(8);
$secrets = $keyManager->deriveInitialSecrets($connectionId);

// 获取当前密钥
$writeKey = $keyManager->getWriteKey(true); // 客户端密钥
$writeIv = $keyManager->getWriteIv(true);
$hpKey = $keyManager->getHpKey(true);

// 构造 nonce
$packetNumber = 12345;
$nonce = $keyManager->constructNonce($writeIv, $packetNumber);
```

### 安全随机数

```php
use Tourze\QUIC\Crypto\SecureRandom;

// 生成随机字节
$randomBytes = SecureRandom::generate(32);

// 生成 nonce
$nonce = SecureRandom::generateNonce(12);

// 生成密钥
$aesKey = SecureRandom::generateAESKey(128); // AES-128
$chachaKey = SecureRandom::generateChaCha20Key(); // ChaCha20

// 生成连接 ID
$connectionId = SecureRandom::generateConnectionId(8);

// 生成 UUID
$uuid = SecureRandom::generateUuid();

// 时序安全比较
$equal = SecureRandom::timingSafeEquals($string1, $string2);
```

## API 文档

### 异常处理

所有方法可能抛出 `CryptoException` 异常：

```php
use Tourze\QUIC\Crypto\Exception\CryptoException;

try {
    $ciphertext = $aes->encrypt($plaintext, $nonce, $aad);
} catch (CryptoException $e) {
    echo '加密失败: ' . $e->getMessage();
    echo '错误代码: ' . $e->getCode();
}
```

### 支持的算法

- **AEAD**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **哈希**: SHA-256, SHA-384, SHA-512
- **密码套件**: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256

## 安全考虑

1. **密钥管理**: 使用完毕后立即清理敏感密钥
2. **随机数**: 使用密码学安全的随机数生成器
3. **时序攻击**: 提供时序安全的字符串比较函数
4. **内存安全**: 自动清理内存中的敏感数据
5. **恒定时间操作**: 关键操作设计为恒定时间

## 测试

运行测试套件：

```bash
./vendor/bin/phpunit packages/quic-crypto/tests
```

## 贡献指南

我们欢迎贡献！请遵循以下指南：

1. **问题反馈**: 通过 GitHub Issues 报告错误或功能请求
2. **拉取请求**: 
    - Fork 仓库
    - 创建功能分支 (`git checkout -b feature/amazing-feature`)
    - 提交更改 (`git commit -m 'Add amazing feature'`)
    - 推送到分支 (`git push origin feature/amazing-feature`)
    - 打开拉取请求

3. **代码风格**: 遵循 PSR-12 编码标准
4. **测试**: 确保所有测试通过并为新功能添加测试
5. **文档**: 为任何 API 更改更新文档

## 参考文档

- [RFC 9001: Using TLS to Secure QUIC](https://tools.ietf.org/html/rfc9001)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [RFC 5116: An Interface and Algorithms for Authenticated Encryption](https://tools.ietf.org/html/rfc5116)

## 许可证

MIT 许可证。详情请参见 [LICENSE](LICENSE) 文件。
