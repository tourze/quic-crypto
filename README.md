# QUIC Crypto Library

QUIC协议加密库 - 提供AEAD加密、包头保护、密钥派生等核心安全功能

## 功能特性

- **AEAD加密算法**：支持AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305
- **包头保护**：实现QUIC数据包头保护机制 
- **密钥派生**：基于RFC 5869的HKDF密钥派生功能
- **密钥管理**：完整的QUIC密钥生命周期管理
- **密码套件**：支持标准QUIC密码套件管理和选择
- **安全随机数**：密码学安全的随机数生成器

## 安装

```bash
composer require tourze/quic-crypto
```

## 基本使用

### AEAD加密

```php
use Tourze\QUIC\Crypto\AES128GCM;

// 创建AES-128-GCM实例
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

// HKDF密钥派生
$ikm = 'input key material';
$salt = 'optional salt';
$info = 'context info';
$length = 32;

$derivedKey = KeyDerivation::hkdf($ikm, $length, $info, $salt);

// QUIC专用密钥派生
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

// 构造nonce
$packetNumber = 12345;
$nonce = $keyManager->constructNonce($writeIv, $packetNumber);
```

### 安全随机数

```php
use Tourze\QUIC\Crypto\SecureRandom;

// 生成随机字节
$randomBytes = SecureRandom::generate(32);

// 生成nonce
$nonce = SecureRandom::generateNonce(12);

// 生成密钥
$aesKey = SecureRandom::generateAESKey(128); // AES-128
$chachaKey = SecureRandom::generateChaCha20Key(); // ChaCha20

// 生成连接ID
$connectionId = SecureRandom::generateConnectionId(8);

// 生成UUID
$uuid = SecureRandom::generateUuid();

// 时序安全比较
$equal = SecureRandom::timingSafeEquals($string1, $string2);
```

## API文档

### 异常处理

所有方法可能抛出 `CryptoException` 异常：

```php
use Tourze\QUIC\Crypto\CryptoException;

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

## 测试

```bash
./vendor/bin/phpunit packages/quic-crypto/tests
```

## 要求

- PHP 8.1+
- OpenSSL扩展
- Sodium扩展（可选，用于更好的安全性）

## 参考文档

- [RFC 9001: Using TLS to Secure QUIC](https://tools.ietf.org/html/rfc9001)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [RFC 5116: An Interface and Algorithms for Authenticated Encryption](https://tools.ietf.org/html/rfc5116)

## 许可证

MIT License
