# QUIC Crypto Library

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/quic-crypto.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-crypto)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-blue.svg?style=flat-square)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square)](https://github.com/tourze/php-monorepo)
[![Code Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg?style=flat-square)](https://github.com/tourze/php-monorepo)

A comprehensive QUIC protocol cryptographic library providing AEAD encryption, header protection, key derivation, and other core security features.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Basic Usage](#basic-usage)
  - [AEAD Encryption](#aead-encryption)
  - [Key Derivation](#key-derivation)
  - [Header Protection](#header-protection)
  - [Crypto Suite Management](#crypto-suite-management)
  - [Key Manager](#key-manager)
  - [Secure Random](#secure-random)
- [API Documentation](#api-documentation)
  - [Exception Handling](#exception-handling)
  - [Supported Algorithms](#supported-algorithms)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

## Features

- **AEAD Encryption**: Support for AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Header Protection**: QUIC packet header protection implementation
- **Key Derivation**: HKDF-based key derivation following RFC 5869
- **Key Management**: Complete QUIC key lifecycle management
- **Crypto Suites**: Standard QUIC cipher suite management and selection
- **Secure Random**: Cryptographically secure random number generation
- **RFC Compliance**: Strict adherence to RFC 9001 (QUIC-TLS) and related standards

## Installation

```bash
composer require tourze/quic-crypto
```

## Requirements

- PHP 8.1 or higher
- OpenSSL extension (required)
- Sodium extension (optional, for enhanced security)
- Hash extension (required)

## Quick Start

Get started with the QUIC Crypto Library in minutes:

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

// 4. Decrypt data
$decrypted = $aes->decrypt($ciphertext, $nonce, $aad);
echo $decrypted; // Output: Hello, QUIC!

// 5. Key derivation example
$secret = SecureRandom::generate(32);
$derivedKey = KeyDerivation::quicKDF($secret, 'quic key', 16);
```

## Basic Usage

### AEAD Encryption

```php
use Tourze\QUIC\Crypto\AES128GCM;

// Create AES-128-GCM instance
$key = random_bytes(16);
$aes = new AES128GCM($key);

// Encrypt data
$plaintext = 'Hello, QUIC!';
$nonce = random_bytes(12);
$aad = 'additional data';
$ciphertext = $aes->encrypt($plaintext, $nonce, $aad);

// Decrypt data
$decrypted = $aes->decrypt($ciphertext, $nonce, $aad);
```

### Key Derivation

```php
use Tourze\QUIC\Crypto\KeyDerivation;

// HKDF key derivation
$ikm = 'input key material';
$salt = 'optional salt';
$info = 'context info';
$length = 32;

$derivedKey = KeyDerivation::hkdf($ikm, $length, $info, $salt);

// QUIC-specific key derivation
$secret = random_bytes(32);
$label = 'quic key';
$quicKey = KeyDerivation::quicKDF($secret, $label, 16);
```

### Header Protection

```php
use Tourze\QUIC\Crypto\HeaderProtection;
use Tourze\QUIC\Crypto\AES128GCM;

$aesKey = random_bytes(16);
$hpKey = random_bytes(16);
$aes = new AES128GCM($aesKey);

$hp = new HeaderProtection($aes, $hpKey);

// Protect header
$header = "\x40\x01\x02\x03\x04";
$sample = random_bytes(16);
$protectedHeader = $hp->protect($header, $sample);

// Unprotect header
$originalHeader = $hp->unprotect($protectedHeader, $sample);
```

### Crypto Suite Management

```php
use Tourze\QUIC\Crypto\CryptoSuite;

// Create crypto suite
$key = random_bytes(16);
$suite = CryptoSuite::createAES128GCM($key);

// Get suite information
echo $suite->getName(); // TLS_AES_128_GCM_SHA256
echo $suite->getKeyLength(); // 16
echo $suite->getHashAlgorithm(); // sha256

// Check supported suites
$supported = CryptoSuite::getSupportedSuites();
$best = CryptoSuite::selectBestSuite();
```

### Key Manager

```php
use Tourze\QUIC\Crypto\KeyManager;
use Tourze\QUIC\Crypto\CryptoSuite;

$suite = CryptoSuite::createAES128GCM(random_bytes(16));
$keyManager = new KeyManager($suite);

// Derive initial secrets
$connectionId = random_bytes(8);
$secrets = $keyManager->deriveInitialSecrets($connectionId);

// Get current keys
$writeKey = $keyManager->getWriteKey(true); // Client key
$writeIv = $keyManager->getWriteIv(true);
$hpKey = $keyManager->getHpKey(true);

// Construct nonce
$packetNumber = 12345;
$nonce = $keyManager->constructNonce($writeIv, $packetNumber);
```

### Secure Random

```php
use Tourze\QUIC\Crypto\SecureRandom;

// Generate random bytes
$randomBytes = SecureRandom::generate(32);

// Generate nonce
$nonce = SecureRandom::generateNonce(12);

// Generate keys
$aesKey = SecureRandom::generateAESKey(128); // AES-128
$chachaKey = SecureRandom::generateChaCha20Key(); // ChaCha20

// Generate connection ID
$connectionId = SecureRandom::generateConnectionId(8);

// Generate UUID
$uuid = SecureRandom::generateUuid();

// Timing-safe comparison
$equal = SecureRandom::timingSafeEquals($string1, $string2);
```

## API Documentation

### Exception Handling

All methods may throw `CryptoException`:

```php
use Tourze\QUIC\Crypto\Exception\CryptoException;

try {
    $ciphertext = $aes->encrypt($plaintext, $nonce, $aad);
} catch (CryptoException $e) {
    echo 'Encryption failed: ' . $e->getMessage();
    echo 'Error code: ' . $e->getCode();
}
```

### Supported Algorithms

- **AEAD**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Hash**: SHA-256, SHA-384, SHA-512
- **Cipher Suites**: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256

## Security Considerations

1. **Key Management**: Clear sensitive keys immediately after use
2. **Random Numbers**: Use cryptographically secure random number generators
3. **Timing Attacks**: Timing-safe string comparison functions are provided
4. **Memory Safety**: Automatic cleanup of sensitive data in memory
5. **Constant-Time Operations**: Critical operations are designed to be constant-time

## Testing

Run the test suite:

```bash
./vendor/bin/phpunit packages/quic-crypto/tests
```

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Issues**: Report bugs or feature requests via GitHub Issues
2. **Pull Requests**: 
    - Fork the repository
    - Create a feature branch (`git checkout -b feature/amazing-feature`)
    - Commit your changes (`git commit -m 'Add amazing feature'`)
    - Push to the branch (`git push origin feature/amazing-feature`)
    - Open a Pull Request

3. **Code Style**: Follow PSR-12 coding standards
4. **Testing**: Ensure all tests pass and add tests for new features
5. **Documentation**: Update documentation for any API changes

## References

- [RFC 9001: Using TLS to Secure QUIC](https://tools.ietf.org/html/rfc9001)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [RFC 5116: An Interface and Algorithms for Authenticated Encryption](https://tools.ietf.org/html/rfc5116)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
