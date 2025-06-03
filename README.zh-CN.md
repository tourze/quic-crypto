# QUIC 加密库

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

## 核心特性

- 严格遵循RFC 9001 (QUIC-TLS)和RFC 5869 (HKDF)规范
- 支持所有QUIC标准密码套件
- 提供完整的密钥生命周期管理
- 实现包头保护和认证加密功能
- 内置安全的随机数生成和密钥清理机制

## 依赖要求

- PHP 8.1+
- OpenSSL扩展（必需）
- Sodium扩展（可选，提供更好的安全性）

## 快速开始

详细的使用示例和API文档请参考 [README.md](README.md)

## 测试

```bash
./vendor/bin/phpunit packages/quic-crypto/tests
```

## 许可证

MIT License

## 使用方法

待补充

## 配置

待补充

## 示例

待补充

## 参考文档

- [示例链接](https://example.com)
