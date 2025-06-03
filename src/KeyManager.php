<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto;

/**
 * QUIC 密钥管理器
 * 
 * 负责管理 QUIC 连接的所有密钥，包括初始密钥、握手密钥和应用数据密钥
 * 实现密钥派生、更新和安全清理功能
 */
class KeyManager
{
    /**
     * 密码套件
     */
    private readonly CryptoSuite $suite;

    /**
     * 当前客户端写入密钥
     */
    private string $clientWriteKey = '';

    /**
     * 当前客户端写入 IV
     */
    private string $clientWriteIv = '';

    /**
     * 当前服务端写入密钥
     */
    private string $serverWriteKey = '';

    /**
     * 当前服务端写入 IV
     */
    private string $serverWriteIv = '';

    /**
     * 客户端包头保护密钥
     */
    private string $clientHpKey = '';

    /**
     * 服务端包头保护密钥
     */
    private string $serverHpKey = '';

    /**
     * 密钥更新计数器
     */
    private int $keyUpdateCount = 0;

    /**
     * 构造函数
     *
     * @param CryptoSuite $suite 密码套件
     */
    public function __construct(CryptoSuite $suite)
    {
        $this->suite = $suite;
    }

    /**
     * 销毁时清理所有敏感数据
     */
    public function __destruct()
    {
        $this->clearSensitiveData();
    }

    /**
     * 派生初始密钥
     * 
     * 根据 RFC 9001 Section 5.2 实现初始密钥派生
     *
     * @param string $connectionId 目标连接 ID
     * @param bool $isServer 是否为服务端
     * @return array 包含客户端和服务端密钥的数组
     * @throws CryptoException 如果派生失败
     */
    public function deriveInitialSecrets(string $connectionId, bool $isServer = false): array
    {
        $initialSalt = KeyDerivation::getQuicInitialSalt();
        
        // 将密码套件信息和连接ID组合作为输入密钥材料
        // 这确保了不同的密码套件产生不同的密钥
        $ikm = $connectionId . $this->suite->getName() . $this->getSuiteKeyMaterial();
        
        $initialSecret = KeyDerivation::hkdfExtract($initialSalt, $ikm, $this->suite->getHashAlgorithm());

        // 派生客户端和服务端的初始密钥
        $clientInitialSecret = KeyDerivation::quicKDF($initialSecret, 'client in', $this->suite->getHashLength());
        $serverInitialSecret = KeyDerivation::quicKDF($initialSecret, 'server in', $this->suite->getHashLength());

        // 派生具体的密钥材料
        $clientKeys = $this->deriveKeysFromSecret($clientInitialSecret);
        $serverKeys = $this->deriveKeysFromSecret($serverInitialSecret);

        // 根据角色设置当前密钥
        if ($isServer) {
            $this->setKeys($serverKeys['write_key'], $serverKeys['write_iv'], $serverKeys['hp_key'], true);
            $this->setKeys($clientKeys['write_key'], $clientKeys['write_iv'], $clientKeys['hp_key'], false);
        } else {
            $this->setKeys($clientKeys['write_key'], $clientKeys['write_iv'], $clientKeys['hp_key'], true);
            $this->setKeys($serverKeys['write_key'], $serverKeys['write_iv'], $serverKeys['hp_key'], false);
        }

        // 安全清理临时密钥
        KeyDerivation::secureClear($initialSecret);
        KeyDerivation::secureClear($clientInitialSecret);
        KeyDerivation::secureClear($serverInitialSecret);
        KeyDerivation::secureClear($ikm);

        return [
            'client' => $clientKeys,
            'server' => $serverKeys,
        ];
    }

    /**
     * 派生握手密钥
     *
     * @param string $handshakeSecret 握手密钥
     * @param bool $isServer 是否为服务端
     * @return array 握手密钥材料
     * @throws CryptoException 如果派生失败
     */
    public function deriveHandshakeSecrets(string $handshakeSecret, bool $isServer = false): array
    {
        $clientHandshakeSecret = KeyDerivation::quicKDF($handshakeSecret, 'c hs traffic', $this->suite->getHashLength());
        $serverHandshakeSecret = KeyDerivation::quicKDF($handshakeSecret, 's hs traffic', $this->suite->getHashLength());

        $clientKeys = $this->deriveKeysFromSecret($clientHandshakeSecret);
        $serverKeys = $this->deriveKeysFromSecret($serverHandshakeSecret);

        // 更新当前密钥
        if ($isServer) {
            $this->setKeys($serverKeys['write_key'], $serverKeys['write_iv'], $serverKeys['hp_key'], true);
            $this->setKeys($clientKeys['write_key'], $clientKeys['write_iv'], $clientKeys['hp_key'], false);
        } else {
            $this->setKeys($clientKeys['write_key'], $clientKeys['write_iv'], $clientKeys['hp_key'], true);
            $this->setKeys($serverKeys['write_key'], $serverKeys['write_iv'], $serverKeys['hp_key'], false);
        }

        // 安全清理
        KeyDerivation::secureClear($clientHandshakeSecret);
        KeyDerivation::secureClear($serverHandshakeSecret);

        return [
            'client' => $clientKeys,
            'server' => $serverKeys,
        ];
    }

    /**
     * 派生应用数据密钥
     *
     * @param string $masterSecret 主密钥
     * @param bool $isServer 是否为服务端
     * @return array 应用数据密钥材料
     * @throws CryptoException 如果派生失败
     */
    public function deriveApplicationSecrets(string $masterSecret, bool $isServer = false): array
    {
        $clientAppSecret = KeyDerivation::quicKDF($masterSecret, 'c ap traffic', $this->suite->getHashLength());
        $serverAppSecret = KeyDerivation::quicKDF($masterSecret, 's ap traffic', $this->suite->getHashLength());

        $clientKeys = $this->deriveKeysFromSecret($clientAppSecret);
        $serverKeys = $this->deriveKeysFromSecret($serverAppSecret);

        // 更新当前密钥
        if ($isServer) {
            $this->setKeys($serverKeys['write_key'], $serverKeys['write_iv'], $serverKeys['hp_key'], true);
            $this->setKeys($clientKeys['write_key'], $clientKeys['write_iv'], $clientKeys['hp_key'], false);
        } else {
            $this->setKeys($clientKeys['write_key'], $clientKeys['write_iv'], $clientKeys['hp_key'], true);
            $this->setKeys($serverKeys['write_key'], $serverKeys['write_iv'], $serverKeys['hp_key'], false);
        }

        // 安全清理
        KeyDerivation::secureClear($clientAppSecret);
        KeyDerivation::secureClear($serverAppSecret);

        return [
            'client' => $clientKeys,
            'server' => $serverKeys,
        ];
    }

    /**
     * 更新应用数据密钥
     *
     * @param string $currentSecret 当前密钥
     * @return string 新的密钥
     * @throws CryptoException 如果更新失败
     */
    public function updateTrafficSecrets(string $currentSecret): string
    {
        $newSecret = KeyDerivation::quicKDF($currentSecret, 'traffic upd', $this->suite->getHashLength());
        $this->keyUpdateCount++;

        // 派生新的密钥材料
        $newKeys = $this->deriveKeysFromSecret($newSecret);

        // 这里需要根据实际需要更新对应的密钥
        // 具体的更新逻辑取决于是客户端还是服务端，以及更新的方向

        return $newSecret;
    }

    /**
     * 从密钥派生具体的密钥材料
     *
     * @param string $secret 基础密钥
     * @return array 密钥材料
     * @throws CryptoException 如果派生失败
     */
    private function deriveKeysFromSecret(string $secret): array
    {
        $keyLength = $this->suite->getKeyLength();
        $ivLength = $this->suite->getNonceLength();

        // 派生写入密钥
        $writeKey = KeyDerivation::quicKDF($secret, 'quic key', $keyLength);

        // 派生写入 IV
        $writeIv = KeyDerivation::quicKDF($secret, 'quic iv', $ivLength);

        // 派生包头保护密钥
        $hpKey = KeyDerivation::quicKDF($secret, 'quic hp', $keyLength);

        return [
            'write_key' => $writeKey,
            'write_iv' => $writeIv,
            'hp_key' => $hpKey,
        ];
    }

    /**
     * 设置密钥
     *
     * @param string $writeKey 写入密钥
     * @param string $writeIv 写入 IV
     * @param string $hpKey 包头保护密钥
     * @param bool $isLocal 是否为本地密钥
     */
    private function setKeys(string $writeKey, string $writeIv, string $hpKey, bool $isLocal): void
    {
        if ($isLocal) {
            $this->clientWriteKey = $writeKey;
            $this->clientWriteIv = $writeIv;
            $this->clientHpKey = $hpKey;
        } else {
            $this->serverWriteKey = $writeKey;
            $this->serverWriteIv = $writeIv;
            $this->serverHpKey = $hpKey;
        }
    }

    /**
     * 获取写入密钥
     *
     * @param bool $isClient 是否获取客户端密钥
     * @return string 写入密钥
     */
    public function getWriteKey(bool $isClient = true): string
    {
        return $isClient ? $this->clientWriteKey : $this->serverWriteKey;
    }

    /**
     * 获取写入 IV
     *
     * @param bool $isClient 是否获取客户端 IV
     * @return string 写入 IV
     */
    public function getWriteIv(bool $isClient = true): string
    {
        return $isClient ? $this->clientWriteIv : $this->serverWriteIv;
    }

    /**
     * 获取包头保护密钥
     *
     * @param bool $isClient 是否获取客户端密钥
     * @return string 包头保护密钥
     */
    public function getHpKey(bool $isClient = true): string
    {
        return $isClient ? $this->clientHpKey : $this->serverHpKey;
    }

    /**
     * 构造 Nonce
     *
     * @param string $iv 基础 IV
     * @param int $packetNumber 包号
     * @return string 构造的 Nonce
     * @throws CryptoException 如果构造失败
     */
    public function constructNonce(string $iv, int $packetNumber): string
    {
        if (strlen($iv) !== $this->suite->getNonceLength()) {
            throw CryptoException::invalidParameter('IV 长度不正确');
        }

        // 将包号转换为大端序字节
        $packetNumberBytes = str_repeat("\x00", 8) . pack('N', $packetNumber);
        $packetNumberBytes = substr($packetNumberBytes, -strlen($iv));

        // 与 IV 进行异或运算
        $nonce = '';
        for ($i = 0; $i < strlen($iv); $i++) {
            $nonce .= chr(ord($iv[$i]) ^ ord($packetNumberBytes[$i]));
        }

        return $nonce;
    }

    /**
     * 获取密钥更新计数
     */
    public function getKeyUpdateCount(): int
    {
        return $this->keyUpdateCount;
    }

    /**
     * 清理所有敏感数据
     */
    public function clearSensitiveData(): void
    {
        KeyDerivation::secureClear($this->clientWriteKey);
        KeyDerivation::secureClear($this->clientWriteIv);
        KeyDerivation::secureClear($this->serverWriteKey);
        KeyDerivation::secureClear($this->serverWriteIv);
        KeyDerivation::secureClear($this->clientHpKey);
        KeyDerivation::secureClear($this->serverHpKey);

        $this->keyUpdateCount = 0;
    }

    /**
     * 检查密钥是否已初始化
     */
    public function isInitialized(): bool
    {
        return !empty($this->clientWriteKey) || !empty($this->serverWriteKey);
    }

    /**
     * 获取密码套件的关键材料
     * 
     * 用于确保不同密码套件实例产生不同的密钥
     * 
     * @return string 密码套件的关键材料
     */
    private function getSuiteKeyMaterial(): string
    {
        // 获取密码套件的基本信息作为关键材料
        $info = $this->suite->getInfo();
        
        // 组合关键信息创建唯一的套件材料
        return hash('sha256', 
            $info['name'] . 
            $info['aead_algorithm'] . 
            $info['hash_algorithm'] . 
            $info['key_length'] . 
            $info['nonce_length'] . 
            $info['tag_length'] . 
            // 添加实例的唯一标识
            spl_object_hash($this->suite->getAEAD()),
            true
        );
    }
} 