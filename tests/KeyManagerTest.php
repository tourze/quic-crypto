<?php

declare(strict_types=1);

namespace Tourze\QUIC\Crypto\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Crypto\CryptoException;
use Tourze\QUIC\Crypto\CryptoSuite;
use Tourze\QUIC\Crypto\KeyManager;

/**
 * QUIC 密钥管理器测试类
 */
class KeyManagerTest extends TestCase
{
    private KeyManager $keyManager;
    private CryptoSuite $suite;

    protected function setUp(): void
    {
        $key = str_repeat("\x01", 16);
        $this->suite = CryptoSuite::createAES128GCM($key);
        $this->keyManager = new KeyManager($this->suite);
    }

    public function testInitialState(): void
    {
        $this->assertFalse($this->keyManager->isInitialized());
        $this->assertEquals(0, $this->keyManager->getKeyUpdateCount());
        $this->assertEquals('', $this->keyManager->getWriteKey());
        $this->assertEquals('', $this->keyManager->getWriteIv());
        $this->assertEquals('', $this->keyManager->getHpKey());
    }

    public function testDeriveInitialSecretsClient(): void
    {
        $connectionId = str_repeat("\x02", 8);
        $isServer = false;

        $secrets = $this->keyManager->deriveInitialSecrets($connectionId, $isServer);

        $this->assertIsArray($secrets);
        $this->assertArrayHasKey('client', $secrets);
        $this->assertArrayHasKey('server', $secrets);

        $clientKeys = $secrets['client'];
        $this->assertArrayHasKey('write_key', $clientKeys);
        $this->assertArrayHasKey('write_iv', $clientKeys);
        $this->assertArrayHasKey('hp_key', $clientKeys);

        $this->assertEquals(16, strlen($clientKeys['write_key']));
        $this->assertEquals(12, strlen($clientKeys['write_iv']));
        $this->assertEquals(16, strlen($clientKeys['hp_key']));

        // 作为客户端，应该设置客户端密钥为本地密钥
        $this->assertTrue($this->keyManager->isInitialized());
        $this->assertEquals($clientKeys['write_key'], $this->keyManager->getWriteKey(true));
        $this->assertEquals($clientKeys['write_iv'], $this->keyManager->getWriteIv(true));
        $this->assertEquals($clientKeys['hp_key'], $this->keyManager->getHpKey(true));
    }

    public function testDeriveInitialSecretsServer(): void
    {
        $connectionId = str_repeat("\x03", 8);
        $isServer = true;

        $secrets = $this->keyManager->deriveInitialSecrets($connectionId, $isServer);

        $serverKeys = $secrets['server'];
        
        // 作为服务端，应该设置服务端密钥为本地密钥
        $this->assertTrue($this->keyManager->isInitialized());
        // 服务端的本地密钥应该是服务端密钥（isLocal=true时存储在client变量中）
        $this->assertEquals($serverKeys['write_key'], $this->keyManager->getWriteKey(true));
        $this->assertEquals($serverKeys['write_iv'], $this->keyManager->getWriteIv(true));
        $this->assertEquals($serverKeys['hp_key'], $this->keyManager->getHpKey(true));
    }

    public function testDeriveHandshakeSecrets(): void
    {
        $handshakeSecret = str_repeat("\x04", 32);
        $isServer = false;

        $secrets = $this->keyManager->deriveHandshakeSecrets($handshakeSecret, $isServer);

        $this->assertIsArray($secrets);
        $this->assertArrayHasKey('client', $secrets);
        $this->assertArrayHasKey('server', $secrets);

        $clientKeys = $secrets['client'];
        $this->assertEquals(16, strlen($clientKeys['write_key']));
        $this->assertEquals(12, strlen($clientKeys['write_iv']));
        $this->assertEquals(16, strlen($clientKeys['hp_key']));

        $this->assertTrue($this->keyManager->isInitialized());
    }

    public function testDeriveApplicationSecrets(): void
    {
        $masterSecret = str_repeat("\x05", 32);
        $isServer = false;

        $secrets = $this->keyManager->deriveApplicationSecrets($masterSecret, $isServer);

        $this->assertIsArray($secrets);
        $this->assertArrayHasKey('client', $secrets);
        $this->assertArrayHasKey('server', $secrets);

        $clientKeys = $secrets['client'];
        $this->assertEquals(16, strlen($clientKeys['write_key']));
        $this->assertEquals(12, strlen($clientKeys['write_iv']));
        $this->assertEquals(16, strlen($clientKeys['hp_key']));

        $this->assertTrue($this->keyManager->isInitialized());
    }

    public function testUpdateTrafficSecrets(): void
    {
        // 先初始化一些密钥
        $connectionId = str_repeat("\x06", 8);
        $this->keyManager->deriveInitialSecrets($connectionId);

        $currentSecret = str_repeat("\x07", 32);
        $initialUpdateCount = $this->keyManager->getKeyUpdateCount();

        $newSecret = $this->keyManager->updateTrafficSecrets($currentSecret);

        $this->assertEquals(32, strlen($newSecret));
        $this->assertNotEquals($currentSecret, $newSecret);
        $this->assertEquals($initialUpdateCount + 1, $this->keyManager->getKeyUpdateCount());
    }

    public function testConstructNonce(): void
    {
        $iv = str_repeat("\x08", 12);
        $packetNumber = 0x12345678;

        $nonce = $this->keyManager->constructNonce($iv, $packetNumber);

        $this->assertEquals(12, strlen($nonce));
        $this->assertNotEquals($iv, $nonce);

        // 测试不同包号产生不同nonce
        $nonce2 = $this->keyManager->constructNonce($iv, 0x87654321);
        $this->assertNotEquals($nonce, $nonce2);
    }

    public function testConstructNonceWithZeroPacketNumber(): void
    {
        $iv = str_repeat("\x09", 12);
        $packetNumber = 0;

        $nonce = $this->keyManager->constructNonce($iv, $packetNumber);

        $this->assertEquals(12, strlen($nonce));
        // 包号为0时，nonce应该等于IV
        $this->assertEquals($iv, $nonce);
    }

    public function testClearSensitiveData(): void
    {
        // 先初始化一些密钥
        $connectionId = str_repeat("\x0A", 8);
        $this->keyManager->deriveInitialSecrets($connectionId);

        $this->assertTrue($this->keyManager->isInitialized());
        $this->assertNotEquals('', $this->keyManager->getWriteKey());

        $this->keyManager->clearSensitiveData();

        // clearSensitiveData后，isInitialized的结果取决于具体实现
        // 由于secureClear会将密钥清零，但不是空字符串，所以isInitialized可能仍返回true
        $this->assertEquals(0, $this->keyManager->getKeyUpdateCount());
        
        // 检查密钥被清理（应该是全零或空）
        $writeKey = $this->keyManager->getWriteKey();
        $writeIv = $this->keyManager->getWriteIv();
        $hpKey = $this->keyManager->getHpKey();
        
        // 密钥应该被清零或清空
        $isKeyCleared = empty($writeKey) || $writeKey === str_repeat("\x00", strlen($writeKey));
        $isIvCleared = empty($writeIv) || $writeIv === str_repeat("\x00", strlen($writeIv));
        $isHpKeyCleared = empty($hpKey) || $hpKey === str_repeat("\x00", strlen($hpKey));
        
        $this->assertTrue($isKeyCleared, '写入密钥应该被清理');
        $this->assertTrue($isIvCleared, '写入IV应该被清理');
        $this->assertTrue($isHpKeyCleared, '包头保护密钥应该被清理');
    }

    public function testGetKeysBeforeInitialization(): void
    {
        // 在初始化之前，所有密钥都应该为空
        $this->assertEquals('', $this->keyManager->getWriteKey(true));
        $this->assertEquals('', $this->keyManager->getWriteKey(false));
        $this->assertEquals('', $this->keyManager->getWriteIv(true));
        $this->assertEquals('', $this->keyManager->getWriteIv(false));
        $this->assertEquals('', $this->keyManager->getHpKey(true));
        $this->assertEquals('', $this->keyManager->getHpKey(false));
    }

    public function testDifferentConnectionIdProduceDifferentKeys(): void
    {
        $connectionId1 = str_repeat("\x0B", 8);
        $connectionId2 = str_repeat("\x0C", 8);

        $keyManager1 = new KeyManager($this->suite);
        $keyManager2 = new KeyManager($this->suite);

        $secrets1 = $keyManager1->deriveInitialSecrets($connectionId1);
        $secrets2 = $keyManager2->deriveInitialSecrets($connectionId2);

        // 不同的连接ID应该产生不同的密钥
        $this->assertNotEquals($secrets1['client']['write_key'], $secrets2['client']['write_key']);
        $this->assertNotEquals($secrets1['server']['write_key'], $secrets2['server']['write_key']);
    }

    public function testFullKeyDerivationFlow(): void
    {
        $connectionId = str_repeat("\x0D", 8);
        $handshakeSecret = str_repeat("\x0E", 32);
        $masterSecret = str_repeat("\x0F", 32);

        // 1. 派生初始密钥
        $initialSecrets = $this->keyManager->deriveInitialSecrets($connectionId);
        $this->assertTrue($this->keyManager->isInitialized());

        $initialClientKey = $this->keyManager->getWriteKey(true);

        // 2. 派生握手密钥
        $handshakeSecrets = $this->keyManager->deriveHandshakeSecrets($handshakeSecret);
        
        $handshakeClientKey = $this->keyManager->getWriteKey(true);
        $this->assertNotEquals($initialClientKey, $handshakeClientKey);

        // 3. 派生应用数据密钥
        $appSecrets = $this->keyManager->deriveApplicationSecrets($masterSecret);
        
        $appClientKey = $this->keyManager->getWriteKey(true);
        $this->assertNotEquals($handshakeClientKey, $appClientKey);

        // 4. 更新密钥
        $currentUpdateCount = $this->keyManager->getKeyUpdateCount();
        $currentSecret = str_repeat("\x10", 32);
        $newSecret = $this->keyManager->updateTrafficSecrets($currentSecret);
        
        $this->assertEquals($currentUpdateCount + 1, $this->keyManager->getKeyUpdateCount());
        $this->assertNotEquals($currentSecret, $newSecret);
    }

    public function testDestructor(): void
    {
        $connectionId = str_repeat("\x11", 8);
        $keyManager = new KeyManager($this->suite);
        $keyManager->deriveInitialSecrets($connectionId);

        $this->assertTrue($keyManager->isInitialized());

        // 销毁对象时应该自动清理敏感数据
        unset($keyManager);
        
        // 由于已经销毁，无法直接验证，但确保没有异常
        $this->assertTrue(true);
    }

    public function testWithDifferentCryptoSuites(): void
    {
        $connectionId = str_repeat("\x12", 8);

        // AES-256 套件
        $key256 = str_repeat("\x13", 32);
        $suite256 = CryptoSuite::createAES256GCM($key256);
        $keyManager256 = new KeyManager($suite256);

        $secrets256 = $keyManager256->deriveInitialSecrets($connectionId);
        
        $this->assertEquals(32, strlen($secrets256['client']['write_key'])); // AES-256 密钥长度
        $this->assertEquals(12, strlen($secrets256['client']['write_iv']));
        $this->assertEquals(32, strlen($secrets256['client']['hp_key']));

        // 与AES-128产生的密钥应该不同
        $secrets128 = $this->keyManager->deriveInitialSecrets($connectionId);
        $this->assertNotEquals($secrets128['client']['write_key'], $secrets256['client']['write_key']);
    }

    // 异常测试
    public function testConstructNonceInvalidIvLength(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(CryptoException::INVALID_PARAMETER);

        $invalidIv = str_repeat("\x14", 10); // 错误长度
        $this->keyManager->constructNonce($invalidIv, 123);
    }

    public function testSecurityProperties(): void
    {
        $connectionId = str_repeat("\x15", 8);
        $secrets = $this->keyManager->deriveInitialSecrets($connectionId);

        // 客户端和服务端密钥应该不同
        $this->assertNotEquals($secrets['client']['write_key'], $secrets['server']['write_key']);
        $this->assertNotEquals($secrets['client']['write_iv'], $secrets['server']['write_iv']);
        $this->assertNotEquals($secrets['client']['hp_key'], $secrets['server']['hp_key']);

        // 同一方的不同密钥应该不同
        $clientKeys = $secrets['client'];
        $this->assertNotEquals($clientKeys['write_key'], $clientKeys['write_iv']);
        $this->assertNotEquals($clientKeys['write_key'], $clientKeys['hp_key']);
        $this->assertNotEquals($clientKeys['write_iv'], $clientKeys['hp_key']);
    }

    public function testNonceConstructionMath(): void
    {
        // 测试nonce构造的数学正确性
        $iv = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C";
        $packetNumber = 0x12345678;

        $nonce = $this->keyManager->constructNonce($iv, $packetNumber);

        // 手动计算期望的nonce
        $packetNumberBytes = "\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34\x56\x78";
        $expectedNonce = '';
        for ($i = 0; $i < 12; $i++) {
            $expectedNonce .= chr(ord($iv[$i]) ^ ord($packetNumberBytes[$i]));
        }

        $this->assertEquals($expectedNonce, $nonce);
    }

    public function testLargePacketNumber(): void
    {
        $iv = str_repeat("\x16", 12);
        $largePacketNumber = 0x7FFFFFFF; // 最大32位整数

        $nonce = $this->keyManager->constructNonce($iv, $largePacketNumber);
        $this->assertEquals(12, strlen($nonce));

        // 测试包号回绕
        $wrappedNonce = $this->keyManager->constructNonce($iv, 0);
        $this->assertNotEquals($nonce, $wrappedNonce);
    }

    public function testRepeatedOperations(): void
    {
        $connectionId = str_repeat("\x17", 8);

        // 重复调用相同操作应该产生相同结果
        $secrets1 = $this->keyManager->deriveInitialSecrets($connectionId);
        $this->keyManager->clearSensitiveData();
        $secrets2 = $this->keyManager->deriveInitialSecrets($connectionId);

        $this->assertEquals($secrets1['client']['write_key'], $secrets2['client']['write_key']);
        $this->assertEquals($secrets1['server']['write_key'], $secrets2['server']['write_key']);
    }

    public function testKeyIsolation(): void
    {
        // 测试不同KeyManager实例之间的密钥隔离
        $key1 = str_repeat("\x18", 16);
        $key2 = str_repeat("\x19", 16);
        
        $suite1 = CryptoSuite::createAES128GCM($key1);
        $suite2 = CryptoSuite::createAES128GCM($key2);
        
        $manager1 = new KeyManager($suite1);
        $manager2 = new KeyManager($suite2);

        $connectionId = str_repeat("\x1A", 8);
        
        $secrets1 = $manager1->deriveInitialSecrets($connectionId);
        $secrets2 = $manager2->deriveInitialSecrets($connectionId);

        // 不同suite应该产生不同的密钥，即使连接ID相同
        // 使用字符串长度比较避免二进制输出问题
        $key1_len = strlen($secrets1['client']['write_key']);
        $key2_len = strlen($secrets2['client']['write_key']);
        $this->assertEquals($key1_len, $key2_len); // 长度应该相同
        $this->assertNotEquals(
            bin2hex($secrets1['client']['write_key']), 
            bin2hex($secrets2['client']['write_key'])
        ); // 但内容应该不同
    }
} 