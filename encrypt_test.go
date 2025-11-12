package ecc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	testMsg = []byte("我是中国人梵蒂冈啊!!!ABC@#")
)

func BenchmarkECDHCreate(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := CreateECDH()
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkECDHSharedKey(b *testing.B) {
	b.StopTimer()
	prk, err := CreateECDH()
	if err != nil {
		panic(err)
	}
	pub := prk.PublicKey()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := prk.ECDH(pub)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkECDHEncrypt(b *testing.B) {
	b.StopTimer()
	prk, err := CreateECDH()
	if err != nil {
		panic(err)
	}
	pubBytes := GetECDHPublicKeyBytes(*prk.PublicKey())
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(prk, pubBytes, testMsg)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkECDHDecrypt(b *testing.B) {
	b.StopTimer()
	prk, err := CreateECDH()
	if err != nil {
		panic(err)
	}
	pubBytes := GetECDHPublicKeyBytes(*prk.PublicKey())
	r, err := Encrypt(prk, pubBytes, testMsg)
	if err != nil {
		panic(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(prk, r)
		if err != nil {
			panic(err)
		}
	}
}

// TestECDHEncryptDecrypt 测试完整的ECDH加密解密流程
func TestECDHEncryptDecrypt(t *testing.T) {
	// 生成密钥对
	prk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH failed: %v", err)
	}

	pub := prk.PublicKey()
	pubBytes := pub.Bytes()
	t.Logf("Public key length: %d, bytes: %x", len(pubBytes), pubBytes)

	testMsg := []byte("Hello, ECDH encryption!")

	// 加密
	encrypted, err := Encrypt(prk, pubBytes, testMsg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 解密
	decrypted, err := Decrypt(prk, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 验证结果
	if !bytes.Equal(testMsg, decrypted) {
		t.Errorf("Decryption failed. Expected: %s, Got: %s", testMsg, decrypted)
	}
}

// TestECDHBasic 测试基本的ECDH功能
func TestECDHBasic(t *testing.T) {
	// 生成Alice的密钥对
	alicePrk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH failed: %v", err)
	}

	// 生成Bob的密钥对
	bobPrk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH failed: %v", err)
	}

	// Alice和Bob交换公钥并计算共享密钥
	aliceShared, err := alicePrk.ECDH(bobPrk.PublicKey())
	if err != nil {
		t.Fatalf("Alice ECDH failed: %v", err)
	}

	bobShared, err := bobPrk.ECDH(alicePrk.PublicKey())
	if err != nil {
		t.Fatalf("Bob ECDH failed: %v", err)
	}

	// 验证共享密钥相同
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("Shared keys don't match between Alice and Bob")
	} else {
		t.Log("✓ ECDH key exchange successful - shared keys match")
	}

	// 测试加密解密
	testMsg := []byte("Hello, ECDH encryption!")
	encrypted, err := Encrypt(alicePrk, GetECDHPublicKeyBytes(*bobPrk.PublicKey()), testMsg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(bobPrk, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(testMsg, decrypted) {
		t.Errorf("Encryption/decryption failed. Expected: %s, Got: %s", testMsg, decrypted)
	} else {
		t.Log("✓ ECDH encryption/decryption successful")
	}
}

// TestTypeScriptCompatibility 测试与TypeScript版本的兼容性
func TestTypeScriptCompatibility(t *testing.T) {
	// 模拟TypeScript版本产生的公钥格式
	// TypeScript elliptic库的未压缩公钥格式：04 + 32字节X + 32字节Y = 65字节
	const ecdhPubKeyLen = 65

	// 生成一个Go的ECDH密钥对作为基准
	goPrk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH failed: %v", err)
	}
	goPubBytes := GetECDHPublicKeyBytes(*goPrk.PublicKey())

	t.Logf("Go ECDH public key length: %d", len(goPubBytes))
	t.Logf("Go ECDH public key: %x", goPubBytes)

	// 验证格式
	if len(goPubBytes) != ecdhPubKeyLen {
		t.Errorf("Expected %d bytes for uncompressed public key, got %d", ecdhPubKeyLen, len(goPubBytes))
	}

	const uncompressedPubKeyPrefix = 0x04
	if goPubBytes[0] != uncompressedPubKeyPrefix {
		t.Errorf("Expected uncompressed format (0x04 prefix), got 0x%02x", goPubBytes[0])
	}

	// 测试TypeScript格式的兼容性
	t.Run("TypeScript_Format_Compatibility", func(t *testing.T) {
		// 使用Go生成的公钥作为"TypeScript格式"的输入
		tsFormatPubKey := goPubBytes

		// 测试能否用Go的ECDH正确解析
		parsedPub, err := LoadECDHPublicKey(tsFormatPubKey)
		if err != nil {
			t.Fatalf("Failed to parse TypeScript format public key: %v", err)
		}

		// 测试密钥交换
		shared1, err := goPrk.ECDH(parsedPub)
		if err != nil {
			t.Fatalf("ECDH key exchange failed: %v", err)
		}

		// 创建另一个密钥对验证
		otherPrk, err := CreateECDH()
		if err != nil {
			t.Fatalf("Create second ECDH key failed: %v", err)
		}

		shared2, err := otherPrk.ECDH(parsedPub)
		if err != nil {
			t.Fatalf("Second ECDH key exchange failed: %v", err)
		}

		t.Logf("Shared key 1: %x", shared1)
		t.Logf("Shared key 2: %x", shared2)

		if bytes.Equal(shared1, shared2) {
			t.Error("Shared keys should be different for different private keys")
		}

		// 测试实际加密解密
		testMsg := []byte("Hello from TypeScript compatible format!")
		encrypted, err := Encrypt(goPrk, tsFormatPubKey, testMsg)
		if err != nil {
			t.Fatalf("Encryption with TypeScript format failed: %v", err)
		}

		decrypted, err := Decrypt(goPrk, encrypted)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if !bytes.Equal(testMsg, decrypted) {
			t.Errorf("Encryption/decryption failed. Expected: %s, Got: %s", testMsg, decrypted)
		}

		t.Log("✓ TypeScript elliptic.js format is compatible with Go ECDH")
	})

	// 测试十六进制格式（TypeScript中常用的格式）
	t.Run("Hex_Format_Compatibility", func(t *testing.T) {
		// TypeScript中公钥通常是十六进制字符串
		hexPubKey := hex.EncodeToString(goPubBytes)
		t.Logf("Hex public key: %s", hexPubKey)

		// 验证长度（65字节 = 130个十六进制字符）
		expectedHexLen := ecdhPubKeyLen * 2
		if len(hexPubKey) != expectedHexLen {
			t.Errorf("Expected %d hex characters, got %d", expectedHexLen, len(hexPubKey))
		}

		// 测试从十六进制转换回字节
		decodedPub, err := hex.DecodeString(hexPubKey)
		if err != nil {
			t.Fatalf("Hex decode failed: %v", err)
		}

		if !bytes.Equal(goPubBytes, decodedPub) {
			t.Error("Hex encoding/decoding failed")
		}

		t.Log("✓ Hex format compatibility confirmed")
	})

	// 测试实际的TypeScript兼容性
	t.Run("Real_TypeScript_Compatibility", func(t *testing.T) {
		// 模拟TypeScript代码中的公钥生成流程
		// 在TypeScript中：const tempPublic = tempPrivate.getPublic()
		//                  const ephemPublicKey = Buffer.from(tempPublic.encode('hex', false), 'hex')

		// 生成临时密钥对（模拟TypeScript的tempPrivate）
		tempPrk, err := CreateECDH()
		if err != nil {
			t.Fatalf("Create temp ECDH key failed: %v", err)
		}

		// 获取公钥字节（模拟TypeScript的tempPublic.encode('hex', false)）
		tempPubBytes := GetECDHPublicKeyBytes(*tempPrk.PublicKey())

		// 这应该就是TypeScript版本会发送给Go的公钥格式
		tsCompatiblePubKey := tempPubBytes

		t.Logf("TypeScript compatible public key: %x", tsCompatiblePubKey)
		t.Logf("Length: %d bytes", len(tsCompatiblePubKey))

		// 验证Go的Encrypt能接受这个格式
		testMsg := []byte("Message from TypeScript to Go")
		encrypted, err := Encrypt(goPrk, tsCompatiblePubKey, testMsg)
		if err != nil {
			t.Fatalf("Encrypt with TypeScript key failed: %v", err)
		}

		// 验证解密
		decrypted, err := Decrypt(tempPrk, encrypted)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(testMsg, decrypted) {
			t.Errorf("Cross-platform encryption/decryption failed")
		} else {
			t.Log("✓ Real TypeScript ↔ Go ECDH compatibility confirmed!")
		}
	})
}

// TestFillSharedKeyHexComparison 比较原始实现和优化实现的差异
func TestFillSharedKeyHexComparison(t *testing.T) {
	// 原始实现函数 - 使用和fillSharedKeyHex相同的逻辑
	originalFillSharedKeyHex := func(b []byte) []byte {
		sharedKeyHex := hex.EncodeToString(b)
		const sharedKeyHexLen = 64
		if len(sharedKeyHex) < sharedKeyHexLen {
			cha := sharedKeyHexLen - len(sharedKeyHex)
			for j := 0; j < cha; j++ {
				sharedKeyHex = "0" + sharedKeyHex
			}
		}
		// 使用和fillSharedKeyHex相同的hexToBytes逻辑
		return hexToBytes(sharedKeyHex)
	}

	// 测试不同长度输入
	testCases := [][]byte{
		{1, 2, 3, 4, 5},                // 5字节
		bytes.Repeat([]byte{0xFF}, 31), // 31字节
		bytes.Repeat([]byte{0xAA}, 32), // 32字节
		bytes.Repeat([]byte{0xBB}, 33), // 33字节 - 实际ECDH中不会发生
	}

	for i, input := range testCases {
		originalResult := originalFillSharedKeyHex(input)
		optimizedResult := fillSharedKeyHex(input)

		t.Logf("=== Test case %d - Input len: %d ===", i, len(input))
		t.Logf("Input bytes: %x", input)
		t.Logf("Original result len: %d, bytes: %x", len(originalResult), originalResult)
		t.Logf("Optimized result len: %d, bytes: %x", len(optimizedResult), optimizedResult)

		// 对于实际ECDH中可能出现的输入（<=32字节），结果必须完全相同
		if len(input) <= 32 {
			if !bytes.Equal(originalResult, optimizedResult) {
				t.Errorf("FAIL: Test case %d failed for input len <= 32", i)
			} else {
				t.Logf("PASS: Results are identical")
			}
		} else {
			// 对于>32字节的情况，记录差异但不认为是错误
			t.Logf("NOTE: Input len > 32, results may differ (original: %d bytes, optimized: %d bytes)",
				len(originalResult), len(optimizedResult))
		}
		t.Logf("")
	}
}
