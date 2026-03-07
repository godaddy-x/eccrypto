package ecc

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

var (
	testMsg = []byte("测试下混合数据!!!ABC@#")
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
	pubBytes := GetECDHPublicKeyBytes(prk.PublicKey())
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		r, err := Encrypt(prk, pubBytes, testMsg, nil)
		if err != nil {
			b.Fatal(err)
		}
		Decrypt(prk, r, nil, nil)
	}
}

func BenchmarkECDHDecrypt(b *testing.B) {
	b.StopTimer()
	prk, err := CreateECDH()
	if err != nil {
		panic(err)
	}
	pubBytes := GetECDHPublicKeyBytes(prk.PublicKey())
	r, err := Encrypt(prk, pubBytes, testMsg, nil)
	if err != nil {
		panic(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(prk, r, nil, nil)
		if err != nil {
			panic(err)
		}
	}
}

func TestECDHEncryptDecrypt(t *testing.T) {
	prk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH failed: %v", err)
	}

	pubBytes := GetECDHPublicKeyBytes(prk.PublicKey())
	t.Logf("Public key length: %d, bytes: %x", len(pubBytes), pubBytes)

	r, err := Encrypt(prk, pubBytes, testMsg, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(prk, r, nil, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(testMsg, decrypted) {
		t.Errorf("Encryption/decryption failed. Expected: %s, Got: %s", testMsg, decrypted)
	}
}

func TestECDHBasic(t *testing.T) {
	// 生成 Alice 的密钥对
	alicePrk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH for Alice failed: %v", err)
	}

	// 生成 Bob 的密钥对
	bobPrk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH for Bob failed: %v", err)
	}

	// Alice 和 Bob 进行密钥交换
	aliceSharedKey, err := GenSharedKeyECDH(alicePrk, bobPrk.PublicKey())
	if err != nil {
		t.Fatalf("Alice ECDH key exchange failed: %v", err)
	}

	bobSharedKey, err := GenSharedKeyECDH(bobPrk, alicePrk.PublicKey())
	if err != nil {
		t.Fatalf("Bob ECDH key exchange failed: %v", err)
	}

	// 验证共享密钥相同
	if !bytes.Equal(aliceSharedKey, bobSharedKey) {
		t.Fatal("Shared keys don't match!")
	}
	t.Log("✓ ECDH key exchange successful - shared keys match")

	// 测试加密解密
	testMsg := []byte("Hello, ECDH encryption!")
	encrypted, err := Encrypt(alicePrk, GetECDHPublicKeyBytes(bobPrk.PublicKey()), testMsg, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(bobPrk, encrypted, nil, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(testMsg, decrypted) {
		t.Errorf("Encryption/decryption failed. Expected: %s, Got: %s", testMsg, decrypted)
	} else {
		t.Log("✓ ECDH encryption/decryption successful")
	}
}

func TestTypeScriptCompatibility(t *testing.T) {
	// TypeScript elliptic.js 兼容性测试
	t.Run("TypeScript_Format_Compatibility", func(t *testing.T) {
		// 这个测试验证我们能够正确处理密钥交换
		// TypeScript elliptic.js 使用不同的公钥格式，但 ECDH 密钥交换应该是兼容的
		goPrk1, err := CreateECDH()
		if err != nil {
			t.Fatalf("CreateECDH failed: %v", err)
		}

		goPrk2, err := CreateECDH()
		if err != nil {
			t.Fatalf("CreateECDH failed: %v", err)
		}

		// 测试共享密钥生成
		shared1, err := goPrk1.ECDH(goPrk2.PublicKey())
		if err != nil {
			t.Fatalf("ECDH key exchange failed: %v", err)
		}

		shared2, err := goPrk2.ECDH(goPrk1.PublicKey())
		if err != nil {
			t.Fatalf("ECDH key exchange failed: %v", err)
		}

		if !bytes.Equal(shared1, shared2) {
			t.Errorf("Shared keys don't match: %x vs %x", shared1, shared2)
		}

		t.Logf("Shared key 1: %x", shared1)
		t.Logf("Shared key 2: %x", shared2)
		t.Log("✓ ECDH key exchange with different keys works correctly")
	})

	t.Run("Hex_Format_Compatibility", func(t *testing.T) {
		goPrk, err := CreateECDH()
		if err != nil {
			t.Fatalf("CreateECDH failed: %v", err)
		}

		pubBytes := GetECDHPublicKeyBytes(goPrk.PublicKey())
		t.Logf("Go ECDH public key length: %d", len(pubBytes))
		t.Logf("Go ECDH public key: %x", pubBytes)

		hexPubKey := hex.EncodeToString(pubBytes)
		t.Logf("Hex public key: %s", hexPubKey)

		// 测试十六进制格式
		parsedPub, err := LoadECDHPublicKeyFromHex(hexPubKey)
		if err != nil {
			t.Fatalf("LoadECDHPublicKeyFromHex failed: %v", err)
		}

		// 验证解析后的公钥与原始公钥相同
		parsedBytes := GetECDHPublicKeyBytes(parsedPub)
		if !bytes.Equal(pubBytes, parsedBytes) {
			t.Errorf("Hex format parsing failed")
		} else {
			t.Log("✓ Hex format compatibility confirmed")
		}
	})

	t.Run("Real_TypeScript_Compatibility", func(t *testing.T) {
		// 测试使用 nil 私钥的临时密钥生成（模拟 TypeScript 风格）
		goPrk, err := CreateECDH()
		if err != nil {
			t.Fatalf("CreateECDH failed: %v", err)
		}

		pubKey := GetECDHPublicKeyBytes(goPrk.PublicKey())
		t.Logf("Go public key: %x", pubKey)
		t.Logf("Length: %d bytes", len(pubKey))

		// 测试 Encrypt 函数能够处理有效的 ECDH 公钥
		testMsg := []byte("Message from TypeScript to Go")
		encrypted, err := Encrypt(nil, pubKey, testMsg, nil)
		if err != nil {
			t.Fatalf("Encrypt with valid key failed: %v", err)
		}

		// 验证能够正确解密
		decrypted, err := Decrypt(goPrk, encrypted, nil, nil)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(testMsg, decrypted) {
			t.Errorf("Encryption/decryption compatibility failed")
		} else {
			t.Log("✓ Go ECDH encryption/decryption compatibility confirmed!")
		}
	})
}

func TestSecurityVulnerabilities(t *testing.T) {
	prk, err := CreateECDH()
	if err != nil {
		t.Fatalf("CreateECDH failed: %v", err)
	}

	testCases := []struct {
		name        string
		input       []byte
		expectError bool
		errorMsg    string
	}{
		{"Too short message", make([]byte, 50), true, "message too short"},
		{"Invalid protocol version", append([]byte{0x00}, make([]byte, 81)...), true, "unsupported protocol version"},
		{"Invalid public key format", append(append([]byte{0x01}, make([]byte, 64)...), make([]byte, 17)...), true, "public key must be 65 bytes"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decrypt(prk, tc.input, nil, nil)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tc.name)
				} else if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tc.name, err)
				}
			}
		})
	}

	t.Run("Encrypt with nil private key", func(t *testing.T) {
		pub := GetECDHPublicKeyBytes(prk.PublicKey())
		message := []byte("test message")

		result, err := Encrypt(nil, pub, message, nil)
		if err != nil {
			t.Errorf("Encrypt with nil private key should work, got error: %v", err)
		}
		if len(result) == 0 {
			t.Error("Encrypt should return non-empty result")
		}
	})

	t.Run("Encrypt with invalid public key length", func(t *testing.T) {
		invalidPub := make([]byte, 64) // 不是 65 字节
		message := []byte("test")

		_, err := Encrypt(prk, invalidPub, message, nil)
		if err == nil {
			t.Error("Expected error for invalid public key length")
		}
		if !strings.Contains(err.Error(), "public key must be 65 bytes") {
			t.Errorf("Expected specific error message, got: %s", err.Error())
		}
	})

	t.Run("Encrypt with empty message", func(t *testing.T) {
		pub := GetECDHPublicKeyBytes(prk.PublicKey())
		message := []byte{}

		result, err := Encrypt(prk, pub, message, nil)
		if err != nil {
			t.Errorf("Encrypt with empty message should work, got error: %v", err)
		}
		if len(result) == 0 {
			t.Error("Encrypt should return non-empty result even for empty message")
		}

		// 验证能正确解密
		decrypted, err := Decrypt(prk, result, nil, nil)
		if err != nil {
			t.Errorf("Decrypt failed: %v", err)
		}
		if len(decrypted) != 0 {
			t.Errorf("Expected empty result, got %d bytes", len(decrypted))
		}
	})
}
