package ecc

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// TestECDSASigning 测试 ECDSA 签名和验签功能
func TestECDSASigning(t *testing.T) {
	// 生成密钥对
	privateKey, err := CreateECDSA()
	if err != nil {
		t.Fatalf("CreateECDSA failed: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// 测试消息
	testMessages := [][]byte{
		[]byte("Hello, ECDSA!"),
		[]byte("This is a test message for digital signature."),
		[]byte("A"), // 单字符
		bytes.Repeat([]byte("long message"), 100), // 长消息
	}

	for i, message := range testMessages {
		t.Run(fmt.Sprintf("Message_%d", i), func(t *testing.T) {
			// 签名
			signature, err := SignECDSA(privateKey, message)
			if err != nil {
				t.Fatalf("SignECDSA failed: %v", err)
			}

			if len(signature) == 0 {
				t.Error("Signature should not be empty")
			}

			// 验签 - 正确的公钥
			err = VerifyECDSA(publicKey, message, signature)
			if err != nil {
				t.Fatalf("VerifyECDSA failed with correct key: %v", err)
			}

			// 验签 - 错误的消息
			wrongMessage := append(message, []byte("tampered")...)
			err = VerifyECDSA(publicKey, wrongMessage, signature)
			if err == nil {
				t.Error("VerifyECDSA should fail with wrong message")
			}

			// 验签 - 错误的签名
			wrongSignature := make([]byte, len(signature))
			copy(wrongSignature, signature)
			if len(wrongSignature) > 0 {
				wrongSignature[0] ^= 0xFF // 翻转第一个字节
			}
			err = VerifyECDSA(publicKey, message, wrongSignature)
			if err == nil {
				t.Error("VerifyECDSA should fail with wrong signature")
			}
		})
	}

	// 测试 nil 私钥
	_, err = SignECDSA(nil, []byte("test"))
	if err == nil {
		t.Error("SignECDSA should fail with nil private key")
	}

	// 测试 nil 公钥
	err = VerifyECDSA(nil, []byte("test"), []byte("dummy"))
	if err == nil {
		t.Error("VerifyECDSA should fail with nil public key")
	}
}

// TestECDSAKeySerialization 测试 ECDSA 密钥序列化
func TestECDSAKeySerialization(t *testing.T) {
	// 生成原始密钥
	originalPrivate, err := CreateECDSA()
	if err != nil {
		t.Fatalf("CreateECDSA failed: %v", err)
	}

	// 序列化私钥
	privateBytes, err := GetECDSAPrivateKeyBytes(originalPrivate)
	if err != nil {
		t.Fatalf("GetECDSAPrivateKeyBytes failed: %v", err)
	}
	publicBytes, err := GetECDSAPublicKeyBytes(&originalPrivate.PublicKey)
	if err != nil {
		t.Fatalf("GetECDSAPublicKeyBytes failed: %v", err)
	}

	// 验证序列化长度
	if len(publicBytes) != 65 {
		t.Errorf("ECDSA public key should be 65 bytes, got %d", len(publicBytes))
	}
	if len(privateBytes) == 0 {
		t.Error("ECDSA private key should not be empty")
	}

	// 反序列化私钥
	loadedPrivate, err := LoadECDSAPrivateKey(privateBytes)
	if err != nil {
		t.Fatalf("LoadECDSAPrivateKey failed: %v", err)
	}

	// 反序列化公钥
	loadedPublic, err := LoadECDSAPublicKey(publicBytes)
	if err != nil {
		t.Fatalf("LoadECDSAPublicKey failed: %v", err)
	}

	// 验证私钥功能
	testMessage := []byte("test message for key serialization")

	// 使用原始私钥签名
	signature, err := SignECDSA(originalPrivate, testMessage)
	if err != nil {
		t.Fatalf("SignECDSA with original key failed: %v", err)
	}

	// 使用加载的公钥验签
	err = VerifyECDSA(loadedPublic, testMessage, signature)
	if err != nil {
		t.Fatalf("VerifyECDSA with loaded public key failed: %v", err)
	}

	// 使用加载的私钥签名
	signature2, err := SignECDSA(loadedPrivate, testMessage)
	if err != nil {
		t.Fatalf("SignECDSA with loaded private key failed: %v", err)
	}

	// 使用原始公钥验签
	err = VerifyECDSA(&originalPrivate.PublicKey, testMessage, signature2)
	if err != nil {
		t.Fatalf("VerifyECDSA with original public key failed: %v", err)
	}

	// 测试十六进制序列化
	privateHex := hex.EncodeToString(privateBytes)
	publicHex := hex.EncodeToString(publicBytes)

	loadedPrivateHex, err := LoadECDSAPrivateKeyFromHex(privateHex)
	if err != nil {
		t.Fatalf("LoadECDSAPrivateKeyFromHex failed: %v", err)
	}

	loadedPublicHex, err := LoadECDSAPublicKeyFromHex(publicHex)
	if err != nil {
		t.Fatalf("LoadECDSAPublicKeyFromHex failed: %v", err)
	}

	// 验证十六进制加载的密钥
	err = VerifyECDSA(loadedPublicHex, testMessage, signature)
	if err != nil {
		t.Fatalf("VerifyECDSA with hex loaded public key failed: %v", err)
	}

	// 使用十六进制加载的私钥签名
	signature3, err := SignECDSA(loadedPrivateHex, testMessage)
	if err != nil {
		t.Fatalf("SignECDSA with hex loaded private key failed: %v", err)
	}

	err = VerifyECDSA(&originalPrivate.PublicKey, testMessage, signature3)
	if err != nil {
		t.Fatalf("VerifyECDSA with original public key and hex private key signature failed: %v", err)
	}

	// 测试 Base64 序列化
	privateBase64 := base64.StdEncoding.EncodeToString(privateBytes)
	publicBase64 := base64.StdEncoding.EncodeToString(publicBytes)

	loadedPrivateB64, err := LoadECDSAPrivateKeyFromBase64(privateBase64)
	if err != nil {
		t.Fatalf("LoadECDSAPrivateKeyFromBase64 failed: %v", err)
	}

	loadedPublicB64, err := LoadECDSAPublicKeyFromBase64(publicBase64)
	if err != nil {
		t.Fatalf("LoadECDSAPublicKeyFromBase64 failed: %v", err)
	}

	// 验证 Base64 加载的密钥
	err = VerifyECDSA(loadedPublicB64, testMessage, signature)
	if err != nil {
		t.Fatalf("VerifyECDSA with base64 loaded public key failed: %v", err)
	}

	// 使用 Base64 加载的私钥签名
	signature4, err := SignECDSA(loadedPrivateB64, testMessage)
	if err != nil {
		t.Fatalf("SignECDSA with base64 loaded private key failed: %v", err)
	}

	err = VerifyECDSA(&originalPrivate.PublicKey, testMessage, signature4)
	if err != nil {
		t.Fatalf("VerifyECDSA with original public key and base64 private key signature failed: %v", err)
	}
}

func BenchmarkECDSASign(b *testing.B) {
	prk, err := CreateECDSA()
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for ECDSA signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignECDSA(prk, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDSAVerify(b *testing.B) {
	prk, err := CreateECDSA()
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for ECDSA verification")
	signature, err := SignECDSA(prk, message)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := VerifyECDSA(&prk.PublicKey, message, signature)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestGenSharedKeyECDSA(t *testing.T) {
	alicePrk, err := CreateECDSA()
	if err != nil {
		t.Fatalf("CreateECDSA for Alice failed: %v", err)
	}
	bobPrk, err := CreateECDSA()
	if err != nil {
		t.Fatalf("CreateECDSA for Bob failed: %v", err)
	}

	aliceShared, err := GenSharedKeyECDSA(alicePrk, &bobPrk.PublicKey)
	if err != nil {
		t.Fatalf("Alice shared key generation failed: %v", err)
	}
	bobShared, err := GenSharedKeyECDSA(bobPrk, &alicePrk.PublicKey)
	if err != nil {
		t.Fatalf("Bob shared key generation failed: %v", err)
	}

	if len(aliceShared) != ecdsaPrivKeyLen || len(bobShared) != ecdsaPrivKeyLen {
		t.Fatalf("shared key length mismatch, expected %d bytes", ecdsaPrivKeyLen)
	}
	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatalf("shared keys mismatch:\nAlice: %x\nBob:   %x", aliceShared, bobShared)
	}
	if bytes.Equal(aliceShared, make([]byte, len(aliceShared))) {
		t.Fatalf("shared key should not be all zeros")
	}

	// 错误分支：nil 输入
	if _, err := GenSharedKeyECDSA(nil, &bobPrk.PublicKey); err == nil {
		t.Error("expected error when owner private key is nil")
	}
	if _, err := GenSharedKeyECDSA(alicePrk, nil); err == nil {
		t.Error("expected error when other public key is nil")
	}

	// 错误分支：伪造公钥（无穷远点）
	invalidPub := &ecdsa.PublicKey{
		Curve: ecdsaCurve,
		X:     big.NewInt(0),
		Y:     big.NewInt(0),
	}
	if _, err := GenSharedKeyECDSA(alicePrk, invalidPub); err == nil {
		t.Error("expected error when public key is point at infinity")
	}
}
