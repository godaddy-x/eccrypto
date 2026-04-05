package ecc

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	// X25519 密钥长度（RFC 7748 / crypto/ecdh）
	x25519PubKeyLen  = 32
	x25519PrivKeyLen = 32

	// 与 P256 封装（protocolVersion 0x01 + 65 字节公钥）区分，避免误解析
	protocolVersionX25519 = 0x02

	hkdfInfoEncX25519 = "ecdh-x25519-aes-gcm-encryption:" // 与 P256 的 hkdfInfoEnc 域分离
)

var x25519Curve = ecdh.X25519()

// CreateX25519 生成新的 X25519 密钥对，用于 ECDH。
func CreateX25519() (*ecdh.PrivateKey, error) {
	return x25519Curve.GenerateKey(rand.Reader)
}

// LoadX25519PrivateKey 从 32 字节标量加载 X25519 私钥。
func LoadX25519PrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("private key data is empty")
	}
	key, err := x25519Curve.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key bytes: %w", err)
	}
	return key, nil
}

// LoadX25519PrivateKeyFromHex 从十六进制字符串加载 X25519 私钥。
func LoadX25519PrivateKeyFromHex(hexStr string) (*ecdh.PrivateKey, error) {
	if hexStr == "" {
		return nil, fmt.Errorf("private key hex string is empty")
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadX25519PrivateKey(b)
}

// LoadX25519PrivateKeyFromBase64 从 Base64 字符串加载 X25519 私钥。
func LoadX25519PrivateKeyFromBase64(b64Str string) (*ecdh.PrivateKey, error) {
	if b64Str == "" {
		return nil, fmt.Errorf("private key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadX25519PrivateKey(b)
}

// LoadX25519PublicKey 从 32 字节加载 X25519 公钥（Montgomery u 坐标编码）。
func LoadX25519PublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("public key data is empty")
	}
	if len(b) != x25519PubKeyLen {
		return nil, fmt.Errorf("X25519 public key must be %d bytes", x25519PubKeyLen)
	}
	key, err := x25519Curve.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key bytes: %w", err)
	}
	return key, nil
}

// LoadX25519PublicKeyFromHex 从十六进制字符串加载 X25519 公钥。
func LoadX25519PublicKeyFromHex(hexStr string) (*ecdh.PublicKey, error) {
	if hexStr == "" {
		return nil, fmt.Errorf("public key hex string is empty")
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadX25519PublicKey(b)
}

// LoadX25519PublicKeyFromBase64 从 Base64 字符串加载 X25519 公钥。
func LoadX25519PublicKeyFromBase64(b64Str string) (*ecdh.PublicKey, error) {
	if b64Str == "" {
		return nil, fmt.Errorf("public key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadX25519PublicKey(b)
}

// GetX25519PublicKeyBytes 返回 X25519 公钥的 32 字节编码。
func GetX25519PublicKeyBytes(pub *ecdh.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	return pub.Bytes()
}

// GetX25519PrivateKeyBytes 返回 X25519 私钥的 32 字节编码。
func GetX25519PrivateKeyBytes(prk *ecdh.PrivateKey) []byte {
	if prk == nil {
		return nil
	}
	return prk.Bytes()
}

// GenSharedKeyX25519 计算 X25519 ECDH 共享秘密（与对端公钥长度相同，通常为 32 字节）。
func GenSharedKeyX25519(ownerPrk *ecdh.PrivateKey, otherPub *ecdh.PublicKey) ([]byte, error) {
	if ownerPrk == nil || otherPub == nil {
		return nil, fmt.Errorf("private key and public key cannot be nil")
	}
	sharedKey, err := ownerPrk.ECDH(otherPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 key exchange failed: %w", err)
	}
	return sharedKey, nil
}

func hkdfKeyX25519(sharedKey []byte) ([]byte, error) {
	if len(sharedKey) == 0 {
		return nil, fmt.Errorf("sharedKey cannot be empty")
	}
	result, err := hkdf.Key(sha256.New, sharedKey, nil, hkdfInfoEncX25519, keyLen)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// EncryptX25519 使用 X25519 ECDH + HKDF-SHA256 + AES-GCM 加密。
// 输出格式：[版本 0x02(1)] + [临时公钥 32] + [Nonce(12) + 密文 + Tag(16)]。
func EncryptX25519(inputPrk *ecdh.PrivateKey, publicTo []byte, message, additionalData []byte) ([]byte, error) {
	if len(publicTo) != x25519PubKeyLen {
		return nil, fmt.Errorf("public key must be %d bytes", x25519PubKeyLen)
	}
	if len(additionalData) > 1024*1024 {
		return nil, fmt.Errorf("additionalData too large (max 1MB)")
	}

	pubTo, err := LoadX25519PublicKey(publicTo)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	ephemPrk := inputPrk
	if ephemPrk == nil {
		ephemPrk, err = CreateX25519()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
		}
	}
	defer SecureZeroBytes(GetX25519PrivateKeyBytes(ephemPrk))

	ephemPub := ephemPrk.PublicKey()
	ephemPubBytes := GetX25519PublicKeyBytes(ephemPub)

	sharedKey, err := GenSharedKeyX25519(ephemPrk, pubTo)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(sharedKey)

	aesKey, err := hkdfKeyX25519(sharedKey)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(aesKey)

	aad := constructSecureAAD(additionalData, ephemPubBytes, protocolVersionX25519)

	gcmData, err := aesGCMEncrypt(message, aesKey, aad)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	result := make([]byte, 1+len(ephemPubBytes)+len(gcmData))
	result[0] = protocolVersionX25519
	copy(result[1:], ephemPubBytes)
	copy(result[1+len(ephemPubBytes):], gcmData)

	return result, nil
}

// DecryptX25519 解密 EncryptX25519 产出；要求版本字节为 0x02。
func DecryptX25519(privateKey *ecdh.PrivateKey, msg, additionalData, dst []byte) ([]byte, error) {
	minBody := 1 + x25519PubKeyLen + nonceLen + 16 // version + pub + min GCM
	if len(msg) < minBody {
		return nil, fmt.Errorf("message too short")
	}
	version := msg[0]
	if version != protocolVersionX25519 {
		return nil, fmt.Errorf("unsupported protocol version: %d", version)
	}

	ephemPubBytes := msg[1 : 1+x25519PubKeyLen]
	ciphertextWithTag := msg[1+x25519PubKeyLen:]

	ephemPub, err := LoadX25519PublicKey(ephemPubBytes)
	if err != nil {
		return nil, err
	}

	sharedKey, err := GenSharedKeyX25519(privateKey, ephemPub)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(sharedKey)

	aesKey, err := hkdfKeyX25519(sharedKey)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(aesKey)

	aad := constructSecureAAD(additionalData, ephemPubBytes, version)

	expectedPlaintextLen := len(ciphertextWithTag) - 16
	if dst != nil {
		if cap(dst) < expectedPlaintextLen {
			return nil, fmt.Errorf(
				"dst capacity (%d) insufficient for plaintext (expected %d)",
				cap(dst), expectedPlaintextLen,
			)
		}
		return AesGCMDecrypt(ciphertextWithTag, aesKey, aad, dst)
	}
	return AesGCMDecrypt(ciphertextWithTag, aesKey, aad, nil)
}

// X25519PublicKeyToHex 将 X25519 公钥转为十六进制字符串。
func X25519PublicKeyToHex(pub *ecdh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return hex.EncodeToString(pub.Bytes())
}

// X25519PrivateKeyToHex 将 X25519 私钥转为十六进制字符串。
func X25519PrivateKeyToHex(prk *ecdh.PrivateKey) string {
	if prk == nil {
		return ""
	}
	return hex.EncodeToString(prk.Bytes())
}

// X25519PublicKeyToBase64 将 X25519 公钥转为 Base64 字符串。
func X25519PublicKeyToBase64(pub *ecdh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}

// X25519PrivateKeyToBase64 将 X25519 私钥转为 Base64 字符串。
func X25519PrivateKeyToBase64(prk *ecdh.PrivateKey) string {
	if prk == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(prk.Bytes())
}

// GetX25519ProtocolVersion 返回 X25519 封装使用的版本字节（0x02）。
func GetX25519ProtocolVersion() byte {
	return protocolVersionX25519
}

// ValidateX25519PublicKey 校验 32 字节 X25519 公钥是否可被标准库接受。
func ValidateX25519PublicKey(publicKey []byte) error {
	_, err := LoadX25519PublicKey(publicKey)
	return err
}
