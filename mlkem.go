package ecc

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	mlkem1024PubKeyLen       = mlkem.EncapsulationKeySize1024
	mlkem1024CtLen           = mlkem.CiphertextSize1024
	mlkem1024DecapSeedLen    = mlkem.SeedSize
	mlkem1024SharedKeyLen    = mlkem.SharedKeySize
	protocolVersionMLKEM1024 = 0x04

	hkdfInfoEncMLKEM1024 = "hkdf-mlkem1024-aes-gcm-encryption:"
)

// CreateMLKEM1024 生成 ML-KEM-1024 解封装（私）密钥对。
func CreateMLKEM1024() (*mlkem.DecapsulationKey1024, error) {
	return mlkem.GenerateKey1024()
}

// LoadMLKEM1024DecapsulationKey 从 64 字节种子（d‖z）加载解封装私钥。
func LoadMLKEM1024DecapsulationKey(seed []byte) (*mlkem.DecapsulationKey1024, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("ML-KEM decapsulation seed is empty")
	}
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-1024 decapsulation key: %w", err)
	}
	return dk, nil
}

func LoadMLKEM1024DecapsulationKeyFromHex(h string) (*mlkem.DecapsulationKey1024, error) {
	if h == "" {
		return nil, fmt.Errorf("decapsulation key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadMLKEM1024DecapsulationKey(b)
}

func LoadMLKEM1024DecapsulationKeyFromBase64(b64 string) (*mlkem.DecapsulationKey1024, error) {
	if b64 == "" {
		return nil, fmt.Errorf("decapsulation key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadMLKEM1024DecapsulationKey(b)
}

// LoadMLKEM1024EncapsulationKey 从 1568 字节加载封装（公）密钥。
func LoadMLKEM1024EncapsulationKey(b []byte) (*mlkem.EncapsulationKey1024, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("encapsulation key data is empty")
	}
	ek, err := mlkem.NewEncapsulationKey1024(b)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-1024 encapsulation key: %w", err)
	}
	return ek, nil
}

func LoadMLKEM1024EncapsulationKeyFromHex(h string) (*mlkem.EncapsulationKey1024, error) {
	if h == "" {
		return nil, fmt.Errorf("encapsulation key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadMLKEM1024EncapsulationKey(b)
}

func LoadMLKEM1024EncapsulationKeyFromBase64(b64 string) (*mlkem.EncapsulationKey1024, error) {
	if b64 == "" {
		return nil, fmt.Errorf("encapsulation key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadMLKEM1024EncapsulationKey(b)
}

func GetMLKEM1024EncapsulationKeyBytes(ek *mlkem.EncapsulationKey1024) []byte {
	if ek == nil {
		return nil
	}
	return ek.Bytes()
}

func GetMLKEM1024DecapsulationKeyBytes(dk *mlkem.DecapsulationKey1024) []byte {
	if dk == nil {
		return nil
	}
	return dk.Bytes()
}

// EncapsulateMLKEM1024 向接收方封装密钥，返回共享秘密与 KEM 密文。
func EncapsulateMLKEM1024(recipient *mlkem.EncapsulationKey1024) (sharedKey, ciphertext []byte, err error) {
	if recipient == nil {
		return nil, nil, fmt.Errorf("encapsulation key cannot be nil")
	}
	sk, ct := recipient.Encapsulate()
	return sk, ct, nil
}

// DecapsulateMLKEM1024 用解封装私钥从 KEM 密文恢复共享秘密。
func DecapsulateMLKEM1024(dk *mlkem.DecapsulationKey1024, ciphertext []byte) ([]byte, error) {
	if dk == nil {
		return nil, fmt.Errorf("decapsulation key cannot be nil")
	}
	if len(ciphertext) != mlkem1024CtLen {
		return nil, fmt.Errorf("invalid ML-KEM ciphertext length: got %d, expected %d", len(ciphertext), mlkem1024CtLen)
	}
	return dk.Decapsulate(ciphertext)
}

func hkdfKeyMLKEM1024(sharedKey []byte) ([]byte, error) {
	if len(sharedKey) == 0 {
		return nil, fmt.Errorf("sharedKey cannot be empty")
	}
	return hkdf.Key(sha256.New, sharedKey, nil, hkdfInfoEncMLKEM1024, keyLen)
}

// EncryptMLKEM1024 使用 ML-KEM-1024 封装 + HKDF-SHA256 + AES-GCM 加密。
// 输出：[版本 0x04][KEM 密文 1568][nonce‖密文‖tag]；publicTo 为 1568 字节接收方封装公钥。
func EncryptMLKEM1024(publicTo []byte, message, additionalData []byte) ([]byte, error) {
	if len(publicTo) != mlkem1024PubKeyLen {
		return nil, fmt.Errorf("encapsulation key must be %d bytes", mlkem1024PubKeyLen)
	}
	if len(additionalData) > 1024*1024 {
		return nil, fmt.Errorf("additionalData too large (max 1MB)")
	}

	ek, err := LoadMLKEM1024EncapsulationKey(publicTo)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient encapsulation key: %w", err)
	}

	sharedKey, kemCt, err := EncapsulateMLKEM1024(ek)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(sharedKey)

	aesKey, err := hkdfKeyMLKEM1024(sharedKey)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(aesKey)

	aad := constructSecureAAD(additionalData, kemCt, protocolVersionMLKEM1024)

	gcmData, err := aesGCMEncrypt(message, aesKey, aad)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	result := make([]byte, 1+len(kemCt)+len(gcmData))
	result[0] = protocolVersionMLKEM1024
	copy(result[1:], kemCt)
	copy(result[1+len(kemCt):], gcmData)
	return result, nil
}

// DecryptMLKEM1024 解密 EncryptMLKEM1024 产出；版本字节须为 0x04。
func DecryptMLKEM1024(dk *mlkem.DecapsulationKey1024, msg, additionalData, dst []byte) ([]byte, error) {
	minBody := 1 + mlkem1024CtLen + nonceLen + 16
	if len(msg) < minBody {
		return nil, fmt.Errorf("message too short")
	}
	if msg[0] != protocolVersionMLKEM1024 {
		return nil, fmt.Errorf("unsupported protocol version: %d", msg[0])
	}

	kemCt := msg[1 : 1+mlkem1024CtLen]
	ciphertextWithTag := msg[1+mlkem1024CtLen:]

	sharedKey, err := DecapsulateMLKEM1024(dk, kemCt)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(sharedKey)

	aesKey, err := hkdfKeyMLKEM1024(sharedKey)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(aesKey)

	aad := constructSecureAAD(additionalData, kemCt, protocolVersionMLKEM1024)

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

func MLKEM1024EncapsulationKeyToHex(ek *mlkem.EncapsulationKey1024) string {
	if ek == nil {
		return ""
	}
	return hex.EncodeToString(ek.Bytes())
}

func MLKEM1024DecapsulationKeyToHex(dk *mlkem.DecapsulationKey1024) string {
	if dk == nil {
		return ""
	}
	return hex.EncodeToString(dk.Bytes())
}

func MLKEM1024EncapsulationKeyToBase64(ek *mlkem.EncapsulationKey1024) string {
	if ek == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(ek.Bytes())
}

func MLKEM1024DecapsulationKeyToBase64(dk *mlkem.DecapsulationKey1024) string {
	if dk == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(dk.Bytes())
}

func GetMLKEM1024ProtocolVersion() byte {
	return protocolVersionMLKEM1024
}

func ValidateMLKEM1024EncapsulationKey(b []byte) error {
	_, err := LoadMLKEM1024EncapsulationKey(b)
	return err
}
