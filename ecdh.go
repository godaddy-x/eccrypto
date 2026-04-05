package ecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// ECDH 相关常量
	ecdhPubKeyLen = 65 // P256曲线未压缩公钥固定为65字节：0x04 + 32字节X + 32字节Y

	// 加密相关常量
	hkdfInfoEnc = "ecdh-aes-gcm-encryption:" // HKDF上下文标签（加密密钥）
	keyLen      = 32                         // AES-256 密钥长度
	nonceLen    = 12                         // GCM推荐nonce长度
	// 消息格式版本
	protocolVersion = 0x01
)

var (
	ecdhCurve = ecdh.P256() // 使用P256曲线进行密钥交换
)

// CreateECDH 生成新的ECDH私钥，用于密钥交换
// 建议每次会话使用新密钥以实现前向保密
func CreateECDH() (*ecdh.PrivateKey, error) {
	return ecdhCurve.GenerateKey(rand.Reader)
}

// --------------- 私钥加载 ---------------

// LoadECDHPrivateKey 从字节数组加载ECDH私钥
func LoadECDHPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	if len(b) == 0 {
		return nil, errors.New("private key data is empty")
	}
	key, err := ecdhCurve.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid private key bytes: %w", err)
	}
	return key, nil
}

// LoadECDHPrivateKeyFromHex 从十六进制字符串加载ECDH私钥
func LoadECDHPrivateKeyFromHex(hexStr string) (*ecdh.PrivateKey, error) {
	if hexStr == "" {
		return nil, errors.New("private key hex string is empty")
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadECDHPrivateKey(b)
}

// LoadECDHPrivateKeyFromBase64 从Base64字符串加载ECDH私钥
func LoadECDHPrivateKeyFromBase64(b64Str string) (*ecdh.PrivateKey, error) {
	if b64Str == "" {
		return nil, errors.New("private key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadECDHPrivateKey(b)
}

// --------------- 公钥加载 ---------------

// LoadECDHPublicKey 从字节数组加载ECDH公钥（必须是未压缩格式：0x04 + 32字节X + 32字节Y）
func LoadECDHPublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) == 0 {
		return nil, errors.New("public key data is empty")
	}
	if len(b) != ecdhPubKeyLen || b[0] != 0x04 {
		return nil, fmt.Errorf("public key must be 65 bytes (uncompressed 0x04 format)")
	}
	key, err := ecdhCurve.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid public key bytes: %w", err)
	}
	return key, nil
}

// LoadECDHPublicKeyFromHex 从十六进制字符串加载ECDH公钥
func LoadECDHPublicKeyFromHex(hexStr string) (*ecdh.PublicKey, error) {
	if hexStr == "" {
		return nil, errors.New("public key hex string is empty")
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadECDHPublicKey(b)
}

// LoadECDHPublicKeyFromBase64 从Base64字符串加载ECDH公钥
func LoadECDHPublicKeyFromBase64(b64Str string) (*ecdh.PublicKey, error) {
	if b64Str == "" {
		return nil, errors.New("public key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadECDHPublicKey(b)
}

// --------------- 密钥字节获取 ---------------

// GetECDHPublicKeyBytes 获取ECDH公钥的字节表示（未压缩格式）
func GetECDHPublicKeyBytes(pub *ecdh.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	return pub.Bytes()
}

// GetECDHPrivateKeyBytes 获取ECDH私钥的字节表示
func GetECDHPrivateKeyBytes(prk *ecdh.PrivateKey) []byte {
	if prk == nil {
		return nil
	}
	return prk.Bytes()
}

// --------------- 密钥交换 ---------------

// GenSharedKeyECDH 计算ECDH共享密钥
func GenSharedKeyECDH(ownerPrk *ecdh.PrivateKey, otherPub *ecdh.PublicKey) ([]byte, error) {
	if ownerPrk == nil || otherPub == nil {
		return nil, errors.New("private key and public key cannot be nil")
	}
	sharedKey, err := ownerPrk.ECDH(otherPub)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}
	return sharedKey, nil
}

// --------------- 加密解密核心 ---------------

// Encrypt 使用ECDH+AES-GCM加密消息
// 输出格式：[版本(1字节)] + [临时公钥(65字节)] + [GCM数据(Nonce + 密文 + AuthTag)]
func Encrypt(inputPrk *ecdh.PrivateKey, publicTo []byte, message, additionalData []byte) ([]byte, error) {
	// 输入验证
	if len(publicTo) != ecdhPubKeyLen {
		return nil, fmt.Errorf("public key must be %d bytes", ecdhPubKeyLen)
	}
	// 允许空消息（用于测试兼容性）
	if len(additionalData) > 1024*1024 { // 1MB上限
		return nil, errors.New("additionalData too large (max 1MB)")
	}

	// 加载接收方公钥
	pubTo, err := LoadECDHPublicKey(publicTo)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	// 生成临时私钥（若未提供，实现前向保密）
	ephemPrk := inputPrk
	if ephemPrk == nil {
		ephemPrk, err = CreateECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
		}
	}
	defer SecureZeroBytes(GetECDHPrivateKeyBytes(ephemPrk)) // 清理临时私钥

	ephemPub := ephemPrk.PublicKey()
	ephemPubBytes := GetECDHPublicKeyBytes(ephemPub)

	// 计算共享密钥
	sharedKey, err := GenSharedKeyECDH(ephemPrk, pubTo)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(sharedKey) // 清理共享密钥

	aesKey, err := HkdfKey(sharedKey)
	if err != nil {
		return nil, err
	}

	defer SecureZeroBytes(aesKey) // 清理加密密钥

	// 构造安全的AAD（包含版本信息）
	aad := constructSecureAAD(additionalData, ephemPubBytes, protocolVersion)

	// AES-GCM加密
	gcmData, err := aesGCMEncrypt(message, aesKey, aad)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// 最终消息：版本 + 临时公钥 + GCM数据
	result := make([]byte, 1+len(ephemPubBytes)+len(gcmData))
	result[0] = protocolVersion
	copy(result[1:], ephemPubBytes)
	copy(result[1+len(ephemPubBytes):], gcmData)

	return result, nil
}

// Decrypt 使用ECDH+AES-GCM解密消息
func Decrypt(privateKey *ecdh.PrivateKey, msg, additionalData, dst []byte) ([]byte, error) {
	// 解析消息
	if len(msg) < 1+ecdhPubKeyLen+16 {
		return nil, errors.New("message too short")
	}
	version := msg[0]
	if version != protocolVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	ephemPubBytes := msg[1 : 1+ecdhPubKeyLen]
	ciphertextWithTag := msg[1+ecdhPubKeyLen:]

	ephemPub, err := LoadECDHPublicKey(ephemPubBytes)
	if err != nil {
		return nil, err
	}

	sharedKey, err := GenSharedKeyECDH(privateKey, ephemPub)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(sharedKey)

	aesKey, err := HkdfKey(sharedKey)
	if err != nil {
		return nil, err
	}

	defer SecureZeroBytes(aesKey)

	// 构造安全的AAD（包含版本信息）
	aad := constructSecureAAD(additionalData, ephemPubBytes, version)

	// === 关键修复：检查 dst 容量 ===
	expectedPlaintextLen := len(ciphertextWithTag) - 16 // GCM auth tag is always 16 bytes
	if dst != nil {
		if cap(dst) < expectedPlaintextLen {
			return nil, fmt.Errorf(
				"dst capacity (%d) insufficient for plaintext (expected %d)",
				cap(dst), expectedPlaintextLen,
			)
		}
		// 复用 dst 内存
		return AesGCMDecrypt(ciphertextWithTag, aesKey, aad, dst)
	}

	// 分配新内存
	return AesGCMDecrypt(ciphertextWithTag, aesKey, aad, nil)

}

// --------------- 安全改进的工具函数 ---------------

// HkdfKey 使用 HKDF-SHA256 从 ECDH 共享密钥派生 AES-256 密钥
// 参数:
//   - sharedKey: ECDH 协商得到的原始共享秘密（raw shared secret）
func HkdfKey(sharedKey []byte) ([]byte, error) {
	if len(sharedKey) == 0 {
		return nil, errors.New("sharedKey cannot be empty")
	}

	result, err := hkdf.Key(sha256.New, sharedKey, nil, hkdfInfoEnc, keyLen)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func SecureNonce(l int) ([]byte, error) {
	nonce := make([]byte, l)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// constructSecureAAD 构造安全的附加认证数据
func constructSecureAAD(additionalData, ephemPubBytes []byte, version byte) []byte {
	aad := make([]byte, 1+len(additionalData)+len(ephemPubBytes))
	aad[0] = version
	copy(aad[1:], additionalData)
	copy(aad[1+len(additionalData):], ephemPubBytes)
	return aad
}

// aesGCMEncrypt Byte(Nonce + Ciphertext + AuthTag)
func aesGCMEncrypt(plaintext, key, additionalData []byte) ([]byte, error) {
	// 1. 输入验证
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	// 2. 创建 AES 加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// 3. 创建 GCM 模式（AEAD: Authenticated Encryption with Associated Data）
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// 4. 生成 Nonce（GCM 标准：12 字节）
	// 注意：Nonce 必须唯一，否则会破坏 GCM 安全性
	nonce, err := SecureNonce(nonceLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 5. 加密并生成认证标签（单步操作）
	// Seal 会自动：
	//   - 加密 plaintext
	//   - 对 ciphertext + additionalData 生成 GMAC 认证标签
	//   - 返回：ciphertext + authTag
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)

	// 6. 拼接：Nonce + Ciphertext + AuthTag
	result := append(nonce, ciphertext...)

	return result, nil
}

// AesGCMDecrypt AES-GCM 解密基础方法
func AesGCMDecrypt(data, key, additionalData, dst []byte) ([]byte, error) {
	// 1. 输入验证
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	// 3. 创建 AES 加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// 4. 创建 GCM 模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// 5. 检查数据长度（Nonce + Ciphertext + AuthTag）
	nonceSize := gcm.NonceSize()
	minLen := nonceSize + gcm.Overhead()
	if len(data) < minLen {
		return nil, fmt.Errorf("encrypted data too short (expected at least %d bytes)", minLen)
	}

	// 6. 分离 Nonce 和 Ciphertext+AuthTag
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// 7. 解密并验证认证标签（单步操作）
	// Open 会自动：
	//   - 验证 GMAC 认证标签（防篡改）
	//   - 验证 additionalData（如果提供）
	//   - 解密 ciphertext
	// 任何验证失败都会返回 error
	if dst == nil {
		// 解密并验证
		return gcm.Open(nil, nonce, ciphertext, additionalData)
	}
	// 解密并验证
	return gcm.Open(dst[:0], nonce, ciphertext, additionalData)

}

// --------------- 便利函数 ---------------

// ECDHPublicKeyToHex 将ECDH公钥转换为十六进制字符串
func ECDHPublicKeyToHex(pub *ecdh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return hex.EncodeToString(pub.Bytes())
}

// ECDHPrivateKeyToHex 将ECDH私钥转换为十六进制字符串
func ECDHPrivateKeyToHex(prk *ecdh.PrivateKey) string {
	if prk == nil {
		return ""
	}
	return hex.EncodeToString(prk.Bytes())
}

// ECDHPublicKeyToBase64 将ECDH公钥转换为Base64字符串
func ECDHPublicKeyToBase64(pub *ecdh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}

// ECDHPrivateKeyToBase64 将ECDH私钥转换为Base64字符串
func ECDHPrivateKeyToBase64(prk *ecdh.PrivateKey) string {
	if prk == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(prk.Bytes())
}

// GetProtocolVersion 获取当前协议版本
func GetProtocolVersion() byte {
	return protocolVersion
}

// ValidatePublicKey 验证公钥格式和有效性
func ValidatePublicKey(publicKey []byte) error {
	_, err := LoadECDHPublicKey(publicKey)
	return err
}
