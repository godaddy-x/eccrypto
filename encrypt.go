package ecc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// ECDH 相关常量
	ecdhPubKeyLen = 65 // ECDH 公钥长度 (未压缩格式: 1字节前缀 + 32字节X + 32字节Y)

	// 加密相关常量
	macLen = 32 // MAC 长度 (HMAC-SHA256)
	keyLen = 32 // 加密密钥长度 (AES-256)
)

var (
	ecdhCurve = ecdh.P256() // ECDH curve for key exchange
)

// CreateECDH 生成新的ECDH私钥，用于密钥交换
func CreateECDH() (*ecdh.PrivateKey, error) {
	return ecdhCurve.GenerateKey(rand.Reader)
}

// LoadHexECDHPrivateKey 从十六进制字符串加载ECDH私钥
func LoadHexECDHPrivateKey(h string) (*ecdh.PrivateKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad ECDH private key")
	}
	return ecdhCurve.NewPrivateKey(b)
}

// LoadBase64ECDHPrivateKey 从Base64字符串加载ECDH私钥
func LoadBase64ECDHPrivateKey(h string) (*ecdh.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad ECDH private key")
	}
	return ecdhCurve.NewPrivateKey(b)
}

// LoadECDHPrivateKey 从字节数组加载ECDH私钥
func LoadECDHPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdhCurve.NewPrivateKey(b)
}

// LoadECDHPrivateKeyFromHex 从十六进制字符串加载ECDH私钥
func LoadECDHPrivateKeyFromHex(h string) (*ecdh.PrivateKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad ECDH private key hex")
	}
	return ecdhCurve.NewPrivateKey(b)
}

// LoadECDHPrivateKeyFromBase64 从Base64字符串加载ECDH私钥
func LoadECDHPrivateKeyFromBase64(b64 string) (*ecdh.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("bad ECDH private key base64")
	}
	return ecdhCurve.NewPrivateKey(b)
}

// LoadECDHPublicKey 从字节数组加载ECDH公钥
// 接受未压缩格式的公钥，这是 crypto/ecdh.PublicKey.Bytes() 的输出格式
func LoadECDHPublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != ecdhPubKeyLen || b[0] != 0x04 {
		return nil, errors.New("invalid ECDH public key (must be uncompressed 0x04 format)")
	}
	return ecdhCurve.NewPublicKey(b)
}

// LoadECDHPublicKeyFromHex 从十六进制字符串加载ECDH公钥
func LoadECDHPublicKeyFromHex(h string) (*ecdh.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad ECDH public key hex")
	}
	return LoadECDHPublicKey(b)
}

// LoadECDHPublicKeyFromBase64 从Base64字符串加载ECDH公钥
func LoadECDHPublicKeyFromBase64(b64 string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("bad ECDH public key base64")
	}
	return LoadECDHPublicKey(b)
}

// GetECDHPublicKeyBytes 获取ECDH公钥的字节表示
func GetECDHPublicKeyBytes(pub ecdh.PublicKey) []byte {
	return pub.Bytes()
}

// GetECDHPrivateKeyBytes 获取ECDH私钥的字节表示
func GetECDHPrivateKeyBytes(prk *ecdh.PrivateKey) []byte {
	return prk.Bytes()
}

// GenSharedKeyECDH 使用ECDH进行密钥交换（推荐的新版本）不再使用hex格式
func GenSharedKeyECDH(ownerPrk *ecdh.PrivateKey, otherPub *ecdh.PublicKey) ([]byte, error) {
	sharedKey, err := ownerPrk.ECDH(otherPub)
	if err != nil {
		return nil, errors.New("ECDH key exchange failed: " + err.Error())
	}
	return sharedKey, nil
}

// Encrypt 使用ECDH进行加密（推荐的新版本）
// 加密流程：
// 1. ECDH 密钥交换 → 共享密钥
// 2. 派生加密密钥和 MAC 密钥
// 3. AES-GCM 加密 → GCM数据 (Nonce + Ciphertext + AuthTag)
// 4. HMAC 计算 → 对公钥+GCM数据签名
// 5. 拼接：公钥 + GCM数据 + HMAC
func Encrypt(inputPrk *ecdh.PrivateKey, publicTo, message, additionalData []byte) ([]byte, error) {
	if len(publicTo) != ecdhPubKeyLen {
		return nil, errors.New("invalid ECDH public key length, expected 65 bytes")
	}
	if len(additionalData) > 1024 {
		return nil, errors.New("additionalData too large (max 1KB)")
	}

	// 加载接收方的ECDH公钥
	pub, err := LoadECDHPublicKey(publicTo)
	if err != nil {
		return nil, errors.New("ECDH public key invalid: " + err.Error())
	}

	// 如果没有提供私钥，生成临时密钥
	if inputPrk == nil {
		inputPrk, err = CreateECDH()
		if err != nil {
			return nil, errors.New("create temp ECDH key failed: " + err.Error())
		}
	}

	// 生成共享密钥
	sharedKey, err := GenSharedKeyECDH(inputPrk, pub)
	if err != nil {
		return nil, err
	}

	// 使用共享密钥进行加密（复用现有逻辑）
	return encryptWithSharedKey(sharedKey, GetECDHPublicKeyBytes(*inputPrk.PublicKey()), message, additionalData)
}

// encryptWithSharedKey 使用给定的共享密钥和临时公钥进行加密的核心逻辑
func encryptWithSharedKey(sharedKey, ephemPublicKey, message, additionalData []byte) ([]byte, error) {
	// 输入验证
	if len(sharedKey) != keyLen {
		return nil, errors.New("shared key must be 32 bytes")
	}
	if len(ephemPublicKey) != ecdhPubKeyLen {
		return nil, errors.New("ephemeral public key must be 65 bytes")
	}

	sharedKeyHash := hash512(sharedKey)
	macKey := sharedKeyHash[keyLen:]
	encryptionKey := sharedKeyHash[0:keyLen]

	ciphertext, err := aesGCMEncryptBase(message, encryptionKey, additionalData)
	if err != nil {
		return nil, errors.New("encrypt failed: " + err.Error())
	}

	pubLen := len(ephemPublicKey)
	cipLen := len(ciphertext)
	macLen := len(hmac256([]byte{}, macKey)) // HMAC-SHA256 总是 32 字节

	// 防止整数溢出：检查总长度是否合理
	totalLen := pubLen + cipLen + macLen
	if totalLen < pubLen || totalLen < cipLen { // 检查溢出
		return nil, errors.New("message too large")
	}

	// 构造 HMAC 数据：公钥 + GCM密文
	hashMsg := make([]byte, pubLen+cipLen)
	copy(hashMsg[0:], ephemPublicKey)
	copy(hashMsg[pubLen:], ciphertext)

	// 计算数据指纹
	realMac := hmac256(hashMsg, macKey)

	// 填充最终数据：公钥 + GCM数据 + HMAC
	resultMsg := make([]byte, totalLen)
	copy(resultMsg[0:], ephemPublicKey)
	copy(resultMsg[pubLen:], ciphertext)
	copy(resultMsg[pubLen+cipLen:], realMac)

	return resultMsg, nil
}

// Decrypt 使用ECDH进行解密
// 解密流程：
// 1. 分离：公钥 + GCM数据 + HMAC
// 2. ECDH 密钥交换 → 共享密钥
// 3. HMAC 验证 → 确保公钥+GCM数据完整性
// 4. AES-GCM 解密 → 自动验证并解密
func Decrypt(privateKey *ecdh.PrivateKey, msg, additionalData []byte) ([]byte, error) {
	// 输入验证
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if len(additionalData) > 1024 {
		return nil, errors.New("additionalData too large (max 1KB)")
	}

	// 消息格式：公钥(65) + GCM数据(变长) + HMAC(32)
	hmacSize := macLen                    // HMAC 长度 32 字节
	minMsgLen := ecdhPubKeyLen + hmacSize // 最小消息长度

	if len(msg) <= minMsgLen {
		return nil, errors.New("bad msg data")
	}

	// 防止整数溢出
	msgLen := len(msg)
	if msgLen < ecdhPubKeyLen || msgLen < hmacSize {
		return nil, errors.New("message too short")
	}

	// 提取公钥
	ephemPublicKey := msg[0:ecdhPubKeyLen]
	pub, err := LoadECDHPublicKey(ephemPublicKey)
	if err != nil {
		return nil, errors.New("bad ECDH public key: " + err.Error())
	}

	// 生成共享密钥
	sharedKey, err := privateKey.ECDH(pub)
	if err != nil {
		return nil, errors.New("ECDH key exchange failed: " + err.Error())
	}

	// 派生密钥
	sharedKeyHash := hash512(sharedKey)
	macKey := sharedKeyHash[keyLen:]
	encryptionKey := sharedKeyHash[0:keyLen]

	// 分离 GCM 数据和 HMAC
	gcmDataEnd := msgLen - hmacSize
	if gcmDataEnd <= ecdhPubKeyLen {
		return nil, errors.New("invalid message format")
	}

	gcmData := msg[ecdhPubKeyLen:gcmDataEnd]
	receivedMac := msg[gcmDataEnd:]

	// 验证 HMAC（对公钥 + GCM数据）
	hmacData := msg[0:gcmDataEnd]
	expectedMac := hmac256(hmacData, macKey)

	if !bytes.Equal(receivedMac, expectedMac) {
		return nil, errors.New("mac invalid")
	}

	// GCM 解密
	plaintext, err := aesGCMDecryptBase(gcmData, encryptionKey, additionalData)
	if err != nil {
		return nil, errors.New("decrypt failed: " + err.Error())
	}

	return plaintext, nil
}

func hmac256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func hash512(msg []byte) []byte {
	h := sha512.New()
	h.Write(msg)
	return h.Sum(nil)
}

func randomBytes(l int) ([]byte, error) {
	bs := make([]byte, l)
	_, err := io.ReadFull(rand.Reader, bs)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

// AesGCMEncryptBase AES-GCM 加密基础方法
// 返回格式：(Nonce + Ciphertext + AuthTag) 字节数组
// Nonce: 12 字节（GCM 标准）
// AuthTag: 16 字节（128-bit 认证标签）
func aesGCMEncryptBase(plaintext, key, additionalData []byte) ([]byte, error) {
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
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
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

// AesGCMDecryptBase AES-GCM 解密基础方法
// 会自动验证：
// 1. 认证标签（AuthTag）- 确保密文未被篡改
// 2. 附加认证数据（AAD）- 确保关联数据未被篡改
// 任何一项验证失败都会返回错误，拒绝解密
func aesGCMDecryptBase(encryptedData, key, additionalData []byte) ([]byte, error) {
	// 1. 输入验证
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	// 2. 解码 Base64

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
	if len(encryptedData) < nonceSize {
		return nil, errors.New("encrypted data too short")
	}

	// 6. 分离 Nonce 和 Ciphertext+AuthTag
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// 7. 解密并验证认证标签（单步操作）
	// Open 会自动：
	//   - 验证 GMAC 认证标签（防篡改）
	//   - 验证 additionalData（如果提供）
	//   - 解密 ciphertext
	// 任何验证失败都会返回 error
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		// 🚨 这个错误非常重要！表示数据被篡改或密钥错误
		return nil, fmt.Errorf("authentication failed - data may be tampered: %w", err)
	}

	return plaintext, nil
}
