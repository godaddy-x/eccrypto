package ecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// ECDH 相关常量
	ecdhPubKeyLen = 65 // P256曲线未压缩公钥固定为65字节：0x04 + 32字节X + 32字节Y

	// 加密相关常量
	keyLen        = 32                        // AES-256 密钥长度
	nonceLen      = 12                        // GCM推荐nonce长度
	hkdfInfoEnc   = "ecdh-aes-gcm-encryption" // HKDF上下文标签（加密密钥）
	hkdfInfoNonce = "ecdh-aes-gcm-nonce"      // HKDF上下文标签（nonce派生）
	hkdfInfoAAD   = "ecdh-aes-gcm-aad"        // HKDF上下文标签（AAD认证）
	hkdfSalt      = "ecdh-aes-gcm-v1-salt"    // HKDF固定盐值

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

	// 使用HKDF派生加密密钥和nonce
	encKey, nonce, err := deriveKeyAndNonce(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer SecureZeroBytes(encKey) // 清理加密密钥

	// 构造安全的AAD（包含版本信息和HMAC保护）
	aad, err := constructSecureAAD(additionalData, ephemPubBytes, protocolVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to construct AAD: %w", err)
	}

	// AES-GCM加密（使用派生的nonce）
	gcmData, err := aesGCMEncryptWithNonce(message, encKey, nonce, aad)
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
func Decrypt(privateKey *ecdh.PrivateKey, msg, additionalData []byte) ([]byte, error) {
	// 输入验证
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if len(msg) < 1+ecdhPubKeyLen+16 { // 版本 + 公钥 + AuthTag（nonce通过HKDF重新派生）
		return nil, fmt.Errorf("message too short (min %d bytes, got %d)", 1+ecdhPubKeyLen+16, len(msg))
	}
	if len(additionalData) > 1024*1024 {
		return nil, errors.New("additionalData too large (max 1MB)")
	}

	// 解析消息格式
	version := msg[0]
	if version != protocolVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d", version)
	}

	ephemPubBytes := msg[1 : 1+ecdhPubKeyLen]
	gcmData := msg[1+ecdhPubKeyLen:]

	// 加载临时公钥
	ephemPub, err := LoadECDHPublicKey(ephemPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// 计算共享密钥
	sharedKey, err := GenSharedKeyECDH(privateKey, ephemPub)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}
	defer SecureZeroBytes(sharedKey)

	// 使用HKDF派生加密密钥和nonce
	encKey, nonce, err := deriveKeyAndNonce(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer SecureZeroBytes(encKey)

	// 构造与加密时一致的AAD
	aad, err := constructSecureAAD(additionalData, ephemPubBytes, version)
	if err != nil {
		return nil, fmt.Errorf("failed to construct AAD: %w", err)
	}

	// AES-GCM解密
	plaintext, err := aesGCMDecryptWithNonce(gcmData, encKey, nonce, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (data may be tampered or wrong key): %w", err)
	}

	return plaintext, nil
}

// --------------- 安全改进的工具函数 ---------------

// deriveKeyAndNonce 使用HKDF从共享密钥派生加密密钥和nonce
func deriveKeyAndNonce(sharedKey []byte) (encKey, nonce []byte, err error) {
	// 派生足够长度的数据：加密密钥 + nonce
	totalLen := keyLen + nonceLen
	derived, err := hkdfExpandWithSalt(sharedKey, []byte(hkdfInfoEnc), totalLen)
	if err != nil {
		return nil, nil, err
	}

	encKey = derived[:keyLen]
	nonce = derived[keyLen : keyLen+nonceLen]
	return encKey, nonce, nil
}

// constructSecureAAD 构造安全的附加认证数据
func constructSecureAAD(additionalData, ephemPubBytes []byte, version byte) ([]byte, error) {
	// 基础AAD内容
	baseAAD := make([]byte, 0, 1+len(additionalData)+len(ephemPubBytes))
	baseAAD = append(baseAAD, version)
	baseAAD = append(baseAAD, additionalData...)
	baseAAD = append(baseAAD, ephemPubBytes...)

	// 使用HKDF派生AAD认证密钥
	aadKey, err := hkdfExpandWithSalt(baseAAD, []byte(hkdfInfoAAD), keyLen)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(aadKey)

	// 计算HMAC作为最终AAD
	h := hmac.New(sha256.New, aadKey)
	h.Write(baseAAD)
	return h.Sum(nil), nil
}

// hkdfExpandWithSalt 使用固定盐的HKDF扩展
func hkdfExpandWithSalt(secret, info []byte, length int) ([]byte, error) {
	// HKDF-Extract步骤（使用固定盐）
	salt := []byte(hkdfSalt)
	prk := hmac.New(sha256.New, salt)
	prk.Write(secret)
	prkBytes := prk.Sum(nil)

	// HKDF-Expand步骤
	return hkdfExpand(prkBytes, info, length)
}

// hkdfExpand HKDF扩展阶段的内部实现
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	hashLen := sha256.Size
	if length > 255*hashLen {
		return nil, errors.New("HKDF output length too large")
	}

	result := make([]byte, 0, length)
	counter := byte(1)
	prevT := make([]byte, 0)

	for len(result) < length {
		h := hmac.New(sha256.New, prk)
		h.Write(prevT)
		h.Write(info)
		h.Write([]byte{counter})

		currentT := h.Sum(nil)
		prevT = currentT

		needed := length - len(result)
		if needed > hashLen {
			needed = hashLen
		}
		result = append(result, currentT[:needed]...)

		counter++
		if counter == 0 { // 防止计数器溢出
			return nil, errors.New("HKDF counter overflow")
		}
	}

	return result, nil
}

// aesGCMEncryptWithNonce 使用指定nonce进行AES-GCM加密
func aesGCMEncryptWithNonce(plaintext, key, nonce, aad []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes for AES-256", keyLen)
	}
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("nonce must be %d bytes for GCM", nonceLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 使用派生的nonce进行加密
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// 返回密文 + AuthTag（不包含nonce）
	return ciphertext, nil
}

// aesGCMDecryptWithNonce 使用指定nonce进行AES-GCM解密
func aesGCMDecryptWithNonce(ciphertext, key, nonce, aad []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes for AES-256", keyLen)
	}
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("nonce must be %d bytes for GCM", nonceLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}

	// 解密并验证
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// SecureZeroBytes 安全清理字节切片（防止编译器优化）
func SecureZeroBytes(data []byte) {
	if data == nil {
		return
	}
	for i := range data {
		data[i] = 0
	}
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
