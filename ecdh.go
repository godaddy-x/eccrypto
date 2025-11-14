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
	"io"
	"sync"
)

const (
	// ECDH 相关常量（P256曲线未压缩公钥固定为65字节：0x04 + 32字节X + 32字节Y）
	ecdhPubKeyLen = 65

	// 加密相关常量
	keyLen        = 32                        // AES-256 密钥长度
	hkdfInfoEnc   = "ecdh-aes-gcm-encryption" // HKDF上下文标签（加密密钥）
	hkdfInfoNonce = "ecdh-aes-gcm-nonce"      // HKDF上下文标签（nonce派生，可选）
)

var (
	ecdhCurve       = ecdh.P256() // 使用P256曲线进行密钥交换
	createECDHMutex sync.Mutex    // 保护密钥生成并发安全
)

// CreateECDH 生成新的ECDH私钥，用于密钥交换
// 建议每次会话使用新密钥以实现前向保密
// 使用互斥锁确保并发安全
func CreateECDH() (*ecdh.PrivateKey, error) {
	createECDHMutex.Lock()
	defer createECDHMutex.Unlock()
	return ecdhCurve.GenerateKey(rand.Reader)
}

// --------------- 私钥加载（移除冗余函数，统一命名）---------------

// LoadECDHPrivateKey 从字节数组加载ECDH私钥
func LoadECDHPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	key, err := ecdhCurve.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid private key bytes: %w", err)
	}
	return key, nil
}

// LoadECDHPrivateKeyFromHex 从十六进制字符串加载ECDH私钥
func LoadECDHPrivateKeyFromHex(hexStr string) (*ecdh.PrivateKey, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadECDHPrivateKey(b)
}

// LoadECDHPrivateKeyFromBase64 从Base64字符串加载ECDH私钥
func LoadECDHPrivateKeyFromBase64(b64Str string) (*ecdh.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadECDHPrivateKey(b)
}

// --------------- 公钥加载（移除冗余函数，统一命名）---------------

// LoadECDHPublicKey 从字节数组加载ECDH公钥（必须是未压缩格式：0x04 + 32字节X + 32字节Y）
func LoadECDHPublicKey(b []byte) (*ecdh.PublicKey, error) {
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
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return LoadECDHPublicKey(b)
}

// LoadECDHPublicKeyFromBase64 从Base64字符串加载ECDH公钥
func LoadECDHPublicKeyFromBase64(b64Str string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return LoadECDHPublicKey(b)
}

// --------------- 密钥字节获取 ---------------

// GetECDHPublicKeyBytes 获取ECDH公钥的字节表示（未压缩格式）
func GetECDHPublicKeyBytes(pub *ecdh.PublicKey) []byte {
	return pub.Bytes()
}

// GetECDHPrivateKeyBytes 获取ECDH私钥的字节表示
func GetECDHPrivateKeyBytes(prk *ecdh.PrivateKey) []byte {
	return prk.Bytes()
}

// --------------- 密钥交换 ---------------

// GenSharedKeyECDH 计算ECDH共享密钥
func GenSharedKeyECDH(ownerPrk *ecdh.PrivateKey, otherPub *ecdh.PublicKey) ([]byte, error) {
	sharedKey, err := ownerPrk.ECDH(otherPub)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}
	return sharedKey, nil
}

// --------------- 加密解密核心 ---------------

// Encrypt 使用ECDH+AES-GCM加密消息
// 流程：
// 1. 若inputPrk为nil，生成临时私钥（推荐，实现前向保密）
// 2. ECDH交换得到共享密钥
// 3. HKDF派生AES-256密钥
// 4. 合并临时公钥和additionalData作为GCM附加认证数据（AAD）
// 5. AES-GCM加密（自动认证AAD和密文）
// 输出格式：[临时公钥(65字节)] + [GCM数据(Nonce + 密文 + AuthTag)]
func Encrypt(inputPrk *ecdh.PrivateKey, publicTo []byte, message, additionalData []byte) ([]byte, error) {
	// 验证接收方公钥长度
	if len(publicTo) != ecdhPubKeyLen {
		return nil, fmt.Errorf("public key must be %d bytes", ecdhPubKeyLen)
	}
	// 限制附加数据大小（防止DoS）
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
	ephemPub := ephemPrk.PublicKey()
	ephemPubBytes := GetECDHPublicKeyBytes(ephemPub)

	// 计算共享密钥
	sharedKey, err := GenSharedKeyECDH(ephemPrk, pubTo)
	if err != nil {
		return nil, err
	}

	// HKDF派生加密密钥（使用上下文标签避免密钥混淆）
	encKey, err := deriveKey(sharedKey, []byte(hkdfInfoEnc))
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// 构造GCM附加认证数据（AAD）：[原始附加数据长度(2字节)] + 原始附加数据 + 临时公钥
	// （长度前缀用于解密时分离原始附加数据）
	aad := append(
		[]byte{byte(len(additionalData) >> 8), byte(len(additionalData))}, // 2字节长度前缀
		append(additionalData, ephemPubBytes...)...,
	)

	// AES-GCM加密（包含nonce、密文、AuthTag）
	gcmData, err := aesGCMEncrypt(message, encKey, aad)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// 最终消息：临时公钥 + GCM数据
	return append(ephemPubBytes, gcmData...), nil
}

// Decrypt 使用ECDH+AES-GCM解密消息
// 流程：
// 1. 从消息中提取临时公钥和GCM数据
// 2. ECDH交换得到共享密钥
// 3. HKDF派生AES-256密钥
// 4. 合并临时公钥和additionalData构造AAD，验证并解密
func Decrypt(privateKey *ecdh.PrivateKey, msg, additionalData []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}
	// 验证消息最小长度（临时公钥65字节 + GCM数据：nonce + 密文 + AuthTag）
	// 对于空消息，GCM只产生AuthTag，所以最小长度是 65 + 12 + 16 = 93
	minMsgLen := ecdhPubKeyLen + 12 + 16 // 12字节nonce + 16字节AuthTag（空消息）
	if len(msg) < minMsgLen {
		return nil, fmt.Errorf("message too short (min %d bytes, got %d)", minMsgLen, len(msg))
	}

	// 提取临时公钥和GCM数据
	ephemPubBytes := msg[:ecdhPubKeyLen]
	gcmData := msg[ecdhPubKeyLen:]

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

	// HKDF派生加密密钥（与加密时标签一致）
	encKey, err := deriveKey(sharedKey, []byte(hkdfInfoEnc))
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// 构造与加密时一致的AAD（用于GCM验证）
	aad := append([]byte{byte(len(additionalData) >> 8), byte(len(additionalData))}, append(additionalData, ephemPubBytes...)...)

	// AES-GCM解密（自动验证AAD和密文完整性）
	plaintext, err := aesGCMDecrypt(gcmData, encKey, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (data may be tampered or wrong key): %w", err)
	}

	return plaintext, nil
}

// --------------- 工具函数 ---------------

// deriveKey 使用HKDF从共享密钥派生子密钥（符合NIST SP 800-56A标准）
// HKDF = HMAC-based Key Derivation Function
func deriveKey(sharedKey, info []byte) ([]byte, error) {
	// HKDF步骤1：HKDF-Extract（使用空盐，因为共享密钥已是高质量熵）
	prk := hmac.New(sha256.New, []byte{}) // 空盐
	prk.Write(sharedKey)
	prkBytes := prk.Sum(nil)

	// HKDF步骤2：HKDF-Expand（使用PRK生成指定长度密钥）
	return hkdfExpand(prkBytes, info, keyLen)
}

// hkdfExpand HKDF扩展阶段的内部实现
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	hashLen := sha256.Size
	if length > 255*hashLen {
		return nil, errors.New("HKDF output length too large")
	}

	result := make([]byte, 0, length)
	counter := byte(1)
	prevT := make([]byte, 0) // T(i-1)，初始为空

	for len(result) < length {
		// T(i) = HMAC(PRK, T(i-1) || info || counter)
		h := hmac.New(sha256.New, prk)
		h.Write(prevT) // T(i-1)
		h.Write(info)
		h.Write([]byte{counter})

		// 计算新的 T
		currentT := h.Sum(nil)
		prevT = currentT // 为下一轮保存

		// 将T添加到结果中
		needed := length - len(result)
		if needed > hashLen {
			needed = hashLen
		}
		result = append(result, currentT[:needed]...)

		counter++
	}

	return result, nil
}

// aesGCMEncrypt AES-GCM加密
// 返回：[nonce(12字节)] + [密文] + [AuthTag(16字节)]
func aesGCMEncrypt(plaintext, key, aad []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes for AES-256", keyLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 生成12字节nonce（GCM推荐长度，安全性最佳）
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// 加密并生成AuthTag（包含对aad的认证）
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// 拼接nonce和密文（含AuthTag）
	return append(nonce, ciphertext...), nil
}

// aesGCMDecrypt AES-GCM解密（自动验证aad和密文完整性）
func aesGCMDecrypt(ciphertext, key, aad []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes for AES-256", keyLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// 分离nonce和密文（含AuthTag）
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// 解密并验证（失败则说明数据被篡改或密钥错误）
	return gcm.Open(nil, nonce, ciphertext, aad)
}
