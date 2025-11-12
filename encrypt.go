package ecc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	// ECDH 相关常量
	ecdhPubKeyLen = 65 // ECDH 公钥长度 (未压缩格式: 1字节前缀 + 32字节X + 32字节Y)

	// 加密相关常量
	ivLen  = 16 // IV 长度 (AES 块大小)
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
	if len(b) != ecdhPubKeyLen {
		return nil, errors.New("invalid ECDH public key length, expected 65 bytes")
	}
	return ecdhCurve.NewPublicKey(b)
}

// LoadECDHPublicKeyFromHex 从十六进制字符串加载ECDH公钥
func LoadECDHPublicKeyFromHex(h string) (*ecdh.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad ECDH public key hex")
	}
	return ecdhCurve.NewPublicKey(b)
}

// LoadECDHPublicKeyFromBase64 从Base64字符串加载ECDH公钥
func LoadECDHPublicKeyFromBase64(b64 string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("bad ECDH public key base64")
	}
	return ecdhCurve.NewPublicKey(b)
}

// GetECDHPublicKeyBytes 获取ECDH公钥的字节表示
func GetECDHPublicKeyBytes(pub ecdh.PublicKey) []byte {
	return pub.Bytes()
}

// GetECDHPrivateKeyBytes 获取ECDH私钥的字节表示
func GetECDHPrivateKeyBytes(prk *ecdh.PrivateKey) []byte {
	return prk.Bytes()
}

// GenSharedKeyECDH 使用ECDH进行密钥交换（推荐的新版本）
func GenSharedKeyECDH(ownerPrk *ecdh.PrivateKey, otherPub *ecdh.PublicKey) ([]byte, error) {
	sharedKey, err := ownerPrk.ECDH(otherPub)
	if err != nil {
		return nil, errors.New("ECDH key exchange failed: " + err.Error())
	}
	return fillSharedKeyHex(sharedKey), nil
}

// Encrypt 使用ECDH进行加密（推荐的新版本）
func Encrypt(inputPrk *ecdh.PrivateKey, publicTo, message []byte) ([]byte, error) {
	if len(publicTo) != ecdhPubKeyLen {
		return nil, errors.New("invalid ECDH public key length, expected 65 bytes")
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
	sharedKeyHex, err := GenSharedKeyECDH(inputPrk, pub)
	if err != nil {
		return nil, err
	}

	// 使用共享密钥进行加密（复用现有逻辑）
	return encryptWithSharedKey(sharedKeyHex, GetECDHPublicKeyBytes(*inputPrk.PublicKey()), message)
}

// encryptWithSharedKey 使用给定的共享密钥和临时公钥进行加密的核心逻辑
func encryptWithSharedKey(sharedKeyHex, ephemPublicKey, message []byte) ([]byte, error) {
	sharedKeyHash := hash512(sharedKeyHex)
	macKey := sharedKeyHash[keyLen:]
	encryptionKey := sharedKeyHash[0:keyLen]

	iv, err := randomBytes(ivLen)
	if err != nil {
		return nil, errors.New("random iv failed: " + err.Error())
	}

	ciphertext, err := aes256CbcEncrypt(iv, encryptionKey, message)
	if err != nil {
		return nil, errors.New("encrypt failed: " + err.Error())
	}

	hashData := mergeMessage(ephemPublicKey, iv, ciphertext)
	realMac := hmac256(macKey, hashData)

	return concatMessage(ephemPublicKey, iv, realMac, ciphertext), nil
}

// Decrypt 使用ECDH进行解密
func Decrypt(privateKey *ecdh.PrivateKey, msg []byte) ([]byte, error) {
	// ECDH使用不同的消息格式：公钥 + IV + MAC + 密文
	ecdhMsgMinLen := ecdhPubKeyLen + ivLen + macLen // ECDH公钥 + IV + MAC

	if len(msg) <= ecdhMsgMinLen {
		return nil, errors.New("bad msg data")
	}

	ephemPublicKey := msg[0:ecdhPubKeyLen]
	pub, err := LoadECDHPublicKey(ephemPublicKey)
	if err != nil {
		return nil, errors.New("bad ECDH public key: " + err.Error())
	}

	// 使用ECDH生成共享密钥
	sharedKey, err := privateKey.ECDH(pub)
	if err != nil {
		return nil, errors.New("ECDH key exchange failed: " + err.Error())
	}

	sharedKeyHex := fillSharedKeyHex(sharedKey)

	// 使用共享密钥进行解密
	sharedKeyHash := hash512(sharedKeyHex)
	macKey := sharedKeyHash[keyLen:]
	encryptionKey := sharedKeyHash[0:keyLen]

	iv := msg[ecdhPubKeyLen : ecdhPubKeyLen+ivLen]               // IV 部分
	mac := msg[ecdhPubKeyLen+ivLen : ecdhPubKeyLen+ivLen+macLen] // MAC 部分
	ciphertext := msg[ecdhPubKeyLen+ivLen+macLen:]               // 密文部分

	hashData := mergeMessage(ephemPublicKey, iv, ciphertext)
	realMac := hmac256(macKey, hashData)

	if !bytes.Equal(mac, realMac) {
		return nil, errors.New("mac invalid")
	}

	plaintext, err := aes256CbcDecrypt(iv, encryptionKey, ciphertext)
	if err != nil {
		return nil, errors.New("decrypt failed: " + err.Error())
	}
	return plaintext, nil
}
