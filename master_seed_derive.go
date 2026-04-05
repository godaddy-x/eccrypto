package ecc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// MinMasterSeedLen 主密钥材料（IKM）最小字节长度；过短拒绝派生，降低弱熵误用风险。
// 生产环境建议使用至少 32 字节密码学随机数，或由 Argon2id / scrypt 等从口令拉伸得到。
const MinMasterSeedLen = 16

const (
	hkdfSaltDual25519     = "eccrypto:dual25519:v1"
	hkdfInfoEd25519Subkey = "eccrypto:dual25519:v1:ed25519-seed"
	hkdfInfoX25519Subkey  = "eccrypto:dual25519:v1:x25519-scalar"
)

func deriveSubkey32(master []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, []byte(hkdfSaltDual25519), info, ed25519SeedLen)
}

// decodeMasterSeedBase64 解码标准 Base64（StdEncoding）主密钥材料；解码失败不返回半解析数据。
func decodeMasterSeedBase64(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, fmt.Errorf("master seed base64 string is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid master seed base64: %w", err)
	}
	return raw, nil
}

// DeriveEd25519FromMasterSeed 使用 HKDF-SHA256 从主密钥材料派生 32 字节 Ed25519 种子，再生成扩展私钥。
// 与 DeriveX25519FromMasterSeed 使用不同 HKDF info，域分离；不得将派生出的种子直接当作 X25519 私钥使用。
func DeriveEd25519FromMasterSeed(master []byte) (ed25519.PrivateKey, error) {
	if len(master) < MinMasterSeedLen {
		return nil, fmt.Errorf("master seed length %d below minimum %d", len(master), MinMasterSeedLen)
	}
	seed, err := deriveSubkey32(master, hkdfInfoEd25519Subkey)
	if err != nil {
		return nil, fmt.Errorf("hkdf derive ed25519: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	SecureZeroBytes(seed)
	return priv, nil
}

// DeriveX25519FromMasterSeed 使用 HKDF-SHA256（独立 info）派生 32 字节 X25519 私钥标量。
func DeriveX25519FromMasterSeed(master []byte) (*ecdh.PrivateKey, error) {
	if len(master) < MinMasterSeedLen {
		return nil, fmt.Errorf("master seed length %d below minimum %d", len(master), MinMasterSeedLen)
	}
	scalar, err := deriveSubkey32(master, hkdfInfoX25519Subkey)
	if err != nil {
		return nil, fmt.Errorf("hkdf derive x25519: %w", err)
	}
	key, loadErr := LoadX25519PrivateKey(scalar)
	SecureZeroBytes(scalar)
	if loadErr != nil {
		return nil, loadErr
	}
	return key, nil
}

// DeriveEd25519AndX25519FromMasterSeed 从同一主密钥材料派生 Ed25519（签名）与 X25519（ECDH）私钥。
// 两路输出 HKDF info 不同，互不兼容；若 X25519 派生失败，已得到的 Ed25519 私钥会被清零。
func DeriveEd25519AndX25519FromMasterSeed(master []byte) (ed25519.PrivateKey, *ecdh.PrivateKey, error) {
	edPriv, err := DeriveEd25519FromMasterSeed(master)
	if err != nil {
		return nil, nil, err
	}
	xPriv, err := DeriveX25519FromMasterSeed(master)
	if err != nil {
		SecureZeroBytes(edPriv)
		return nil, nil, err
	}
	return edPriv, xPriv, nil
}

// DeriveEd25519FromMasterSeedBase64 从 Base64（StdEncoding）解码主种子后派生 Ed25519 私钥；解码得到的字节在返回前会清零。
func DeriveEd25519FromMasterSeedBase64(b64 string) (ed25519.PrivateKey, error) {
	raw, err := decodeMasterSeedBase64(b64)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(raw)
	return DeriveEd25519FromMasterSeed(raw)
}

// DeriveX25519FromMasterSeedBase64 从 Base64 解码主种子后派生 X25519 私钥；解码缓冲在返回前清零。
func DeriveX25519FromMasterSeedBase64(b64 string) (*ecdh.PrivateKey, error) {
	raw, err := decodeMasterSeedBase64(b64)
	if err != nil {
		return nil, err
	}
	defer SecureZeroBytes(raw)
	return DeriveX25519FromMasterSeed(raw)
}

// DeriveEd25519AndX25519FromMasterSeedBase64 从 Base64 解码主种子后同时派生 Ed25519 与 X25519 私钥。
func DeriveEd25519AndX25519FromMasterSeedBase64(b64 string) (ed25519.PrivateKey, *ecdh.PrivateKey, error) {
	raw, err := decodeMasterSeedBase64(b64)
	if err != nil {
		return nil, nil, err
	}
	defer SecureZeroBytes(raw)
	return DeriveEd25519AndX25519FromMasterSeed(raw)
}
