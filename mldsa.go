// ML-DSA (FIPS 204) helpers.
//
// Go 1.26 尚未导出 crypto/mldsa，此处使用 filippo.io/mldsa（与拟定中的 crypto/mldsa API 一致）。
// Go 1.27+ 发布 crypto/mldsa 后，可将本文件 import 换为 crypto/mldsa 并删除 filippo 依赖。
package ecc

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	fmldsa "filippo.io/mldsa"
)

const (
	mldsa87SeedLen   = fmldsa.PrivateKeySize
	mldsa87PubKeyLen = fmldsa.MLDSA87PublicKeySize
	mldsa87SigLen    = fmldsa.MLDSA87SignatureSize
)

var defaultMLDSA87Params = fmldsa.MLDSA87()

// CreateMLDSA87 生成 ML-DSA-87 密钥对。
func CreateMLDSA87() (*fmldsa.PrivateKey, error) {
	return fmldsa.GenerateKey(defaultMLDSA87Params)
}

// LoadMLDSA87PrivateKey 从 32 字节种子加载 ML-DSA-87 私钥。
func LoadMLDSA87PrivateKey(seed []byte) (*fmldsa.PrivateKey, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("private key seed is empty")
	}
	if len(seed) != mldsa87SeedLen {
		return nil, fmt.Errorf("invalid ML-DSA-87 seed length: got %d, expected %d", len(seed), mldsa87SeedLen)
	}
	return fmldsa.NewPrivateKey(defaultMLDSA87Params, seed)
}

func LoadMLDSA87PrivateKeyFromHex(h string) (*fmldsa.PrivateKey, error) {
	if h == "" {
		return nil, fmt.Errorf("private key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	return LoadMLDSA87PrivateKey(b)
}

func LoadMLDSA87PrivateKeyFromBase64(b64 string) (*fmldsa.PrivateKey, error) {
	if b64 == "" {
		return nil, fmt.Errorf("private key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid private key base64: %w", err)
	}
	return LoadMLDSA87PrivateKey(b)
}

// LoadMLDSA87PublicKey 从编码字节加载 ML-DSA-87 公钥（2592 字节）。
func LoadMLDSA87PublicKey(b []byte) (*fmldsa.PublicKey, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("public key data is empty")
	}
	if len(b) != mldsa87PubKeyLen {
		return nil, fmt.Errorf("invalid ML-DSA-87 public key length: got %d, expected %d", len(b), mldsa87PubKeyLen)
	}
	pk, err := fmldsa.NewPublicKey(defaultMLDSA87Params, b)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-DSA-87 public key: %w", err)
	}
	return pk, nil
}

func LoadMLDSA87PublicKeyFromHex(h string) (*fmldsa.PublicKey, error) {
	if h == "" {
		return nil, fmt.Errorf("public key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	return LoadMLDSA87PublicKey(b)
}

func LoadMLDSA87PublicKeyFromBase64(b64 string) (*fmldsa.PublicKey, error) {
	if b64 == "" {
		return nil, fmt.Errorf("public key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key base64: %w", err)
	}
	return LoadMLDSA87PublicKey(b)
}

func GetMLDSA87PrivateKeyBytes(sk *fmldsa.PrivateKey) ([]byte, error) {
	if sk == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	return append([]byte(nil), sk.Bytes()...), nil
}

func GetMLDSA87PublicKeyBytes(pk *fmldsa.PublicKey) ([]byte, error) {
	if pk == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	b := pk.Bytes()
	if len(b) != mldsa87PubKeyLen {
		return nil, fmt.Errorf("invalid ML-DSA-87 public key length: got %d, expected %d", len(b), mldsa87PubKeyLen)
	}
	return append([]byte(nil), b...), nil
}

// DeriveMLDSA87PublicKey 从私钥得到公钥（拷贝）。
func DeriveMLDSA87PublicKey(sk *fmldsa.PrivateKey) (*fmldsa.PublicKey, error) {
	if sk == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	pub := sk.PublicKey()
	return LoadMLDSA87PublicKey(pub.Bytes())
}

// SignMLDSA87 对消息签名（ML-DSA-87，空 context）。
func SignMLDSA87(sk *fmldsa.PrivateKey, message []byte) ([]byte, error) {
	if sk == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	sig, err := sk.Sign(nil, message, nil)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA sign failed: %w", err)
	}
	if len(sig) != mldsa87SigLen {
		return nil, fmt.Errorf("unexpected signature length: got %d, expected %d", len(sig), mldsa87SigLen)
	}
	return sig, nil
}

// VerifyMLDSA87 验证 ML-DSA-87 签名。
func VerifyMLDSA87(pk *fmldsa.PublicKey, message, signature []byte) error {
	if pk == nil {
		return fmt.Errorf("public key cannot be nil")
	}
	if len(signature) != mldsa87SigLen {
		return fmt.Errorf("invalid signature length: got %d, expected %d", len(signature), mldsa87SigLen)
	}
	if err := fmldsa.Verify(pk, message, signature, nil); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func MLDSA87PublicKeyToHex(pk *fmldsa.PublicKey) (string, error) {
	b, err := GetMLDSA87PublicKeyBytes(pk)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func MLDSA87PrivateKeyToHex(sk *fmldsa.PrivateKey) (string, error) {
	b, err := GetMLDSA87PrivateKeyBytes(sk)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func MLDSA87PublicKeyToBase64(pk *fmldsa.PublicKey) (string, error) {
	b, err := GetMLDSA87PublicKeyBytes(pk)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func MLDSA87PrivateKeyToBase64(sk *fmldsa.PrivateKey) (string, error) {
	b, err := GetMLDSA87PrivateKeyBytes(sk)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func ValidateMLDSA87PublicKey(b []byte) error {
	_, err := LoadMLDSA87PublicKey(b)
	return err
}
