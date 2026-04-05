package ecc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	ed25519PubKeyLen = ed25519.PublicKeySize  // 32
	ed25519SeedLen   = ed25519.SeedSize       // 32
	ed25519PrivKeyLen = ed25519.PrivateKeySize // 64，Go 中扩展私钥长度
	ed25519SigLen    = ed25519.SignatureSize  // 64
)

// CreateEd25519 生成新的 Ed25519 密钥对（返回 64 字节扩展私钥，内含种子与公钥后缀）
func CreateEd25519() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key generation failed: %w", err)
	}
	return priv, nil
}

// LoadEd25519PrivateKey 从字节加载 Ed25519 私钥：支持 32 字节种子或 64 字节扩展私钥。
// 返回新分配的拷贝；不再使用时应由调用方对持有切片调用 SecureZeroBytes（若需尽量缩短敏感数据寿命）。
func LoadEd25519PrivateKey(b []byte) (ed25519.PrivateKey, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("private key data is empty")
	}
	switch len(b) {
	case ed25519SeedLen:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519PrivKeyLen:
		// 仅校验长度，不做种子/后缀自洽校验（省一次 NewKeyFromSeed）。实际验签要求二者与 GenerateKey/NewKeyFromSeed 产出一致，否则签名无效。
		return ed25519.PrivateKey(append([]byte(nil), b...)), nil
	default:
		return nil, fmt.Errorf("invalid Ed25519 private key length: got %d, expected %d (seed) or %d (expanded)", len(b), ed25519SeedLen, ed25519PrivKeyLen)
	}
}

// LoadEd25519PrivateKeyFromHex 从十六进制字符串加载 Ed25519 私钥
func LoadEd25519PrivateKeyFromHex(h string) (ed25519.PrivateKey, error) {
	if h == "" {
		return nil, fmt.Errorf("private key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	return LoadEd25519PrivateKey(b)
}

// LoadEd25519PrivateKeyFromBase64 从 Base64 字符串加载 Ed25519 私钥
func LoadEd25519PrivateKeyFromBase64(b64 string) (ed25519.PrivateKey, error) {
	if b64 == "" {
		return nil, fmt.Errorf("private key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid private key base64: %w", err)
	}
	return LoadEd25519PrivateKey(b)
}

// LoadEd25519PublicKey 从字节数组加载 Ed25519 公钥（32 字节），并校验是否为合法曲线编码点。
// 借助 crypto/ed25519.VerifyWithOptions 在验签路径上调用内部 NewPublicKey；非“坏公钥”类错误视为公钥格式合法。
func LoadEd25519PublicKey(b []byte) (ed25519.PublicKey, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("public key data is empty")
	}
	if len(b) != ed25519PubKeyLen {
		return nil, fmt.Errorf("invalid Ed25519 public key length: got %d, expected %d", len(b), ed25519PubKeyLen)
	}
	dummySig := make([]byte, ed25519SigLen)
	err := ed25519.VerifyWithOptions(b, []byte{0}, dummySig, &ed25519.Options{Hash: crypto.Hash(0)})
	if err != nil && isEd25519BadPublicKeyError(err) {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	return ed25519.PublicKey(append([]byte(nil), b...)), nil
}

func isEd25519BadPublicKeyError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "ed25519: bad public key")
}

// LoadEd25519PublicKeyFromHex 从十六进制字符串加载 Ed25519 公钥
func LoadEd25519PublicKeyFromHex(h string) (ed25519.PublicKey, error) {
	if h == "" {
		return nil, fmt.Errorf("public key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	return LoadEd25519PublicKey(b)
}

// LoadEd25519PublicKeyFromBase64 从 Base64 字符串加载 Ed25519 公钥
func LoadEd25519PublicKeyFromBase64(b64 string) (ed25519.PublicKey, error) {
	if b64 == "" {
		return nil, fmt.Errorf("public key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key base64: %w", err)
	}
	return LoadEd25519PublicKey(b)
}

// GetEd25519PublicKeyBytes 获取 Ed25519 公钥的 32 字节拷贝
func GetEd25519PublicKeyBytes(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519PubKeyLen {
		return nil, fmt.Errorf("invalid Ed25519 public key length: got %d, expected %d", len(pub), ed25519PubKeyLen)
	}
	return append([]byte(nil), pub...), nil
}

// GetEd25519PublicKeyBytesUnsafe 获取 Ed25519 公钥字节切片（与 pub 共享底层数组，只读场景或已确认安全时使用）
func GetEd25519PublicKeyBytesUnsafe(pub ed25519.PublicKey) []byte {
	return pub
}

// GetEd25519PrivateKeyBytes 获取 Ed25519 扩展私钥的 64 字节拷贝。
// 不再使用返回切片时可调用 SecureZeroBytes。
func GetEd25519PrivateKeyBytes(prk ed25519.PrivateKey) ([]byte, error) {
	if len(prk) != ed25519PrivKeyLen {
		return nil, fmt.Errorf("invalid Ed25519 private key length: got %d, expected %d", len(prk), ed25519PrivKeyLen)
	}
	return append([]byte(nil), prk...), nil
}

// GetEd25519PrivateKeyBytesUnsafe 返回私钥底层切片引用（勿修改；性能敏感场景）
func GetEd25519PrivateKeyBytesUnsafe(prk ed25519.PrivateKey) []byte {
	return prk
}

// SignEd25519 使用 Ed25519 私钥对消息签名（标准 Ed25519，64 字节签名）。
// 私钥可为 32 字节种子或 64 字节扩展形式；32 字节时内部会先展开再调用标准库 Sign（因 crypto/ed25519.Sign 要求 64 字节）。
func SignEd25519(privateKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	switch len(privateKey) {
	case ed25519SeedLen:
		expanded := ed25519.NewKeyFromSeed(privateKey)
		sig := ed25519.Sign(expanded, message)
		SecureZeroBytes(expanded)
		return sig, nil
	case ed25519PrivKeyLen:
		return ed25519.Sign(privateKey, message), nil
	default:
		return nil, fmt.Errorf("invalid private key length: got %d, expected %d (seed) or %d (expanded)", len(privateKey), ed25519SeedLen, ed25519PrivKeyLen)
	}
}

// DeriveEd25519PublicKey 从 32 字节种子或 64 字节扩展私钥派生公钥。
// crypto/ed25519.PrivateKey.Public() 已对后缀做拷贝；此处直接返回该切片，避免二次分配。
// 注意：32 字节种子需先 NewKeyFromSeed，展开得到的临时扩展私钥会在返回前被 SecureZeroBytes。
func DeriveEd25519PublicKey(privateKey ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	switch len(privateKey) {
	case ed25519SeedLen:
		expanded := ed25519.NewKeyFromSeed(privateKey)
		pub := expanded.Public().(ed25519.PublicKey)
		SecureZeroBytes(expanded)
		return pub, nil
	case ed25519PrivKeyLen:
		return privateKey.Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("invalid private key length: got %d, expected %d (seed) or %d (expanded)", len(privateKey), ed25519SeedLen, ed25519PrivKeyLen)
	}
}

// VerifyEd25519 使用 Ed25519 公钥验证签名
func VerifyEd25519(publicKey ed25519.PublicKey, message, signature []byte) error {
	if publicKey == nil {
		return fmt.Errorf("public key cannot be nil")
	}
	if len(publicKey) != ed25519PubKeyLen {
		return fmt.Errorf("invalid public key length: got %d, expected %d", len(publicKey), ed25519PubKeyLen)
	}
	if len(signature) != ed25519SigLen {
		return fmt.Errorf("invalid signature length: got %d, expected %d", len(signature), ed25519SigLen)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("signature verification failed: does not match message or public key")
	}
	return nil
}

// Ed25519PublicKeyToHex 将 Ed25519 公钥转为十六进制字符串
func Ed25519PublicKeyToHex(pub ed25519.PublicKey) (string, error) {
	b, err := GetEd25519PublicKeyBytes(pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Ed25519PrivateKeyToHex 将 Ed25519 扩展私钥转为十六进制字符串
func Ed25519PrivateKeyToHex(prk ed25519.PrivateKey) (string, error) {
	b, err := GetEd25519PrivateKeyBytes(prk)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Ed25519PublicKeyToBase64 将 Ed25519 公钥转为 Base64 字符串
func Ed25519PublicKeyToBase64(pub ed25519.PublicKey) (string, error) {
	b, err := GetEd25519PublicKeyBytes(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Ed25519PrivateKeyToBase64 将 Ed25519 扩展私钥转为 Base64 字符串
func Ed25519PrivateKeyToBase64(prk ed25519.PrivateKey) (string, error) {
	b, err := GetEd25519PrivateKeyBytes(prk)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
