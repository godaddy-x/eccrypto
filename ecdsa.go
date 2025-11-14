package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

const (
	// ECDSA 相关常量
	ecdsaPubKeyLen  = 65 // 未压缩公钥长度: 1字节前缀(0x04) + 32字节X + 32字节Y
	ecdsaPrivKeyLen = 32 // P256私钥长度固定为32字节(256位)
)

var (
	ecdsaCurve       = elliptic.P256()       // 使用P256曲线
	ecdsaCurveN      = ecdsaCurve.Params().N // 曲线阶(n)，用于私钥和签名验证
	createECDSAMutex sync.Mutex              // 保护ECDSA密钥生成并发安全
)

// CreateECDSA 生成新的ECDSA密钥对，用于数字签名
// 使用互斥锁确保并发安全
func CreateECDSA() (*ecdsa.PrivateKey, error) {
	createECDSAMutex.Lock()
	defer createECDSAMutex.Unlock()
	return ecdsa.GenerateKey(ecdsaCurve, rand.Reader)
}

// LoadECDSAPrivateKey 从字节数组加载ECDSA私钥
// 输入必须是32字节的私钥标量D
func LoadECDSAPrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	// 检查私钥长度（P256私钥固定32字节）
	if len(b) != ecdsaPrivKeyLen {
		return nil, fmt.Errorf("invalid private key length: got %d bytes, expected %d", len(b), ecdsaPrivKeyLen)
	}

	// 解析私钥标量D
	d := new(big.Int).SetBytes(b)

	// 验证D的有效性：必须满足 1 ≤ D ≤ n-1（n为曲线阶）
	if d.Cmp(big.NewInt(1)) < 0 || d.Cmp(new(big.Int).Sub(ecdsaCurveN, big.NewInt(1))) > 0 {
		return nil, errors.New("private key D is out of valid range [1, n-1]")
	}

	// 创建私钥并计算公钥
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ecdsaCurve,
		},
		D: d,
	}
	privateKey.PublicKey.X, privateKey.PublicKey.Y = ecdsaCurve.ScalarBaseMult(d.Bytes())

	return privateKey, nil
}

// LoadECDSAPrivateKeyFromHex 从十六进制字符串加载ECDSA私钥
func LoadECDSAPrivateKeyFromHex(h string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	return LoadECDSAPrivateKey(b)
}

// LoadECDSAPrivateKeyFromBase64 从Base64字符串加载ECDSA私钥
func LoadECDSAPrivateKeyFromBase64(b64 string) (*ecdsa.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid private key base64: %w", err)
	}
	return LoadECDSAPrivateKey(b)
}

// LoadECDSAPublicKey 从字节数组加载ECDSA公钥
// 接受未压缩格式：0x04 + 32字节X + 32字节Y
func LoadECDSAPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != ecdsaPubKeyLen || b[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed public key: must be %d bytes starting with 0x04", ecdsaPubKeyLen)
	}

	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])

	publicKey := &ecdsa.PublicKey{
		Curve: ecdsaCurve,
		X:     x,
		Y:     y,
	}

	// 验证公钥是否在曲线上
	if !publicKey.IsOnCurve(x, y) {
		return nil, errors.New("public key is not on P256 curve")
	}

	return publicKey, nil
}

// LoadECDSAPublicKeyFromHex 从十六进制字符串加载ECDSA公钥
func LoadECDSAPublicKeyFromHex(h string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	return LoadECDSAPublicKey(b)
}

// LoadECDSAPublicKeyFromBase64 从Base64字符串加载ECDSA公钥
func LoadECDSAPublicKeyFromBase64(b64 string) (*ecdsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key base64: %w", err)
	}
	return LoadECDSAPublicKey(b)
}

// GetECDSAPublicKeyBytes 获取ECDSA公钥的字节表示（未压缩格式）
func GetECDSAPublicKeyBytes(pub ecdsa.PublicKey) []byte {
	result := make([]byte, ecdsaPubKeyLen)
	result[0] = 0x04
	pub.X.FillBytes(result[1:33])  // 确保X占32字节（补前导零）
	pub.Y.FillBytes(result[33:65]) // 确保Y占32字节（补前导零）
	return result
}

// GetECDSAPrivateKeyBytes 获取ECDSA私钥的字节表示（固定32字节）
func GetECDSAPrivateKeyBytes(prk *ecdsa.PrivateKey) []byte {
	b := make([]byte, ecdsaPrivKeyLen)
	prk.D.FillBytes(b) // 确保私钥占32字节（补前导零）
	return b
}

// SignECDSA 使用ECDSA私钥对消息进行签名
// 返回DER编码的ASN.1签名（S值已调整为低S值，符合BIP-0062规范）
func SignECDSA(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	// 计算消息哈希（SHA-256）
	hash := sha256.Sum256(message)

	// 生成签名（r, s）
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// 调整S为低S值（若S > n/2，则用n - S替换，避免签名重放风险）
	halfN := new(big.Int).Div(ecdsaCurveN, big.NewInt(2))
	if s.Cmp(halfN) > 0 {
		s.Sub(ecdsaCurveN, s)
	}

	// 编码为DER格式
	signature := ecdsaSignature{R: r, S: s}
	derBytes, err := asn1.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature to DER: %w", err)
	}

	return derBytes, nil
}

// VerifyECDSA 使用ECDSA公钥验证签名
func VerifyECDSA(publicKey *ecdsa.PublicKey, message, signature []byte) error {
	if publicKey == nil {
		return errors.New("public key cannot be nil")
	}
	if len(signature) == 0 {
		return errors.New("signature cannot be empty")
	}

	// 计算消息哈希（SHA-256）
	hash := sha256.Sum256(message)

	// 解析DER编码的签名
	var sig ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal DER signature: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("signature contains extra data after DER encoding")
	}

	// 验证R和S的有效性（必须在[1, n-1]范围内）
	if sig.R.Cmp(big.NewInt(1)) < 0 || sig.R.Cmp(new(big.Int).Sub(ecdsaCurveN, big.NewInt(1))) > 0 {
		return errors.New("signature R is out of valid range [1, n-1]")
	}
	if sig.S.Cmp(big.NewInt(1)) < 0 || sig.S.Cmp(new(big.Int).Sub(ecdsaCurveN, big.NewInt(1))) > 0 {
		return errors.New("signature S is out of valid range [1, n-1]")
	}

	// 验证签名是否匹配
	if !ecdsa.Verify(publicKey, hash[:], sig.R, sig.S) {
		return errors.New("signature verification failed: does not match message or public key")
	}

	return nil
}

// ecdsaSignature 用于ASN.1编码的签名结构（R和S为大整数）
type ecdsaSignature struct {
	R, S *big.Int
}
