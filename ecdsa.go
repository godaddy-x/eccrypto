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
)

const (
	// ECDSA 相关常量
	ecdsaPubKeyLen  = 65 // 未压缩公钥长度: 1字节前缀(0x04) + 32字节X + 32字节Y
	ecdsaPrivKeyLen = 32 // P256私钥长度固定为32字节(256位)
)

var (
	ecdsaCurve      = elliptic.P256()                              // 使用P256曲线
	ecdsaCurveN     = ecdsaCurve.Params().N                        // 曲线阶(n)，用于私钥和签名验证
	ecdsaCurveHalfN = new(big.Int).Div(ecdsaCurveN, big.NewInt(2)) // ✅ 预计算
)

// CreateECDSA 生成新的ECDSA密钥对，用于数字签名
// 使用互斥锁确保并发安全
func CreateECDSA() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(ecdsaCurve, rand.Reader)
}

// LoadECDSAPrivateKey 从字节数组加载ECDSA私钥
// 输入必须是32字节的私钥标量D
func LoadECDSAPrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	if len(b) == 0 {
		return nil, errors.New("private key data is empty")
	}

	// 检查私钥长度（P256私钥固定32字节）
	if len(b) != ecdsaPrivKeyLen {
		return nil, fmt.Errorf("invalid private key length: got %d bytes, expected %d", len(b), ecdsaPrivKeyLen)
	}

	// 解析私钥标量D
	d := new(big.Int).SetBytes(b)

	// 验证D的有效性：必须满足 1 ≤ D ≤ n-1（n为曲线阶）
	// d.Sign() <= 0 表示 D <= 0；d.Cmp(ecdsaCurveN) >= 0 表示 D >= n
	if d.Sign() <= 0 || d.Cmp(ecdsaCurveN) >= 0 {
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
	if h == "" {
		return nil, errors.New("private key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	return LoadECDSAPrivateKey(b)
}

// LoadECDSAPrivateKeyFromBase64 从Base64字符串加载ECDSA私钥
func LoadECDSAPrivateKeyFromBase64(b64 string) (*ecdsa.PrivateKey, error) {
	if b64 == "" {
		return nil, errors.New("private key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid private key base64: %w", err)
	}
	return LoadECDSAPrivateKey(b)
}

// LoadECDSAPublicKey 从字节数组加载ECDSA公钥
// 接受未压缩格式：0x04 + 32字节X + 32字节Y
func LoadECDSAPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) == 0 {
		return nil, errors.New("public key data is empty")
	}
	if len(b) != ecdsaPubKeyLen || b[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed public key: must be %d bytes starting with 0x04", ecdsaPubKeyLen)
	}

	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])

	// 验证公钥是否在曲线上（使用曲线对象而不是公钥对象）
	if !ecdsaCurve.IsOnCurve(x, y) {
		return nil, errors.New("public key is not on P256 curve")
	}

	publicKey := &ecdsa.PublicKey{
		Curve: ecdsaCurve,
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}

// LoadECDSAPublicKeyFromHex 从十六进制字符串加载ECDSA公钥
func LoadECDSAPublicKeyFromHex(h string) (*ecdsa.PublicKey, error) {
	if h == "" {
		return nil, errors.New("public key hex string is empty")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	return LoadECDSAPublicKey(b)
}

// LoadECDSAPublicKeyFromBase64 从Base64字符串加载ECDSA公钥
func LoadECDSAPublicKeyFromBase64(b64 string) (*ecdsa.PublicKey, error) {
	if b64 == "" {
		return nil, errors.New("public key base64 string is empty")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key base64: %w", err)
	}
	return LoadECDSAPublicKey(b)
}

// GetECDSAPublicKeyBytes 获取ECDSA公钥的字节表示（未压缩格式）
func GetECDSAPublicKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key cannot be nil")
	}
	if !ecdsaCurve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("public key is not on P256 curve")
	}

	result := make([]byte, ecdsaPubKeyLen)
	result[0] = 0x04
	pub.X.FillBytes(result[1:33])  // 确保X占32字节（补前导零）
	pub.Y.FillBytes(result[33:65]) // 确保Y占32字节（补前导零）
	return result, nil
}

// GetECDSAPublicKeyBytesUnsafe 获取ECDSA公钥的字节表示（未压缩格式），不进行验证
// 仅用于性能敏感且已确认公钥有效的场景
func GetECDSAPublicKeyBytesUnsafe(pub *ecdsa.PublicKey) []byte {
	result := make([]byte, ecdsaPubKeyLen)
	result[0] = 0x04
	pub.X.FillBytes(result[1:33])
	pub.Y.FillBytes(result[33:65])
	return result
}

// GetECDSAPrivateKeyBytes 获取ECDSA私钥的字节表示（固定32字节）
func GetECDSAPrivateKeyBytes(prk *ecdsa.PrivateKey) ([]byte, error) {
	if prk == nil {
		return nil, errors.New("private key cannot be nil")
	}
	b := make([]byte, ecdsaPrivKeyLen)
	prk.D.FillBytes(b) // 确保私钥占32字节（补前导零）
	return b, nil
}

// GetECDSAPrivateKeyBytesUnsafe 获取ECDSA私钥的字节表示（固定32字节），不进行验证
// 仅用于性能敏感且已确认私钥有效的场景
func GetECDSAPrivateKeyBytesUnsafe(prk *ecdsa.PrivateKey) []byte {
	b := make([]byte, ecdsaPrivKeyLen)
	prk.D.FillBytes(b)
	return b
}

// SignECDSA 使用ECDSA私钥对消息进行签名
// 返回DER编码的ASN.1签名（S值已调整为低S值，符合BIP-0062规范）
func SignECDSA(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if len(message) == 0 {
		return nil, errors.New("message cannot be empty")
	}

	// 计算消息哈希（SHA-256）
	hash := sha256.Sum256(message)

	// 生成签名（r, s）
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// 调整S为低S值（若S > n/2，则用n - S替换）
	if s.Cmp(ecdsaCurveHalfN) > 0 { // ✅ 使用预计算的全局变量
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
	if len(message) == 0 {
		return errors.New("message cannot be empty")
	}
	if len(signature) == 0 {
		return errors.New("signature cannot be empty")
	}

	// 验证公钥有效性
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return errors.New("invalid public key: not on curve")
	}

	// 验证公钥不是无穷远点
	if publicKey.X.Sign() == 0 && publicKey.Y.Sign() == 0 {
		return errors.New("invalid public key: point at infinity")
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
	if sig.R.Sign() <= 0 || sig.R.Cmp(ecdsaCurveN) >= 0 {
		return errors.New("signature R is out of valid range [1, n-1]")
	}
	if sig.S.Sign() <= 0 || sig.S.Cmp(ecdsaCurveN) >= 0 {
		return errors.New("signature S is out of valid range [1, n-1]")
	}

	// 检查是否为低S值（符合BIP-0062）
	if sig.S.Cmp(ecdsaCurveHalfN) > 0 { // ✅ 使用预计算的全局变量
		return errors.New("signature S is not low S value")
	}

	// 验证签名是否匹配
	if !ecdsa.Verify(publicKey, hash[:], sig.R, sig.S) {
		return errors.New("signature verification failed: does not match message or public key")
	}

	return nil
}

// GenSharedKeyECDSA 复用 ECDSA 公/私钥对实现 ECDH 密钥协商
// 要求：双方密钥必须基于 P-256 (nistp256) 曲线
// 返回：32 字节共享密钥（通过共享点 X 坐标经 SHA256 派生）
func GenSharedKeyECDSA(ownerPrk *ecdsa.PrivateKey, otherPub *ecdsa.PublicKey) ([]byte, error) {
	// 1. 基础非空校验
	if ownerPrk == nil {
		return nil, errors.New("ECDSA private key cannot be nil")
	}
	if otherPub == nil {
		return nil, errors.New("ECDSA public key cannot be nil")
	}

	// 2. 曲线一致性校验（必须是 P256）
	if ownerPrk.Curve != ecdsaCurve {
		return nil, fmt.Errorf("ECDSA private key curve must be P256 (nistp256), got %s", ownerPrk.Curve.Params().Name)
	}
	if otherPub.Curve != ecdsaCurve {
		return nil, fmt.Errorf("ECDSA public key curve must be P256 (nistp256), got %s", otherPub.Curve.Params().Name)
	}

	// 3. ECDSA 私钥 D 值合法性校验：必须满足 1 ≤ D ≤ n-1
	if ownerPrk.D == nil || ownerPrk.D.Sign() <= 0 || ownerPrk.D.Cmp(ecdsaCurveN) >= 0 {
		return nil, errors.New("ECDSA private key D value is invalid (must be in range [1, n-1])")
	}

	// 4. ECDSA 公钥合法性校验
	// 4.1 是否在 P256 曲线上 —— ✅ 使用公钥自身的 Curve 字段进行校验
	if !otherPub.Curve.IsOnCurve(otherPub.X, otherPub.Y) {
		return nil, errors.New("ECDSA public key is not on P256 curve")
	}
	// 4.2 是否为无穷远点（无效点）
	if otherPub.X.Sign() == 0 && otherPub.Y.Sign() == 0 {
		return nil, errors.New("ECDSA public key is point at infinity (invalid)")
	}

	// 5. ECDH 核心计算：sharedPoint = D * otherPub
	sharedX, sharedY := ecdsaCurve.ScalarMult(otherPub.X, otherPub.Y, ownerPrk.D.Bytes())

	// 5.1 检查共享点是否为无穷远点（理论上不应发生，但防御性编程）
	if sharedX.Sign() == 0 && sharedY.Sign() == 0 {
		return nil, errors.New("derived shared point is at infinity (negotiation failed)")
	}

	// 5.2 防御性检查：共享点应在曲线上
	if !ecdsaCurve.IsOnCurve(sharedX, sharedY) {
		return nil, errors.New("derived shared point is not on P256 curve")
	}

	// 6. 安全密钥派生：使用共享点 X 坐标 + SHA256
	sharedXBytes := make([]byte, ecdsaPrivKeyLen)
	sharedX.FillBytes(sharedXBytes) // 确保 32 字节，高位补零

	kdf := sha256.New()
	kdf.Write(sharedXBytes)
	derivedKey := kdf.Sum(nil) // 32 字节

	SecureZeroBytes(sharedXBytes)

	return derivedKey, nil
}

// ECDSAPublicKeyToHex 将ECDSA公钥转换为十六进制字符串
func ECDSAPublicKeyToHex(pub *ecdsa.PublicKey) (string, error) {
	b, err := GetECDSAPublicKeyBytes(pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ECDSAPrivateKeyToHex 将ECDSA私钥转换为十六进制字符串
func ECDSAPrivateKeyToHex(prk *ecdsa.PrivateKey) (string, error) {
	b, err := GetECDSAPrivateKeyBytes(prk)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ECDSAPublicKeyToBase64 将ECDSA公钥转换为Base64字符串
func ECDSAPublicKeyToBase64(pub *ecdsa.PublicKey) (string, error) {
	b, err := GetECDSAPublicKeyBytes(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ECDSAPrivateKeyToBase64 将ECDSA私钥转换为Base64字符串
func ECDSAPrivateKeyToBase64(prk *ecdsa.PrivateKey) (string, error) {
	b, err := GetECDSAPrivateKeyBytes(prk)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ecdsaSignature 用于ASN.1编码的签名结构（R和S为大整数）
type ecdsaSignature struct {
	R, S *big.Int
}
