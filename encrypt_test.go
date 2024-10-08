package ecc

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	testMsg = []byte("我是中国人梵蒂冈啊!!!ABC@#")
)

func TestCreateECDSA(t *testing.T) {
	prk, _ := CreateECDSA()
	prkS, pubS, err := GetObjectBase64(prk, &prk.PublicKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("私钥Base64: ", prkS)
	fmt.Println("公钥Base64: ", pubS)
}

func TestECCEncrypt(t *testing.T) {
	prk, _ := CreateECDSA() // 服务端
	prkBs, pubBs, _ := GetObjectBytes(prk, &prk.PublicKey)
	r, err := Encrypt(prk, pubBs, testMsg)
	if err != nil {
		panic(err)
	}
	fmt.Println("私钥hex: ", hex.EncodeToString(prkBs))
	fmt.Println("加密数据: ", base64.StdEncoding.EncodeToString(r))
	r2, err := Decrypt(prk, r)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密数据: ", string(r2))
}

func TestECCDecrypt(t *testing.T) {
	prkHex := `307702010104208b80119ad032d89cd53dc4ba0f1031f5d7db77b15b6009f4cb190447937fb6d2a00a06082a8648ce3d030107a14403420004f0f462f88d000b77832307e206518e12279f57a21b5b273b6548cd9e5690196f88cdb1bd4c42088ba247417c30d6d40346a0b55619e4e7d2f56e386e548ad143`
	//pubHex := `04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	data := `BLTGfDj2m1ICK9Ll4gkmfIwXBlt5OBL2SECsh2869BJaM6kXR2moOYzsHsC0WcBkwmaxg8EBNpgWcsjLvICVC4iJ6PXAUKm+QmQcMdKf3DEfJn3Oh4JkvtNX3xt0Mxl5qAqhhGirGlq507GMUTC8PAv6IrrmA7XFp2Eem2z0hAPzkXcIbXREZ+OQ926K4ujagPTR9KXe+oTPxrVeeSG4nQU=`
	msg, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	prk, err := LoadHexPrivateKey(prkHex)
	r2, err := Decrypt(prk, msg)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("解密数据: ", string(r2))
	fmt.Println(hex.EncodeToString(r2))
}

func TestECDSASharedKey(t *testing.T) {
	prkHex := `30770201010420c9091b7a0bf23754eac17e498ccc6d53b6c9dfd9c543afadc51dd1fdcd028ec7a00a06082a8648ce3d030107a14403420004859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	//pubHex := `04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	prk, err := LoadHexPrivateKey(prkHex)
	if err != nil {
		panic(err)
	}
	pubHex, _ := hex.DecodeString(`04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`)
	pub, err := LoadPublicKey(pubHex)
	if err != nil {
		panic(err)
	}
	sharedKey, err := GenSharedKey(prk, pub)
	if err != nil {
		panic(err)
	}
	fmt.Println("共享密钥: ", string(sharedKey))
	a, err := Encrypt(nil, pubHex, testMsg)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(a))
}

func BenchmarkECDSACreate(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ { //use b.N for looping
		_, err := CreateECDSA()
		if err != nil {
			panic(err)
		}
		//fmt.Println(prk)
	}
}

func BenchmarkECCSharedKey(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	prkHex := `30770201010420c9091b7a0bf23754eac17e498ccc6d53b6c9dfd9c543afadc51dd1fdcd028ec7a00a06082a8648ce3d030107a14403420004859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	//pubHex := `04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	prk, err := LoadHexPrivateKey(prkHex)
	if err != nil {
		panic(err)
	}
	pubHex, _ := hex.DecodeString(`04c23d77f56b60d7ae07b618d794eddfc6461a841cee4b273d20dbcda73683a7345bca10f0844d2dcd92fd5546333463cff1beb88bd786d830452f0c60e1ede219`)
	pub, err := LoadPublicKey(pubHex)
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ { //use b.N for looping
		_, err := GenSharedKey(prk, pub)
		if err != nil {
			panic(err)
		}
		//fmt.Println("共享密钥: ", string(sharedKey))
	}
}

func BenchmarkECDSAEncrypt(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	prk, _ := CreateECDSA() // 服务端
	pub, _ := GetPublicKeyBytes(&prk.PublicKey)
	for i := 0; i < b.N; i++ { //use b.N for looping
		_, err := Encrypt(nil, pub, testMsg)
		if err != nil {
			panic(err)
		}
		//fmt.Println("加密数据: ", base64.StdEncoding.EncodeToString(r))
	}
}

func BenchmarkECCDecrypt(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	prk, _ := CreateECDSA() // 服务端
	pub, _ := GetPublicKeyBytes(&prk.PublicKey)
	r, err := Encrypt(nil, pub, testMsg)
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ { //use b.N for looping
		_, err := Decrypt(prk, r)
		if err != nil {
			panic(err)
		}
		//fmt.Println("解密数据: ", string(r2))
	}
}
