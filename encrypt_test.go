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
	//prkHex := `30770201010420c9091b7a0bf23754eac17e498ccc6d53b6c9dfd9c543afadc51dd1fdcd028ec7a00a06082a8648ce3d030107a14403420004859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	//prk, err := LoadHexPrivateKey(prkHex)

	key := []byte("123456")

	_, pubBs, _ := GetObjectBytes(prk, &prk.PublicKey)
	r, err := Encrypt(pubBs, testMsg, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("加密数据: ", base64.StdEncoding.EncodeToString(r))
	r2, err := DecryptObject(prk, r, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密数据: ", string(r2.Plaintext))
}

func TestECCDecrypt(t *testing.T) {
	prkHex := `30770201010420c9091b7a0bf23754eac17e498ccc6d53b6c9dfd9c543afadc51dd1fdcd028ec7a00a06082a8648ce3d030107a14403420004859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	//pubHex := `04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	data := `BH8/UnFuC+vRqYC7r/j9QrbjBs4kFTWbJAHHX5edwdHmHIpXsp1cznwYmXE532A9V3hIEidPnuzNiSRRHYrp2N/sBw7f8i912i8kclGyp3QxMTY4ODYzMzU3Nvq4UU+fs85rQV02MtOr7TRXux0we2c1guukKt6j8PdnVlOf1SMyEU9D2U2iEuCJaAQ/r+AVKBKmT1/jtFCYx9sUaimOqKNZ+yWF3TEXXkw9`
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
	a, err := Encrypt(pubHex, testMsg)
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
		_, err := Encrypt(pub, testMsg)
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
	r, err := Encrypt(pub, testMsg)
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
