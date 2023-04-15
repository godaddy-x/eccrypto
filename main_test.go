package ecc

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	testMsg       = []byte("我是中国人,test!!!")
	privateKeyHex = `f6711d1c0d38b294a95b108fe89e2fef523cc83fe8c2c8448dc7a9c0c38aa059`
	publicKeyHex  = `04a1a1bb7d6f60aa74a4df5db9ded28bf60401070f91091256744e65f2a6c918f1dc312bbb9729879acb57c83085a2759bfe89a0c40b64137e1ea8746070e7541e`
)

func TestCreateKey(t *testing.T) {
	prk, pub, _ := CreateHexKey()
	fmt.Println("私钥hex: ", prk)
	fmt.Println("公钥hex: ", pub)
}

func TestLoadKey(t *testing.T) {
	prk, err := LoadHexKey(privateKeyHex, publicKeyHex)
	if err != nil {
		panic(err)
	}
	fmt.Println("还原后私钥hex: ", hex.EncodeToString(prk.D.Bytes()))
	publicKeyHex := elliptic.Marshal(prk.Curve, prk.PublicKey.X, prk.PublicKey.Y)
	fmt.Println("还原后公钥hex: ", hex.EncodeToString(publicKeyHex))
}

func TestEncryptAndDecrypt(t *testing.T) {
	prk, err := LoadHexKey(privateKeyHex, publicKeyHex)
	if err != nil {
		panic(err)
	}
	ct, err := Encrypt(&prk.PublicKey, testMsg)
	fmt.Println("加密结果: ", ct)
	ct2, err := Decrypt(prk, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密结果: ", ct2)
}

func TestEncrypt(t *testing.T) {
	prk, err := LoadHexKey(privateKeyHex, publicKeyHex)
	if err != nil {
		panic(err)
	}
	ct, err := Encrypt(&prk.PublicKey, testMsg)
	if err != nil {
		panic(err)
	}
	fmt.Println("加密结果: ", ct)
}

func TestDecrypt(t *testing.T) {
	prk, err := LoadHexKey(privateKeyHex, publicKeyHex)
	if err != nil {
		panic(err)
	}
	//msg := `BIuYCEbN0SmuX4LfVlgehwxVA5RiLou/N+CmxVa2PBk6euJH51agVfxWlhTXyg2Bfl+xKN1DrueoS4OQY033LgBtpqRaMPmTQxaOP2dxyQeRI0GnHRsojGPZQZksWe8Rkn+rZaRJbFgpwVVrUwcKZ1TpnJdDZVxshqytwRshxCpfbTZl5XyOkWZF92EMzwQtytwuC6xcf+lLS2omR3cVXH0=`
	msg := `BDgcT7waxivyXZPYaYzx8PVPdTkyagFmyoOej3yp103QgIG4zszAOxivcDW1z7SUzErcIfSn66OkmU2gZh91QhaO7o3HLxW6VPDWlMcjRCbPWeVtgVE3FnH8KQWVTUrEANZdHiE0myyQasUE/umrgxNPghEkg6kNWKbal1Mkbh1pJA+OGvB3G7GOW89OaCDhlfA0EOA8A+8Aim+3eSnOp25tVJbIafEGam9KCYNbtley`
	ct, err := Decrypt(prk, msg)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密结果: ", ct)
}

var (
	prk, _ = LoadHexKey(privateKeyHex, publicKeyHex)
)

func BenchmarkEncrypt(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	server, err := LoadHexKey(privateKeyHex, publicKeyHex)
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ { //use b.N for looping
		_, err = Encrypt(&server.PublicKey, testMsg)
		if err != nil {
			panic(err)
		}
		//fmt.Println("加密结果: ", ct)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	server, err := LoadHexKey(privateKeyHex, publicKeyHex)
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ { //use b.N for looping
		msg := `BIuYCEbN0SmuX4LfVlgehwxVA5RiLou/N+CmxVa2PBk6euJH51agVfxWlhTXyg2Bfl+xKN1DrueoS4OQY033LgBtpqRaMPmTQxaOP2dxyQeRI0GnHRsojGPZQZksWe8Rkn+rZaRJbFgpwVVrUwcKZ1TpnJdDZVxshqytwRshxCpfbTZl5XyOkWZF92EMzwQtytwuC6xcf+lLS2omR3cVXH0=`
		_, err = Decrypt(server, msg)
		if err != nil {
			panic(err)
		}
		//fmt.Println("解密结果: ", ct)
	}
}
