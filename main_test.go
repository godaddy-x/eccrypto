package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/godaddy-x/eccrypto/crypto/ecies"
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
	ct, err := Encrypt(prk.PublicKey, testMsg)
	fmt.Println("加密结果: ", ct)
	ct2, err := Decrypt(prk, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密结果: ", ct2)
}

var (
	prk, _ = LoadHexKey(privateKeyHex, publicKeyHex)
)

func BenchmarkEncryptAndDecrypt(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	prk, err := LoadHexKey(privateKeyHex, publicKeyHex)
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ { //use b.N for looping
		ct, err := ecies.Encrypt(rand.Reader, &prk.PublicKey, testMsg, nil, nil)
		if err != nil {
			panic(err)
		}
		//fmt.Println("加密结果: ", hex.EncodeToString(ct))
		_, err = prk.Decrypt(ct, nil, nil)
		if err != nil {
			panic(err)
		}
		//fmt.Println("解密结果: ", string(ct2))
	}
}
