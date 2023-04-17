package ecc

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestECCSignAndVerify(t *testing.T) {
	prkHex := `30770201010420c9091b7a0bf23754eac17e498ccc6d53b6c9dfd9c543afadc51dd1fdcd028ec7a00a06082a8648ce3d030107a14403420004859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	pubHex := `04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	prk, _ := LoadHexPrivateKey(prkHex)
	pub, _, _ := LoadHexPublicKey(pubHex)
	sign, err := Sign(prk, testMsg)
	if err != nil {
		panic(err)
	}
	fmt.Println("sign: ", hex.EncodeToString(sign))
	verify := Verify(pub, testMsg, sign)
	fmt.Println("verify: ", verify)
}

func BenchmarkECCSign(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	prkHex := `30770201010420c9091b7a0bf23754eac17e498ccc6d53b6c9dfd9c543afadc51dd1fdcd028ec7a00a06082a8648ce3d030107a14403420004859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	prk, _ := LoadHexPrivateKey(prkHex)
	for i := 0; i < b.N; i++ { //use b.N for looping
		_, err := Sign(prk, testMsg)
		if err != nil {
			panic(err)
		}
		//fmt.Println("sign: ", hex.EncodeToString(sign))
	}
}

func BenchmarkECCVerify(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	prkHex := `30770201010420c9091b7a0bf23754eac17e498ccc6d53b6c9dfd9c543afadc51dd1fdcd028ec7a00a06082a8648ce3d030107a14403420004859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	prk, _ := LoadHexPrivateKey(prkHex)
	sign, err := Sign(prk, testMsg)
	if err != nil {
		panic(err)
	}
	pubHex := `04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58`
	pub, _, _ := LoadHexPublicKey(pubHex)
	for i := 0; i < b.N; i++ { //use b.N for looping
		_ = Verify(pub, testMsg, sign)
		//fmt.Println("verify: ", verify)
	}
}
