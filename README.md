# eccrypto
ecc secp256k1 crypto

#### 1. 创建secp256k1公钥和私钥
```
CreateHexKey() (string, string, error)
```
#### 2. 加载secp256k1公钥和私钥
```
LoadHexKey(priHex, pubHex string) (*ecies.PrivateKey, error)
```
#### 3. 通过公钥加密数据返回Base64字符串
```
Encrypt(pub ecies.PublicKey, msg []byte) (string, error)
```
#### 4. 通过私钥解密Base64字符串返回明文
```
Decrypt(prk *ecies.PrivateKey, msg string) (string, error)
```

## 性能测试
```
func BenchmarkEncryptAndDecrypt(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ { //use b.N for looping
		ct, err := Encrypt(prk.PublicKey, testMsg)
		if err != nil {
			panic(err)
		}
		_, err = Decrypt(prk, ct)
		if err != nil {
			panic(err)
		}
	}
}

goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkEncryptAndDecrypt
BenchmarkEncryptAndDecrypt-12               3061            392791 ns/op
PASS
```