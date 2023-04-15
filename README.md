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
Encrypt(pub *ecies.PublicKey, msg []byte) (string, error)
```
#### 4. 通过私钥解密Base64字符串返回明文
```
Decrypt(prk *ecies.PrivateKey, msg string) (string, error)
```

## 数据加密性能测试
```
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

goos: darwin
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz
BenchmarkEncrypt
BenchmarkEncrypt-8   	    8632	    145256 ns/op
PASS
```

## 数据解密性能测试
```
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
		//fmt.Println("解密结果: ", string(a))
	}
}

goos: darwin
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz
BenchmarkDecrypt
BenchmarkDecrypt-8   	   16538	     74126 ns/op
PASS
```

### JS版本交互
```
# yarn add eccrypto
import eccrypto from 'eccrypto'

const ECCEncrypt = async function () {
    // public key provided by the server
    const publicKey = Buffer.from('04a1a1bb7d6f60aa74a4df5db9ded28bf60401070f91091256744e65f2a6c918f1dc312bbb9729879acb57c83085a2759bfe89a0c40b64137e1ea8746070e7541e', 'hex')
    const message = Buffer.from('我是中国人,test!!!')
    // use the shared secret to encrypt the message using ECIES
    const encrypted = await eccrypto.encrypt(publicKey, message, {})
    // console.log(encrypted)
    console.log('iv: ', encrypted.iv.length, encrypted.iv.toString('hex'))
    console.log('ephemPublicKey: ', encrypted.ephemPublicKey.length, encrypted.ephemPublicKey.toString('hex'))
    console.log('ciphertext: ', encrypted.ciphertext.length, encrypted.ciphertext.toString('hex'))
    console.log('mac: ', encrypted.mac.length, encrypted.mac.toString('hex'))
    console.log('response: ', Buffer.concat([encrypted.ephemPublicKey, encrypted.iv, encrypted.mac, encrypted.ciphertext]).toString('base64'))
}
```