# eccrypto
ecc secp256k1 crypto

### 1. CreateHexKey() (string, string, error) 创建secp256k1公钥和私钥
### 2. LoadHexKey(priHex, pubHex string) (*ecies.PrivateKey, error) 加载secp256k1公钥和私钥
### 3. Encrypt(pub ecies.PublicKey, msg []byte) (string, error) 通过公钥加密数据返回Base64字符串
### 4. Decrypt(prk *ecies.PrivateKey, msg string) (string, error) 通过私钥解密Base64字符串返回明文

## 性能测试
```
goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkEncryptAndDecrypt
BenchmarkEncryptAndDecrypt-12               3061            392791 ns/op
PASS
```