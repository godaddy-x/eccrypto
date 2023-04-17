# eccrypto
ecdsa p256 ecies

#### 1. Create privateKey and publicKey by ECDSA
```
CreateECDSA() (*ecdsa.PrivateKey, error)
```
#### 2. Load privateKey by hex
```
LoadHexPrivateKey(h string) (*ecdsa.PrivateKey, error)
```
#### 3. Load publicKey by hex
```
LoadHexPublicKey(h string) (*ecdsa.PublicKey, []byte, error)
```
#### 4. Load publicKey by base64
```
LoadBase64PublicKey(h string) (*ecdsa.PublicKey, []byte, error)
```
### 5. Generate share key by privateKey and publicKey
```
GenSharedKey(ownerPrk *ecdsa.PrivateKey, otherPub *ecdsa.PublicKey) ([]byte, error)
```
### 6. Encrypt plaintext by publicKey
```
Encrypt(publicTo, message []byte) ([]byte, error)
```
### 7. Decrypt ciphertext by privateKey
```
Decrypt(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error)
```
### 8. Sign Data by privateKey
```
Sign(prk *ecdsa.PrivateKey, msg []byte) ([]byte, error)
```
### 9. Verify data by publicKey
```
Verify(pub *ecdsa.PublicKey, msg, sign []byte) bool
```

### Benchmark

```
// CreateECDSA
goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkECDSACreate
BenchmarkECDSACreate-12            94461             12089 ns/op
```

```
// GenSharedKey
goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkECCSharedKey
BenchmarkECCSharedKey-12           26563             44460 ns/op
```

```
// Encrypt
goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkECDSAEncrypt
BenchmarkECDSAEncrypt-12           19818             60096 ns/op
```

```
// Decrypt
goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkECCDecrypt
BenchmarkECCDecrypt-12             24715             48010 ns/op
```

```
// Sign
goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkECCSign
BenchmarkECCSign-12        57798             20354 ns/op
```

```
// Verify
goos: windows
goarch: amd64
pkg: github.com/godaddy-x/eccrypto
cpu: 12th Gen Intel(R) Core(TM) i5-12400F
BenchmarkECCVerify
BenchmarkECCVerify-12              19876             60247 ns/op
```



