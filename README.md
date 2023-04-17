# eccrypto
ecdsa p256 ecies

#### 1. 创建ECDSA P256公钥和私钥
```
CreateECDSA() (*ecdsa.PrivateKey, error)
```
#### 2. 加载Hex私钥
```
LoadHexPrivateKey(h string) (*ecdsa.PrivateKey, error)
```
#### 3. 加载Hex公钥
```
LoadHexPublicKey(h string) (*ecdsa.PublicKey, []byte, error)
```
#### 4. 加载Base64公钥
```
LoadHexPublicKey(h string) (*ecdsa.PublicKey, []byte, error)
```
### 5. 通过私钥和公钥生成协商密钥
```
GenSharedKey(ownerPrk *ecdsa.PrivateKey, otherPub *ecdsa.PublicKey) ([]byte, error)
```
### 6. 通过私钥和公钥生成协商密钥
```
GenSharedKey(ownerPrk *ecdsa.PrivateKey, otherPub *ecdsa.PublicKey) ([]byte, error)
```
### 7. 通过公钥生成协商密钥并加密数据
```
Encrypt(publicTo, message []byte) ([]byte, error)
```
### 8. 通过私钥生成协商密钥并解密数据
```
Decrypt(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error)
```
### 9. 通过私钥和公钥生成协商密钥
```
GenSharedKey(ownerPrk *ecdsa.PrivateKey, otherPub *ecdsa.PublicKey) ([]byte, error)
```
### 10. 通过私钥签名数据
```
Sign(prk *ecdsa.PrivateKey, msg []byte) ([]byte, error)
```
### 11. 通过公钥验签数据
```
Verify(pub *ecdsa.PublicKey, msg, sign []byte) bool
```