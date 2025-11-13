# eccrypto

ECDH P256 ECIES (Elliptic Curve Integrated Encryption Scheme)

## ECDH Functions (Recommended)

#### 1. Create ECDH privateKey and publicKey

```
CreateECDH() (*ecdh.PrivateKey, error)
```

#### 2. Load ECDH privateKey by hex

```
LoadHexECDHPrivateKey(h string) (*ecdh.PrivateKey, error)
```

#### 3. Load ECDH privateKey by base64

```
LoadBase64ECDHPrivateKey(h string) (*ecdh.PrivateKey, error)
```

#### 4. Get ECDH publicKey bytes

```
GetECDHPublicKeyBytes(pub ecdh.PublicKey) []byte
```

### 5. Generate shared key using ECDH

```
GenSharedKeyECDH(ownerPrk *ecdh.PrivateKey, otherPub *ecdh.PublicKey) ([]byte, error)
```

### 6. Encrypt plaintext using ECDH

```
Encrypt(inputPrk *ecdh.PrivateKey, publicTo, message, additionalData []byte) ([]byte, error)
```

### 7. Decrypt ciphertext using ECDH

```
Decrypt(privateKey *ecdh.PrivateKey, msg, additionalData []byte) ([]byte, error)
```

## Performance Benchmarks

### Performance Comparison (Go 1.20, Intel i5-13600KF)

#### ECDH (Recommended - Modern & Fast)

```
BenchmarkECDHCreate-20        9,023,166     266.6 ns/op
BenchmarkECDHSharedKey-20        66,362    35,975 ns/op
BenchmarkECDHEncrypt-20          64,539    36,884 ns/op
BenchmarkECDHDecrypt-20          65,425    36,675 ns/op
```

### Security Notes

- **ECDH**: Uses crypto/ecdh package (Go 1.20+), providing modern, secure key exchange
- **Performance**: Significantly faster than legacy implementations
- **Compatibility**: Fully compatible with TypeScript elliptic.js library
- **Security**: ECDH provides strong security guarantees for key exchange and encryption
- **Note**: ECDH does not support digital signatures - use ECDSA for signing/verification
