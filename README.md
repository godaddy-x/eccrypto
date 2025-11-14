# eccrypto

ECDH P256 ECIES (Elliptic Curve Integrated Encryption Scheme)

## ECDH Functions (Recommended)

Located in `ecdh.go` - Complete ECDH encryption module

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

## ECDSA Digital Signature Functions

Located in `ecdsa.go` - ECDSA digital signature module

#### 8. Create ECDSA private key and public key

```
CreateECDSA() (*ecdsa.PrivateKey, error)
```

#### 9. Sign message using ECDSA

```
SignECDSA(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error)
```

Returns DER-encoded ASN.1 signature.

#### 10. Verify signature using ECDSA

```
VerifyECDSA(publicKey *ecdsa.PublicKey, message, signature []byte) error
```

#### 11. Load ECDSA private key from bytes/hex/base64

```
LoadECDSAPrivateKey(b []byte) (*ecdsa.PrivateKey, error)
LoadECDSAPrivateKeyFromHex(h string) (*ecdsa.PrivateKey, error)
LoadECDSAPrivateKeyFromBase64(b64 string) (*ecdsa.PrivateKey, error)
```

#### 12. Load ECDSA public key from bytes/hex/base64

```
LoadECDSAPublicKey(b []byte) (*ecdsa.PublicKey, error)
LoadECDSAPublicKeyFromHex(h string) (*ecdsa.PublicKey, error)
LoadECDSAPublicKeyFromBase64(b64 string) (*ecdsa.PublicKey, error)
```

#### 13. Get ECDSA key bytes

```
GetECDSAPublicKeyBytes(pub ecdsa.PublicKey) []byte
GetECDSAPrivateKeyBytes(prk *ecdsa.PrivateKey) []byte
```

## Performance Benchmarks

### Performance Comparison (Go 1.20, Intel i5-13600KF)

#### ECDH (Recommended - Modern & Fast)

```
BenchmarkECDHCreate-20        9,023,166     266.6 ns/op
BenchmarkECDHSharedKey-20        66,362    35,975 ns/op
BenchmarkECDHEncrypt-20          64,539    36,884 ns/op
BenchmarkECDHDecrypt-20          65,425    36,675 ns/op
BenchmarkECDSASign-20            71,407    16,896 ns/op
BenchmarkECDSAVerify-20          23,914    48,851 ns/op
```

### Security Notes

- **ECDH**: Uses crypto/ecdh package (Go 1.20+), providing modern, secure key exchange
- **ECDSA**: Uses crypto/ecdsa package with P-256 curve, providing standard digital signatures
- **Performance**: ECDH is optimized for key exchange; ECDSA provides fast signing/verification
- **Compatibility**: Fully compatible with TypeScript elliptic.js library
- **Security**: Both ECDH and ECDSA provide strong cryptographic security guarantees
- **Usage**: Use ECDH for encryption key exchange, ECDSA for digital signatures
