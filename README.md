# eccrypto

Go helpers for **ECIES-style sealed messaging** (ECDH → HKDF-SHA256 → AES-GCM) on **P-256** and **X25519**, plus **ECDSA** and **Ed25519** signatures. All crypto uses the **standard library** (`crypto/ecdh`, `crypto/ecdsa`, `crypto/ed25519`, …).

## Contents

- [Module map](#module-map)
- [Sealed messaging (ECIES)](#sealed-messaging-ecies)
  - [P-256 — `ecdh.go`](#p-256--ecdhgo)
  - [X25519 — `ecdh_x25519.go`](#x25519--ecdh_x25519go)
- [ECDSA — `ecdsa.go`](#ecdsa--ecdsago)
- [Ed25519 — `ed25519.go`](#ed25519--ed25519go)
- [Benchmarks](#benchmarks)
- [Security & interoperability](#security--interoperability)

## Module map

| File | Role |
|------|------|
| `ecdh.go` | P-256 ECDH; `Encrypt` / `Decrypt`; protocol **`0x01`**; **65-byte** uncompressed public keys |
| `ecdh_x25519.go` | X25519 ECDH; `EncryptX25519` / `DecryptX25519`; protocol **`0x02`**; **32-byte** keys |
| `ecdsa.go` | P-256 ECDSA; DER signatures; includes `GenSharedKeyECDSA` (ECDH-style shared secret from ECDSA keys) |
| `ed25519.go` | Ed25519 sign/verify; 64-byte raw signatures (not DER) |
| `secure_zero.go` | `SecureZeroBytes` (used by several helpers) |

## Sealed messaging (ECIES)

Both stacks share the same **idea**: ephemeral (or supplied) sender key, ECDH with recipient public key, **HKDF-SHA256** to a 32-byte AES key, **AES-GCM** with random nonce. **They are not compatible on the wire** — use the decrypt function that matches the encrypt function and curve.

| | P-256 | X25519 |
|---|-------|--------|
| Version byte | `0x01` | `0x02` |
| Ephemeral pubkey in blob | 65 bytes (`0x04` ‖ X ‖ Y) | 32 bytes |
| HKDF `info` | `ecdh-aes-gcm-encryption:` | `ecdh-x25519-aes-gcm-encryption:` |
| Encrypt / Decrypt | `Encrypt`, `Decrypt` | `EncryptX25519`, `DecryptX25519` |

Blob layout: `[version:1][ephemeral public key][nonce ‖ ciphertext ‖ GCM tag]`.

### P-256 — `ecdh.go`

- **Create:** `CreateECDH() (*ecdh.PrivateKey, error)`
- **Load private:** `LoadECDHPrivateKey`, `LoadECDHPrivateKeyFromHex`, `LoadECDHPrivateKeyFromBase64`
- **Load public:** `LoadECDHPublicKey`, `…FromHex`, `…FromBase64` — input must be **65-byte** uncompressed SEC1 (`0x04` prefix)
- **Bytes:** `GetECDHPublicKeyBytes`, `GetECDHPrivateKeyBytes`
- **Shared secret (raw):** `GenSharedKeyECDH(ownerPrk, otherPub)`
- **Sealed message:** `Encrypt(inputPrk, publicTo, message, additionalData)` — `inputPrk` may be `nil` (ephemeral sender key)  
  `Decrypt(privateKey, msg, additionalData, dst)` — `dst` optional in-place buffer when `cap(dst)` is enough
- **Helpers:** `ECDHPublicKeyToHex` / `ECDHPrivateKeyToHex`, `…ToBase64`, `GetProtocolVersion()` → `0x01`, `ValidatePublicKey`

### X25519 — `ecdh_x25519.go`

Curve25519 per RFC 7748 via `crypto/ecdh.X25519()`. Key types are still `*ecdh.PrivateKey` / `*ecdh.PublicKey` but must be created through these APIs (not P-256).

- **Create:** `CreateX25519() (*ecdh.PrivateKey, error)`
- **Load private:** `LoadX25519PrivateKey`, `…FromHex`, `…FromBase64` — **32-byte** scalar encoding
- **Load public:** `LoadX25519PublicKey`, `…FromHex`, `…FromBase64` — **32-byte** Montgomery *u*; invalid encodings rejected by the stdlib
- **Bytes:** `GetX25519PublicKeyBytes`, `GetX25519PrivateKeyBytes`
- **Shared secret (raw):** `GenSharedKeyX25519`
- **Sealed message:** `EncryptX25519` / `DecryptX25519` — `publicTo` must be **32** bytes; only accepts version **`0x02`**
- **Helpers:** `X25519PublicKeyToHex` / `X25519PrivateKeyToHex`, `…ToBase64`, `GetX25519ProtocolVersion()` → `0x02`, `ValidateX25519PublicKey`

## ECDSA — `ecdsa.go`

Curve **P-256**. Signing hashes the message with **SHA-256**; signatures are **DER** (ASN.1), with **low-S** normalization for verification.

- **Create:** `CreateECDSA() (*ecdsa.PrivateKey, error)`
- **Sign / verify:** `SignECDSA`, `VerifyECDSA` — non-empty `message` required
- **Load private:** `LoadECDSAPrivateKey`, `…FromHex`, `…FromBase64` — **32-byte** scalar *d*
- **Load public:** `LoadECDSAPublicKey`, `…FromHex`, `…FromBase64` — **65-byte** uncompressed
- **Bytes:** `GetECDSAPublicKeyBytes`, `GetECDSAPrivateKeyBytes` (and `…Unsafe` variants in code)
- **Helpers:** `ECDSAPublicKeyToHex` / `ECDSAPrivateKeyToHex`, `…ToBase64`
- **ECDH from ECDSA keys:** `GenSharedKeyECDSA` — P-256 only; shared material derived from ECDH-style scalar mult + SHA-256

## Ed25519 — `ed25519.go`

Signing and verification via `crypto/ed25519`. **Not** for key exchange (use X25519 / P-256 ECDH above).

- **Create:** `CreateEd25519() (ed25519.PrivateKey, error)` — **64-byte** expanded private key (stdlib layout)
- **Sign / verify:** `SignEd25519`, `VerifyEd25519` — **64-byte** raw signature; **empty message allowed** (RFC 8032). `SignEd25519` accepts **32-byte seed** or **64-byte expanded** key (seeds expanded internally)
- **Derive public key:** `DeriveEd25519PublicKey` — use when the material may be **seed-only** (do not use `PrivateKey.Public()` on a 32-byte slice alone)
- **Load private:** `LoadEd25519PrivateKey`, `…FromHex`, `…FromBase64` — **32-byte seed** or **64-byte expanded**
- **Load public:** `LoadEd25519PublicKey`, `…FromHex`, `…FromBase64` — **32 bytes**; invalid curve points rejected
- **Bytes / encoding:** `GetEd25519PublicKeyBytes`, `GetEd25519PrivateKeyBytes`, `Ed25519…ToHex`, `Ed25519…ToBase64`  
  Minimal storage: keep **32-byte seed** and `LoadEd25519PrivateKey`; expanded 64-byte form must keep seed and suffix consistent if you generate signatures (stdlib signing uses both parts of the blob)

## Benchmarks

Approximate results (one machine: **Intel i5-13600KF**; P-256 / ECDSA rows historically **Go 1.20**; X25519 / Ed25519 refreshed with **`go test -run=^$ -bench='BenchmarkECDH|BenchmarkX25519|BenchmarkECDSA|BenchmarkEd25519' -benchmem`** — treat as order-of-magnitude only).

```
BenchmarkECDHCreate-20           ~9,000,000      ~267 ns/op
BenchmarkECDHSharedKey-20          ~66,000    ~36,000 ns/op
BenchmarkECDHEncrypt-20            ~64,000    ~37,000 ns/op
BenchmarkECDHDecrypt-20            ~65,000    ~37,000 ns/op
BenchmarkX25519Create-20           ~47,000    ~26,000 ns/op
BenchmarkX25519SharedKey-20        ~48,000    ~25,000 ns/op
BenchmarkX25519Encrypt-20          ~22,000    ~54,000 ns/op
BenchmarkECDSASign-20                ~71,000    ~17,000 ns/op
BenchmarkECDSAVerify-20              ~24,000    ~49,000 ns/op
BenchmarkEd25519Sign-20            ~96,000    ~12,500 ns/op
BenchmarkEd25519Verify-20          ~43,000    ~28,000 ns/op
```

## Security & interoperability

- **Algorithms** — P-256 and X25519 ECDH, P-256 ECDSA, and Ed25519 are implemented with **Go stdlib** primitives.
- **ECIES** — Do not decrypt P-256 blobs with `DecryptX25519` or vice versa; version byte and HKDF labels differ by design.
- **Signatures** — ECDSA uses DER + low-S checks; Ed25519 uses **64-byte raw** signatures. Peers must agree on algorithm and encoding.
- **P-256 public keys** in this package’s ECDH helpers follow **uncompressed SEC1** (65 bytes), which matches many ecosystems (e.g. JS **elliptic**-style uncompressed points). X25519 uses **32-byte** Montgomery wire format.
- **Memory** — `SecureZeroBytes` overwrites slices you pass in; it does not defeat all copies the runtime or hardware might keep. Sensitive buffers should still be discarded when done.
