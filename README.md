# eccrypto

Go helpers for **ECIES-style sealed messaging** (ECDH/KEM → HKDF-SHA256 → AES-GCM) and **digital signatures**. Classical: P-256 / X25519 / ECDSA / Ed25519. Post-quantum: **ML-KEM-1024** (`crypto/mlkem`) and **ML-DSA-87** (via `filippo.io/mldsa` until `crypto/mldsa` ships in Go 1.27+).

## Contents

- [Module map](#module-map)
- [Sealed messaging (ECIES)](#sealed-messaging-ecies)
  - [P-256 — `ecdh.go`](#p-256--ecdhgo)
  - [X25519 — `ecdh_x25519.go`](#x25519--ecdh_x25519go)
- [ECDSA — `ecdsa.go`](#ecdsa--ecdsago)
- [Ed25519 — `ed25519.go`](#ed25519--ed25519go)
- [ML-KEM-1024 — `mlkem.go`](#ml-kem-1024--mlkemgo)
- [ML-DSA-87 — `mldsa.go`](#ml-dsa-87--mldsago)
- [Dual derive (one master seed)](#dual-derive-one-master-seed)
- [Benchmarks](#benchmarks)
- [Security & interoperability](#security--interoperability)

## Module map

| File | Role |
|------|------|
| `ecdh.go` | P-256 ECDH; `Encrypt` / `Decrypt`; protocol **`0x01`**; **65-byte** uncompressed public keys |
| `ecdh_x25519.go` | X25519 ECDH; `EncryptX25519` / `DecryptX25519`; protocol **`0x02`**; **32-byte** keys |
| `ecdsa.go` | P-256 ECDSA; DER signatures; includes `GenSharedKeyECDSA` (ECDH-style shared secret from ECDSA keys) |
| `ed25519.go` | Ed25519 sign/verify; 64-byte raw signatures (not DER) |
| `mlkem.go` | ML-KEM-1024 (`crypto/mlkem`); `EncryptMLKEM1024` / `DecryptMLKEM1024`; protocol **`0x04`**; KEM ciphertext **1568** bytes |
| `mldsa.go` | ML-DSA-87 sign/verify (FIPS 204); mirrors `ed25519.go` API shape |
| `master_seed_derive.go` | One high-entropy **master seed** → HKDF → separate **Ed25519** + **X25519** private keys |
| `secure_zero.go` | `SecureZeroBytes` (used by several helpers) |

## Sealed messaging (ECIES)

Both stacks share the same **idea**: ephemeral (or supplied) sender key, ECDH with recipient public key, **HKDF-SHA256** to a 32-byte AES key, **AES-GCM** with random nonce. **They are not compatible on the wire** — use the decrypt function that matches the encrypt function and curve.

| | P-256 | X25519 |
|---|-------|--------|
| Version byte | `0x01` | `0x02` |
| Ephemeral pubkey in blob | 65 bytes (`0x04` ‖ X ‖ Y) | 32 bytes |
| HKDF `info` | `ecdh-aes-gcm-encryption:` | `ecdh-x25519-aes-gcm-encryption:` |
| Encrypt / Decrypt | `Encrypt`, `Decrypt` | `EncryptX25519`, `DecryptX25519` |

Blob layout (classical): `[version:1][ephemeral public key][nonce ‖ ciphertext ‖ GCM tag]`.

**ML-KEM-1024** (`mlkem.go`, `crypto/mlkem`): `[version 0x04][KEM ciphertext 1568][nonce ‖ ciphertext ‖ GCM tag]` — shared secret from KEM encapsulation to the recipient’s **1568-byte** encapsulation key.

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

## ML-KEM-1024 — `mlkem.go`

Post-quantum KEM via **`crypto/mlkem`** (FIPS 203). Parameter set **ML-KEM-1024**.

- **Create / load decap (private):** `CreateMLKEM1024`, `LoadMLKEM1024DecapsulationKey` (64-byte seed), `…FromHex`, `…FromBase64`
- **Load encap (public):** `LoadMLKEM1024EncapsulationKey` (1568 bytes), `…FromHex`, `…FromBase64`
- **KEM:** `EncapsulateMLKEM1024`, `DecapsulateMLKEM1024` → 32-byte shared secret + 1568-byte ciphertext
- **Sealed message:** `EncryptMLKEM1024(publicTo, message, additionalData)`, `DecryptMLKEM1024(dk, msg, additionalData, dst)` — version **`0x04`**
- **Helpers:** `MLKEM1024*ToHex` / `ToBase64`, `GetMLKEM1024ProtocolVersion`, `ValidateMLKEM1024EncapsulationKey`

## ML-DSA-87 — `mldsa.go`

Post-quantum signatures (FIPS 204). **Go 1.26** does not export `crypto/mldsa` yet; this module uses **`filippo.io/mldsa`** (same API shape as the proposed std package). Plan to switch to `crypto/mldsa` when you upgrade to **Go 1.27+**.

- **Create / load private:** `CreateMLDSA87`, `LoadMLDSA87PrivateKey` (32-byte seed), `…FromHex`, `…FromBase64`
- **Load public:** `LoadMLDSA87PublicKey` (2592 bytes), `…FromHex`, `…FromBase64`
- **Sign / verify:** `SignMLDSA87`, `VerifyMLDSA87` — signature **4627** bytes; empty message allowed
- **Derive public key:** `DeriveMLDSA87PublicKey`
- **Helpers:** `MLDSA87*ToHex` / `ToBase64`, `ValidateMLDSA87PublicKey`

## Dual derive (one master seed)

Implementation: `master_seed_derive.go`. From one **master secret** (IKM), **HKDF-SHA256** produces **two independent 32-byte subkeys** using fixed salt `eccrypto:dual25519:v1` and distinct `info` strings (`…:ed25519-seed` vs `…:x25519-scalar`). **Do not** use the same 32 bytes for both curves without this split. **Do not** reuse the Ed25519 seed as an X25519 scalar (or vice versa).

- **Minimum IKM length:** `MinMasterSeedLen` (**16**); prefer **≥ 32** bytes of CSPRNG output, or a key-stretching output (Argon2id, scrypt, …) for passwords.
- **API (raw `[]byte` IKM):** `DeriveEd25519FromMasterSeed`, `DeriveX25519FromMasterSeed`, `DeriveEd25519AndX25519FromMasterSeed` (if X25519 fails, the Ed25519 material is zeroed).
- **API (Base64 StdEncoding):** `DeriveEd25519FromMasterSeedBase64`, `DeriveX25519FromMasterSeedBase64`, `DeriveEd25519AndX25519FromMasterSeedBase64` — decode then same HKDF; decoded bytes are zeroed before return.

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

- **Algorithms** — Classical curves use **Go stdlib**; **ML-KEM** uses `crypto/mlkem`; **ML-DSA** uses `filippo.io/mldsa` until `crypto/mldsa` is in your Go release.
- **ECIES** — Do not decrypt P-256 blobs with `DecryptX25519` or vice versa; version byte and HKDF labels differ by design.
- **Signatures** — ECDSA uses DER + low-S checks; Ed25519 uses **64-byte raw** signatures. Peers must agree on algorithm and encoding.
- **P-256 public keys** in this package’s ECDH helpers follow **uncompressed SEC1** (65 bytes), which matches many ecosystems (e.g. JS **elliptic**-style uncompressed points). X25519 uses **32-byte** Montgomery wire format.
- **Memory** — `SecureZeroBytes` overwrites slices you pass in; it does not defeat all copies the runtime or hardware might keep. Sensitive buffers should still be discarded when done.
- **Dual derive** — Master IKM should be high-entropy; HKDF labels are fixed for this package — changing them in code breaks compatibility with existing backups.
