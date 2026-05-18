package ecc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMLDSA87SignVerify(t *testing.T) {
	sk, err := CreateMLDSA87()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := DeriveMLDSA87PublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("ml-dsa message")
	sig, err := SignMLDSA87(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMLDSA87(pk, msg, sig); err != nil {
		t.Fatal(err)
	}
}

func TestMLDSA87DeterministicLoad(t *testing.T) {
	seed := make([]byte, mldsa87SeedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	a, err := LoadMLDSA87PrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadMLDSA87PrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("load not deterministic")
	}
}

func TestMLDSA87Base64PrivateKey(t *testing.T) {
	sk, err := CreateMLDSA87()
	if err != nil {
		t.Fatal(err)
	}
	b64, err := MLDSA87PrivateKeyToBase64(sk)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMLDSA87PrivateKeyFromBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk.Bytes(), loaded.Bytes()) {
		t.Fatal("seed mismatch")
	}
}

func TestMLDSA87EmptyMessage(t *testing.T) {
	sk, err := CreateMLDSA87()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := DeriveMLDSA87PublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignMLDSA87(sk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMLDSA87(pk, nil, sig); err != nil {
		t.Fatal(err)
	}
}

func TestMLDSA87WrongSig(t *testing.T) {
	sk, _ := CreateMLDSA87()
	pk, _ := DeriveMLDSA87PublicKey(sk)
	sig, _ := SignMLDSA87(sk, []byte("x"))
	sig[0] ^= 0xff
	if err := VerifyMLDSA87(pk, []byte("x"), sig); err == nil {
		t.Fatal("expected verify failure")
	}
}

// TestMLDSA87PrintKeyPair 生成一对 ML-DSA-87 密钥并打印（hex / base64），便于手工联调。
// 运行: go test -v -run TestMLDSA87PrintKeyPair .
func TestMLDSA87PrintKeyPair(t *testing.T) {
	sk, err := CreateMLDSA87()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := DeriveMLDSA87PublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	privHex, err := MLDSA87PrivateKeyToHex(sk)
	if err != nil {
		t.Fatal(err)
	}
	pubHex, err := MLDSA87PublicKeyToHex(pk)
	if err != nil {
		t.Fatal(err)
	}
	privB64, err := MLDSA87PrivateKeyToBase64(sk)
	if err != nil {
		t.Fatal(err)
	}
	pubB64, err := MLDSA87PublicKeyToBase64(pk)
	if err != nil {
		t.Fatal(err)
	}

	privBytes, err := GetMLDSA87PrivateKeyBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := GetMLDSA87PublicKeyBytes(pk)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("ML-DSA-87 private key seed (%d bytes)", len(privBytes))
	t.Logf("  hex:    %s", privHex)
	t.Logf("  base64: %s", privB64)
	t.Logf("ML-DSA-87 public key (%d bytes)", len(pubBytes))
	t.Logf("  hex:    %s", pubHex)
	t.Logf("  base64: %s", pubB64)

	// 确认打印内容可重新加载
	if _, err := LoadMLDSA87PrivateKeyFromHex(privHex); err != nil {
		t.Fatalf("reload private from hex: %v", err)
	}
	if _, err := LoadMLDSA87PublicKeyFromHex(pubHex); err != nil {
		t.Fatalf("reload public from hex: %v", err)
	}
}
