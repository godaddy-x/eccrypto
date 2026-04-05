package ecc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEd25519Signing(t *testing.T) {
	privateKey, err := CreateEd25519()
	if err != nil {
		t.Fatalf("CreateEd25519 failed: %v", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	testMessages := [][]byte{
		[]byte("Hello, Ed25519!"),
		[]byte("This is a test message for digital signature."),
		[]byte("A"),
		bytes.Repeat([]byte("long message"), 100),
	}

	for i, message := range testMessages {
		t.Run(fmt.Sprintf("Message_%d", i), func(t *testing.T) {
			signature, err := SignEd25519(privateKey, message)
			if err != nil {
				t.Fatalf("SignEd25519 failed: %v", err)
			}
			if len(signature) != ed25519SigLen {
				t.Fatalf("signature length want %d got %d", ed25519SigLen, len(signature))
			}

			if err := VerifyEd25519(publicKey, message, signature); err != nil {
				t.Fatalf("VerifyEd25519 failed with correct key: %v", err)
			}

			wrongMessage := append(message, []byte("tampered")...)
			if err := VerifyEd25519(publicKey, wrongMessage, signature); err == nil {
				t.Error("VerifyEd25519 should fail with wrong message")
			}

			wrongSignature := make([]byte, len(signature))
			copy(wrongSignature, signature)
			if len(wrongSignature) > 0 {
				wrongSignature[0] ^= 0xFF
			}
			if err := VerifyEd25519(publicKey, message, wrongSignature); err == nil {
				t.Error("VerifyEd25519 should fail with wrong signature")
			}
		})
	}

	if _, err := SignEd25519(nil, []byte("test")); err == nil {
		t.Error("SignEd25519 should fail with nil private key")
	}

	if err := VerifyEd25519(nil, []byte("test"), make([]byte, ed25519SigLen)); err == nil {
		t.Error("VerifyEd25519 should fail with nil public key")
	}
}

func TestEd25519KeySerialization(t *testing.T) {
	originalPrivate, err := CreateEd25519()
	if err != nil {
		t.Fatalf("CreateEd25519 failed: %v", err)
	}

	privateBytes, err := GetEd25519PrivateKeyBytes(originalPrivate)
	if err != nil {
		t.Fatalf("GetEd25519PrivateKeyBytes failed: %v", err)
	}
	publicKey := originalPrivate.Public().(ed25519.PublicKey)
	publicBytes, err := GetEd25519PublicKeyBytes(publicKey)
	if err != nil {
		t.Fatalf("GetEd25519PublicKeyBytes failed: %v", err)
	}

	if len(publicBytes) != ed25519PubKeyLen {
		t.Errorf("Ed25519 public key should be %d bytes, got %d", ed25519PubKeyLen, len(publicBytes))
	}
	if len(privateBytes) != ed25519PrivKeyLen {
		t.Errorf("Ed25519 private key should be %d bytes, got %d", ed25519PrivKeyLen, len(privateBytes))
	}

	loadedPrivate, err := LoadEd25519PrivateKey(privateBytes)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKey failed: %v", err)
	}

	loadedPublic, err := LoadEd25519PublicKey(publicBytes)
	if err != nil {
		t.Fatalf("LoadEd25519PublicKey failed: %v", err)
	}

	testMessage := []byte("test message for key serialization")

	signature, err := SignEd25519(originalPrivate, testMessage)
	if err != nil {
		t.Fatalf("SignEd25519 with original key failed: %v", err)
	}
	if err := VerifyEd25519(loadedPublic, testMessage, signature); err != nil {
		t.Fatalf("VerifyEd25519 with loaded public key failed: %v", err)
	}

	signature2, err := SignEd25519(loadedPrivate, testMessage)
	if err != nil {
		t.Fatalf("SignEd25519 with loaded private key failed: %v", err)
	}
	if err := VerifyEd25519(publicKey, testMessage, signature2); err != nil {
		t.Fatalf("VerifyEd25519 with original public key failed: %v", err)
	}

	// 32 字节种子加载
	seed := append([]byte(nil), privateBytes[:ed25519SeedLen]...)
	loadedFromSeed, err := LoadEd25519PrivateKey(seed)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKey from seed failed: %v", err)
	}
	sigSeed, err := SignEd25519(loadedFromSeed, testMessage)
	if err != nil {
		t.Fatalf("SignEd25519 from seed-loaded key failed: %v", err)
	}
	if err := VerifyEd25519(publicKey, testMessage, sigSeed); err != nil {
		t.Fatalf("VerifyEd25519 after seed load failed: %v", err)
	}

	privateHex := hex.EncodeToString(privateBytes)
	publicHex := hex.EncodeToString(publicBytes)

	loadedPrivateHex, err := LoadEd25519PrivateKeyFromHex(privateHex)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKeyFromHex failed: %v", err)
	}
	loadedPublicHex, err := LoadEd25519PublicKeyFromHex(publicHex)
	if err != nil {
		t.Fatalf("LoadEd25519PublicKeyFromHex failed: %v", err)
	}

	if err := VerifyEd25519(loadedPublicHex, testMessage, signature); err != nil {
		t.Fatalf("VerifyEd25519 with hex loaded public key failed: %v", err)
	}
	signature3, err := SignEd25519(loadedPrivateHex, testMessage)
	if err != nil {
		t.Fatalf("SignEd25519 with hex loaded private key failed: %v", err)
	}
	if err := VerifyEd25519(publicKey, testMessage, signature3); err != nil {
		t.Fatalf("VerifyEd25519 with original public key and hex private signature failed: %v", err)
	}

	privateB64 := base64.StdEncoding.EncodeToString(privateBytes)
	publicB64 := base64.StdEncoding.EncodeToString(publicBytes)

	loadedPrivateB64, err := LoadEd25519PrivateKeyFromBase64(privateB64)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKeyFromBase64 failed: %v", err)
	}
	loadedPublicB64, err := LoadEd25519PublicKeyFromBase64(publicB64)
	if err != nil {
		t.Fatalf("LoadEd25519PublicKeyFromBase64 failed: %v", err)
	}

	if err := VerifyEd25519(loadedPublicB64, testMessage, signature); err != nil {
		t.Fatalf("VerifyEd25519 with base64 loaded public key failed: %v", err)
	}
	signature4, err := SignEd25519(loadedPrivateB64, testMessage)
	if err != nil {
		t.Fatalf("SignEd25519 with base64 loaded private key failed: %v", err)
	}
	if err := VerifyEd25519(publicKey, testMessage, signature4); err != nil {
		t.Fatalf("VerifyEd25519 with original public key and base64 private signature failed: %v", err)
	}
}

func TestEd25519EmptyMessage(t *testing.T) {
	priv, err := CreateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	for _, msg := range [][]byte{nil, []byte{}} {
		sig, err := SignEd25519(priv, msg)
		if err != nil {
			t.Fatalf("SignEd25519 empty/nil message: %v", err)
		}
		if err := VerifyEd25519(pub, msg, sig); err != nil {
			t.Fatalf("VerifyEd25519 empty/nil message: %v", err)
		}
	}
}

func TestSignEd25519With32ByteSeed(t *testing.T) {
	full, err := CreateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	seed := append([]byte(nil), full[:ed25519SeedLen]...)
	msg := []byte("sign with 32-byte seed only")
	sig, err := SignEd25519(seed, msg)
	if err != nil {
		t.Fatalf("SignEd25519(seed32): %v", err)
	}
	pub, err := DeriveEd25519PublicKey(seed)
	if err != nil {
		t.Fatalf("DeriveEd25519PublicKey(seed): %v", err)
	}
	if err := VerifyEd25519(pub, msg, sig); err != nil {
		t.Fatalf("VerifyEd25519: %v", err)
	}
	wantPub := full.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, wantPub) {
		t.Fatalf("derived public key does not match expanded key pair")
	}
}

func TestDeriveEd25519PublicKeyExpanded(t *testing.T) {
	full, err := CreateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := DeriveEd25519PublicKey(full)
	if err != nil {
		t.Fatalf("DeriveEd25519PublicKey: %v", err)
	}
	want := full.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, want) {
		t.Fatal("DeriveEd25519PublicKey(expanded) mismatch")
	}
}

func TestDeriveEd25519PublicKeyErrors(t *testing.T) {
	if _, err := DeriveEd25519PublicKey(nil); err == nil {
		t.Error("expected error for nil private key")
	}
	if _, err := DeriveEd25519PublicKey(ed25519.PrivateKey{1, 2, 3}); err == nil {
		t.Error("expected error for invalid private key length")
	}
}

func TestSignEd25519InvalidKeyLength(t *testing.T) {
	if _, err := SignEd25519(ed25519.PrivateKey{1, 2, 3}, []byte("x")); err == nil {
		t.Error("expected error for invalid private key length")
	}
}

func TestVerifyEd25519ShortSignature(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519PubKeyLen)
	if err := VerifyEd25519(pub, []byte("x"), nil); err == nil {
		t.Fatal("expected error for short signature")
	}
}

func TestLoadEd25519PublicKeyRejectsInvalidCurvePoint(t *testing.T) {
	priv, err := CreateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	valid := priv.Public().(ed25519.PublicKey)
	var rejectErr error
outer:
	for i := 0; i < ed25519PubKeyLen; i++ {
		for _, xor := range []byte{0x01, 0xff} {
			bad := append([]byte(nil), valid...)
			bad[i] ^= xor
			_, rejectErr = LoadEd25519PublicKey(bad)
			if rejectErr != nil {
				break outer
			}
		}
	}
	if rejectErr == nil {
		t.Fatal("expected some single-byte flip of a valid key to be rejected as invalid public key")
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	prk, err := CreateEd25519()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("benchmark message for Ed25519 signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SignEd25519(prk, message); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	prk, err := CreateEd25519()
	if err != nil {
		b.Fatal(err)
	}
	pub := prk.Public().(ed25519.PublicKey)
	message := []byte("benchmark message for Ed25519 verification")
	sig, err := SignEd25519(prk, message)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := VerifyEd25519(pub, message, sig); err != nil {
			b.Fatal(err)
		}
	}
}
