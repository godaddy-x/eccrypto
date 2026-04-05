package ecc

import (
	"bytes"
	"strings"
	"testing"
)

func TestX25519Basic(t *testing.T) {
	alicePrk, err := CreateX25519()
	if err != nil {
		t.Fatalf("CreateX25519 Alice: %v", err)
	}
	bobPrk, err := CreateX25519()
	if err != nil {
		t.Fatalf("CreateX25519 Bob: %v", err)
	}

	aliceShared, err := GenSharedKeyX25519(alicePrk, bobPrk.PublicKey())
	if err != nil {
		t.Fatalf("Alice X25519: %v", err)
	}
	bobShared, err := GenSharedKeyX25519(bobPrk, alicePrk.PublicKey())
	if err != nil {
		t.Fatalf("Bob X25519: %v", err)
	}
	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatalf("shared secrets differ")
	}

	msg := []byte("Hello, X25519 encryption!")
	enc, err := EncryptX25519(alicePrk, GetX25519PublicKeyBytes(bobPrk.PublicKey()), msg, nil)
	if err != nil {
		t.Fatalf("EncryptX25519: %v", err)
	}
	dec, err := DecryptX25519(bobPrk, enc, nil, nil)
	if err != nil {
		t.Fatalf("DecryptX25519: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestX25519EncryptDecrypt(t *testing.T) {
	prk, err := CreateX25519()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := GetX25519PublicKeyBytes(prk.PublicKey())
	if len(pubBytes) != x25519PubKeyLen {
		t.Fatalf("pub len want %d got %d", x25519PubKeyLen, len(pubBytes))
	}

	r, err := EncryptX25519(prk, pubBytes, testMsg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r[0] != protocolVersionX25519 {
		t.Fatalf("wrong protocol version %x", r[0])
	}

	decrypted, err := DecryptX25519(prk, r, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testMsg, decrypted) {
		t.Fatal("round-trip failed")
	}
}

func TestX25519EncryptNilEphemeral(t *testing.T) {
	prk, err := CreateX25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := GetX25519PublicKeyBytes(prk.PublicKey())
	out, err := EncryptX25519(nil, pub, []byte("ephemeral"), nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptX25519(prk, out, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "ephemeral" {
		t.Fatalf("got %q", dec)
	}
}

func TestX25519HexRoundTrip(t *testing.T) {
	prk, err := CreateX25519()
	if err != nil {
		t.Fatal(err)
	}
	h := X25519PublicKeyToHex(prk.PublicKey())
	loaded, err := LoadX25519PublicKeyFromHex(h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(GetX25519PublicKeyBytes(loaded), GetX25519PublicKeyBytes(prk.PublicKey())) {
		t.Fatal("hex load mismatch")
	}
}

func TestX25519SecurityCases(t *testing.T) {
	prk, err := CreateX25519()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("message too short", func(t *testing.T) {
		_, err := DecryptX25519(prk, make([]byte, 40), nil, nil)
		if err == nil || !strings.Contains(err.Error(), "message too short") {
			t.Fatalf("want message too short, got %v", err)
		}
	})

	t.Run("wrong protocol version", func(t *testing.T) {
		// 0x01 为 P256 版本，与 X25519 载荷长度不兼容时也应失败
		bad := append([]byte{0x01}, make([]byte, 80)...)
		_, err := DecryptX25519(prk, bad, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
			t.Fatalf("want unsupported protocol version, got %v", err)
		}
	})

	t.Run("Encrypt invalid recipient pub length", func(t *testing.T) {
		_, err := EncryptX25519(prk, make([]byte, 31), []byte("x"), nil)
		if err == nil || !strings.Contains(err.Error(), "public key must be 32 bytes") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestX25519P256DecryptMismatch(t *testing.T) {
	// P256 密文不可被 DecryptX25519 解析（版本或长度）
	p256Prk, err := CreateECDH()
	if err != nil {
		t.Fatal(err)
	}
	pub := GetECDHPublicKeyBytes(p256Prk.PublicKey())
	p256Blob, err := Encrypt(p256Prk, pub, []byte("p256"), nil)
	if err != nil {
		t.Fatal(err)
	}

	xPrk, err := CreateX25519()
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptX25519(xPrk, p256Blob, nil, nil)
	if err == nil {
		t.Fatal("expected error decrypting P256 blob with X25519")
	}
}

func BenchmarkX25519Create(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := CreateX25519(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519SharedKey(b *testing.B) {
	prk, err := CreateX25519()
	if err != nil {
		b.Fatal(err)
	}
	pub := prk.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := prk.ECDH(pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519Encrypt(b *testing.B) {
	prk, err := CreateX25519()
	if err != nil {
		b.Fatal(err)
	}
	pubBytes := GetX25519PublicKeyBytes(prk.PublicKey())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := EncryptX25519(prk, pubBytes, testMsg, nil)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = DecryptX25519(prk, r, nil, nil)
	}
}

func TestGetX25519ProtocolVersion(t *testing.T) {
	if GetX25519ProtocolVersion() != 0x02 {
		t.Fatal()
	}
}

func TestValidateX25519PublicKey(t *testing.T) {
	prk, err := CreateX25519()
	if err != nil {
		t.Fatal(err)
	}
	if ValidateX25519PublicKey(GetX25519PublicKeyBytes(prk.PublicKey())) != nil {
		t.Fatal("valid key rejected")
	}
	if ValidateX25519PublicKey(make([]byte, 31)) == nil {
		t.Fatal("short key should be rejected")
	}
}
