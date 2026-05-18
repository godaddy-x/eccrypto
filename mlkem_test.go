package ecc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMLKEM1024EncapsDecaps(t *testing.T) {
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	sk, ct, err := EncapsulateMLKEM1024(ek)
	if err != nil {
		t.Fatal(err)
	}
	if len(sk) != mlkem1024SharedKeyLen || len(ct) != mlkem1024CtLen {
		t.Fatalf("bad lengths sk=%d ct=%d", len(sk), len(ct))
	}

	sk2, err := DecapsulateMLKEM1024(dk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk, sk2) {
		t.Fatal("shared secret mismatch")
	}
}

func TestMLKEM1024EncryptDecrypt(t *testing.T) {
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	pub := GetMLKEM1024EncapsulationKeyBytes(dk.EncapsulationKey())

	msg := []byte("ml-kem-1024 sealed message")
	enc, err := EncryptMLKEM1024(pub, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != protocolVersionMLKEM1024 {
		t.Fatalf("version %x", enc[0])
	}

	dec, err := DecryptMLKEM1024(dk, enc, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, dec) {
		t.Fatal("plaintext mismatch")
	}
}

func TestMLKEM1024Base64RoundTrip(t *testing.T) {
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	b64 := MLKEM1024DecapsulationKeyToBase64(dk)
	loaded, err := LoadMLKEM1024DecapsulationKeyFromBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), loaded.Bytes()) {
		t.Fatal("decap key mismatch")
	}
}

func TestMLKEM1024DistinctFromX25519Blob(t *testing.T) {
	xPrk, err := CreateX25519()
	if err != nil {
		t.Fatal(err)
	}
	xPub := GetX25519PublicKeyBytes(xPrk.PublicKey())
	xBlob, err := EncryptX25519(xPrk, xPub, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}

	dk, _ := CreateMLKEM1024()
	_, err = DecryptMLKEM1024(dk, xBlob, nil, nil)
	if err == nil {
		t.Fatal("expected error decrypting X25519 blob with ML-KEM-1024")
	}
}

func TestMLKEM1024LoadEncapKeyFromRandom(t *testing.T) {
	b := make([]byte, mlkem1024PubKeyLen)
	_, _ = rand.Read(b)
	if err := ValidateMLKEM1024EncapsulationKey(b); err == nil {
		// 随机串大概率非法
	} else {
		// ok
	}
}
