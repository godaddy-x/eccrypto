package ecc

import (
	"bytes"
	"testing"
)

func TestTempPubkeyAuthSignVerify(t *testing.T) {
	sk, err := CreateMLDSA87()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := DeriveMLDSA87PublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	encaps := GetMLKEM1024EncapsulationKeyBytes(dk.EncapsulationKey())

	sig, err := SignTempPubkey(sk, "task-1", "keygen", "node0", encaps)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTempPubkey(pk, "task-1", "keygen", "node0", encaps, sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTempPubkey(pk, "task-2", "keygen", "node0", encaps, sig); err == nil {
		t.Fatal("expected fail on taskID mismatch")
	}
	if err := VerifyTempPubkey(pk, "task-1", "sign", "node0", encaps, sig); err == nil {
		t.Fatal("expected fail on module mismatch")
	}
	other := append([]byte(nil), encaps...)
	other[0] ^= 0xff
	if err := VerifyTempPubkey(pk, "task-1", "keygen", "node0", other, sig); err == nil {
		t.Fatal("expected fail on encaps mismatch")
	}
}

func TestTempPubkeyAuthNoFieldAmbiguity(t *testing.T) {
	sk, err := CreateMLDSA87()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := DeriveMLDSA87PublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	encaps := GetMLKEM1024EncapsulationKeyBytes(dk.EncapsulationKey())

	// Length-prefix must keep these distinct even when string concatenation would collide.
	msgA, err := TempPubkeyAuthMessage("a", "keygen", "node0", encaps)
	if err != nil {
		t.Fatal(err)
	}
	msgB, err := TempPubkeyAuthMessage("akeygen", "keygen", "node0", encaps)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(msgA, msgB) {
		t.Fatal("length-prefixed messages must differ")
	}
	sig, err := SignTempPubkey(sk, "a", "keygen", "node0", encaps)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTempPubkey(pk, "akeygen", "keygen", "node0", encaps, sig); err == nil {
		t.Fatal("cross-field reinterpretation must fail")
	}
	if _, err := SignTempPubkey(sk, "", "keygen", "node0", encaps); err == nil {
		t.Fatal("empty taskID must fail")
	}
	if _, err := SignTempPubkey(sk, "t", "other", "node0", encaps); err == nil {
		t.Fatal("invalid module must fail")
	}
	if _, err := TempPubkeyAuthMessage("t", "keygen", "node0", []byte{1}); err == nil {
		t.Fatal("short encaps must fail")
	}
}
