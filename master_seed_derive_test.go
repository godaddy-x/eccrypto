package ecc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestDeriveEd25519FromMasterSeedDeterministic(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	a, err := DeriveEd25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveEd25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("derive not deterministic")
	}
}

func TestDeriveX25519FromMasterSeedDeterministic(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	a, err := DeriveX25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveX25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(GetX25519PrivateKeyBytes(a), GetX25519PrivateKeyBytes(b)) {
		t.Fatal("derive not deterministic")
	}
}

func TestDeriveEd25519AndX25519DistinctSubkeys(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	edPriv, xPriv, err := DeriveEd25519AndX25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	edSeed := edPriv[:ed25519SeedLen]
	xScalar := GetX25519PrivateKeyBytes(xPriv)
	if bytes.Equal(edSeed, xScalar) {
		t.Fatal("ed25519 seed and x25519 scalar must not be identical")
	}
}

func TestDeriveEd25519AndX25519SignAndECDH(t *testing.T) {
	ma := make([]byte, 32)
	mb := make([]byte, 32)
	if _, err := rand.Read(ma); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(mb); err != nil {
		t.Fatal(err)
	}

	edA, xA, err := DeriveEd25519AndX25519FromMasterSeed(ma)
	if err != nil {
		t.Fatal(err)
	}
	edB, xB, err := DeriveEd25519AndX25519FromMasterSeed(mb)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("dual derive")
	sig, err := SignEd25519(edA, msg)
	if err != nil {
		t.Fatal(err)
	}
	pubA, err := DeriveEd25519PublicKey(edA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(pubA, msg, sig); err != nil {
		t.Fatal(err)
	}
	_ = edB // both parties have signing keys; not used further

	s1, err := GenSharedKeyX25519(xA, xB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := GenSharedKeyX25519(xB, xA.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("x25519 shared secret mismatch")
	}
}

func TestDeriveFromMasterSeedTooShort(t *testing.T) {
	short := make([]byte, MinMasterSeedLen-1)
	if _, err := DeriveEd25519FromMasterSeed(short); err == nil {
		t.Fatal("expected error")
	}
	if _, err := DeriveX25519FromMasterSeed(short); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := DeriveEd25519AndX25519FromMasterSeed(short); err == nil {
		t.Fatal("expected error")
	}
}

func TestDeriveEd25519MatchesDualFirstArm(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	edOnly, err := DeriveEd25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	edDual, _, err := DeriveEd25519AndX25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(edOnly, edDual) {
		t.Fatal("dual derive ed25519 arm must match standalone derive")
	}
}

func TestDeriveFromMasterSeedBase64(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(master)

	xRaw, err := DeriveX25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	xB64, err := DeriveX25519FromMasterSeedBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(GetX25519PrivateKeyBytes(xRaw), GetX25519PrivateKeyBytes(xB64)) {
		t.Fatal("DeriveX25519FromMasterSeedBase64 mismatch")
	}

	edRaw, err := DeriveEd25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	edB64, err := DeriveEd25519FromMasterSeedBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(edRaw, edB64) {
		t.Fatal("DeriveEd25519FromMasterSeedBase64 mismatch")
	}

	d1, d2, err := DeriveEd25519AndX25519FromMasterSeed(master)
	if err != nil {
		t.Fatal(err)
	}
	d1b, d2b, err := DeriveEd25519AndX25519FromMasterSeedBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d1, d1b) || !bytes.Equal(GetX25519PrivateKeyBytes(d2), GetX25519PrivateKeyBytes(d2b)) {
		t.Fatal("DeriveEd25519AndX25519FromMasterSeedBase64 mismatch")
	}
}

func TestDeriveFromMasterSeedBase64Errors(t *testing.T) {
	if _, err := DeriveX25519FromMasterSeedBase64(""); err == nil {
		t.Fatal("empty base64")
	}
	if _, err := DeriveX25519FromMasterSeedBase64("not-valid-base64!!!"); err == nil {
		t.Fatal("invalid base64")
	}
	short := make([]byte, MinMasterSeedLen-1)
	shortB64 := base64.StdEncoding.EncodeToString(short)
	if _, err := DeriveEd25519FromMasterSeedBase64(shortB64); err == nil {
		t.Fatal("short IKM")
	}
}
