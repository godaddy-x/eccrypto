package ecc

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenPiggybackRoundTrip(t *testing.T) {
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	pub := GetMLKEM1024EncapsulationKeyBytes(dk.EncapsulationKey())
	plaintext := []byte(`{"taskID":"t1","wireBytesBase64":"abc","fromIndex":1}`)
	aad := SessionMsgAAD("t1", "nodeB", "mpcKeygenMsg")
	info := SessionHKDFInfo("t1", "nodeA", "nodeB", "keygen")

	firstPkt, K, kemCt, err := SealPiggyback(pub, plaintext, aad, info)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZeroBytes(K)
	if firstPkt[0] != ProtocolVersionPiggyback {
		t.Fatalf("version %x", firstPkt[0])
	}
	if len(kemCt) != mlkem1024CtLen {
		t.Fatalf("kemCt len %d", len(kemCt))
	}

	K2, kemCt2, pt, isReplay, err := OpenPiggyback(dk, firstPkt, aad, info, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZeroBytes(K2)
	if isReplay {
		t.Fatal("expected first open")
	}
	if !bytes.Equal(K, K2) {
		t.Fatal("K mismatch")
	}
	if !bytes.Equal(kemCt, kemCt2) {
		t.Fatal("kemCt mismatch")
	}
	if !bytes.Equal(plaintext, pt) {
		t.Fatal("plaintext mismatch")
	}
}

func TestSealPiggybackDistinctCalls(t *testing.T) {
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	pub := GetMLKEM1024EncapsulationKeyBytes(dk.EncapsulationKey())
	aad := SessionMsgAAD("t1", "B", "mpcSignMsg")
	info := SessionHKDFInfo("t1", "A", "B", "sign")
	pt := []byte("payload")

	p1, k1, _, err := SealPiggyback(pub, pt, aad, info)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZeroBytes(k1)
	p2, k2, _, err := SealPiggyback(pub, pt, aad, info)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZeroBytes(k2)
	if bytes.Equal(p1, p2) {
		t.Fatal("two SealPiggyback calls must produce distinct firstPkt (retries must not reseal)")
	}
}

func TestOpenPiggybackReplayAndConflict(t *testing.T) {
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	pub := GetMLKEM1024EncapsulationKeyBytes(dk.EncapsulationKey())
	aad := SessionMsgAAD("t1", "B", "mpcKeygenMsg")
	info := SessionHKDFInfo("t1", "A", "B", "keygen")
	pt := []byte("hello")

	firstPkt, K, kemCt, err := SealPiggyback(pub, pt, aad, info)
	if err != nil {
		t.Fatal(err)
	}
	SecureZeroBytes(K)

	_, _, _, isReplay, err := OpenPiggyback(dk, firstPkt, aad, info, nil)
	if err != nil || isReplay {
		t.Fatalf("first open: err=%v isReplay=%v", err, isReplay)
	}

	_, _, pt2, isReplay, err := OpenPiggyback(dk, firstPkt, aad, info, kemCt)
	if err != nil {
		t.Fatal(err)
	}
	if !isReplay {
		t.Fatal("expected isReplay")
	}
	if pt2 != nil {
		t.Fatal("replay must not return plaintext")
	}

	// Different kemCt → conflict
	other := append([]byte(nil), kemCt...)
	other[0] ^= 0xff
	_, _, _, _, err = OpenPiggyback(dk, firstPkt, aad, info, other)
	if !errors.Is(err, ErrKemCtConflict) {
		t.Fatalf("want ErrKemCtConflict, got %v", err)
	}
}

func TestSealOpenSessionAESRoundTrip(t *testing.T) {
	K := make([]byte, 32)
	for i := range K {
		K[i] = byte(i + 1)
	}
	aad := SessionMsgAAD("t1", "B", "mpcSignMsg")
	var ctr uint64
	pt := []byte("session body")

	pkt, err := SealSessionAES(K, pt, aad, &ctr)
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != ProtocolVersionSessionAES {
		t.Fatalf("version %x", pkt[0])
	}
	if ctr != 1 {
		t.Fatalf("ctr=%d", ctr)
	}

	out, err := OpenSessionAES(K, pkt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, out) {
		t.Fatal("plaintext mismatch")
	}

	// AAD tamper
	badAAD := SessionMsgAAD("t1", "B", "mpcKeygenMsg")
	if _, err := OpenSessionAES(K, pkt, badAAD); err == nil {
		t.Fatal("expected AAD mismatch error")
	}
}

func TestRejectLegacyOnSessionOpen(t *testing.T) {
	dk, err := CreateMLKEM1024()
	if err != nil {
		t.Fatal(err)
	}
	pub := GetMLKEM1024EncapsulationKeyBytes(dk.EncapsulationKey())
	legacy, err := EncryptMLKEM1024(pub, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckMPCMsgWireVersion(legacy[0]); !errors.Is(err, ErrMPCMsgWireDowngrade) {
		t.Fatalf("CheckMPCMsgWireVersion: %v", err)
	}
	aad := SessionMsgAAD("t", "B", "mpcKeygenMsg")
	info := SessionHKDFInfo("t", "A", "B", "keygen")
	_, _, _, _, err = OpenPiggyback(dk, legacy, aad, info, nil)
	if err == nil {
		t.Fatal("expected reject of 0x04 frame")
	}
	if IsMPCMsgWireAllowed(0x04) || IsMPCMsgWireAllowed(0x05) {
		t.Fatal("0x04/0x05 must not be allowed for Msg")
	}
	if !IsMPCMsgWireAllowed(0x06) || !IsMPCMsgWireAllowed(0x07) {
		t.Fatal("0x06/0x07 must be allowed")
	}
}
