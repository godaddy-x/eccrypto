package ecc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestMarshalParseMsgPlainV2Roundtrip(t *testing.T) {
	wire := []byte{0x03, 0xde, 0xad, 0xbe, 0xef}
	pt, err := MarshalMsgPlainV2("task-sign-1", 2, true, wire)
	if err != nil {
		t.Fatal(err)
	}
	if pt[0] != MsgPlainV2Version {
		t.Fatalf("version=%#x", pt[0])
	}
	got, err := ParseMsgPlainV2(pt, "task-sign-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.TaskID != "task-sign-1" || got.FromIndex != 2 || !got.IsBroadcast || !bytes.Equal(got.Wire, wire) {
		t.Fatalf("unexpected parsed: %+v", got)
	}
	taskID, err := PeekMsgPlainTaskIDV2(pt, "task-sign-1")
	if err != nil || taskID != "task-sign-1" {
		t.Fatalf("peek: taskID=%q err=%v", taskID, err)
	}
}

func TestParseMsgPlainV2TaskIDMismatch(t *testing.T) {
	pt, err := MarshalMsgPlainV2("inner", 0, false, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseMsgPlainV2(pt, "outer")
	if !errors.Is(err, ErrMPCMsgPlainTaskIDMismatch) {
		t.Fatalf("want taskID mismatch, got %v", err)
	}
	_, err = PeekMsgPlainTaskIDV2(pt, "outer")
	if !errors.Is(err, ErrMPCMsgPlainTaskIDMismatch) {
		t.Fatalf("peek want taskID mismatch, got %v", err)
	}
}

func TestParseMsgPlainV2RejectLegacyJSON(t *testing.T) {
	legacy := []byte(`{"taskID":"t1","wireBytesBase64":"YQ==","fromIndex":0}`)
	_, err := ParseMsgPlainV2(legacy, "t1")
	if !errors.Is(err, ErrMPCMsgPlainDowngrade) {
		t.Fatalf("want downgrade, got %v", err)
	}
	_, err = PeekMsgPlainTaskIDV2(legacy, "t1")
	if !errors.Is(err, ErrMPCMsgPlainDowngrade) {
		t.Fatalf("peek want downgrade, got %v", err)
	}
}

func TestParseMsgPlainV2UnknownFlags(t *testing.T) {
	pt, err := MarshalMsgPlainV2("t1", 0, false, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	pt[1+4+len("t1")+1] |= 0x02
	_, err = ParseMsgPlainV2(pt, "t1")
	if !errors.Is(err, ErrMPCMsgPlainUnknownFlags) {
		t.Fatalf("want unknown flags, got %v", err)
	}
}

func TestMarshalMsgPlainV2Validation(t *testing.T) {
	if _, err := MarshalMsgPlainV2("", 0, false, []byte{0x01}); err == nil {
		t.Fatal("empty taskID")
	}
	if _, err := MarshalMsgPlainV2("t", 0, false, nil); err == nil {
		t.Fatal("empty wire")
	}
	long := strings.Repeat("a", maxMsgPlainTaskIDLen+1)
	if _, err := MarshalMsgPlainV2(long, 0, false, []byte{0x01}); err == nil {
		t.Fatal("long taskID")
	}
	if _, err := MarshalMsgPlainV2("t", -1, false, []byte{0x01}); err == nil {
		t.Fatal("negative fromIndex")
	}
	if _, err := MarshalMsgPlainV2("t", 256, false, []byte{0x01}); err == nil {
		t.Fatal("fromIndex > 255")
	}
	bigWire := make([]byte, MaxMsgPlainWireBytes+1)
	if _, err := MarshalMsgPlainV2("t", 0, false, bigWire); err == nil {
		t.Fatal("wire too long")
	}
}

func TestParseMsgPlainV2Truncated(t *testing.T) {
	pt, err := MarshalMsgPlainV2("t1", 1, true, []byte{0x0a, 0x0b})
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(pt); cut++ {
		_, err := ParseMsgPlainV2(pt[:cut], "t1")
		if err == nil {
			t.Fatalf("truncated len=%d should fail", cut)
		}
	}
}

func TestParseMsgPlainV2TaskIDInjection(t *testing.T) {
	// Length-prefix prevents interpreting extra bytes as wire when taskID boundary shifts.
	wire := []byte{0x07, 0x11, 0x22}
	pt, err := MarshalMsgPlainV2("a", 0, false, wire)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := MarshalMsgPlainV2("aa", 0, false, wire)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pt, pt2) {
		t.Fatal("distinct taskIDs must produce distinct plaintext")
	}
}

func TestParseMsgPlainV2TrailingBytes(t *testing.T) {
	pt, err := MarshalMsgPlainV2("t1", 0, false, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	bad := append(append([]byte(nil), pt...), 0x00)
	_, err = ParseMsgPlainV2(bad, "t1")
	if !errors.Is(err, ErrMPCMsgPlainInvalid) {
		t.Fatalf("want invalid, got %v", err)
	}
}

func TestParseMsgPlainV2EmptyWire(t *testing.T) {
	pt, err := MarshalMsgPlainV2("t1", 0, false, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	wireLenOff := 1 + 4 + len("t1") + 2
	binary.BigEndian.PutUint32(pt[wireLenOff:wireLenOff+4], 0)
	_, err = ParseMsgPlainV2(pt, "t1")
	if !errors.Is(err, ErrMPCMsgPlainInvalid) {
		t.Fatalf("want invalid for empty wire, got %v", err)
	}
}

func TestParseMsgPlainV2WireLengthOverflow(t *testing.T) {
	pt, err := MarshalMsgPlainV2("t1", 0, false, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt wire length field to exceed MaxMsgPlainWireBytes.
	wireLenOff := 1 + 4 + len("t1") + 2
	binary.BigEndian.PutUint32(pt[wireLenOff:wireLenOff+4], MaxMsgPlainWireBytes+1)
	_, err = ParseMsgPlainV2(pt, "t1")
	if err == nil {
		t.Fatal("expected wire too long error")
	}
}
