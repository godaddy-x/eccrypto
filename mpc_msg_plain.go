package ecc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// MsgPlainV2Version is the first byte of mpc-msg-plain-v2 AES plaintext.
	MsgPlainV2Version byte = 0x02

	msgPlainV2FlagBroadcast byte = 0x01
	msgPlainV2FlagReserved  byte = 0xFE

	maxMsgPlainTaskIDLen = 1024
	// MaxMsgPlainWireBytes matches wallet-mpc-node mpcsess.MaxWireFrameBytes.
	MaxMsgPlainWireBytes = 512 * 1024
)

var (
	// ErrMPCMsgPlainDowngrade is returned when plaintext is not mpc-msg-plain-v2 (e.g. legacy JSON).
	ErrMPCMsgPlainDowngrade = errors.New("mpc msg plain downgrade rejected")
	// ErrMPCMsgPlainTaskIDMismatch is returned when inner taskID != outer CliMPCEncryptData.taskID.
	ErrMPCMsgPlainTaskIDMismatch = errors.New("mpc msg plain taskID mismatch")
	// ErrMPCMsgPlainInvalid is returned for malformed v2 plaintext.
	ErrMPCMsgPlainInvalid = errors.New("mpc msg plain invalid")
	// ErrMPCMsgPlainUnknownFlags is returned when reserved flag bits are set.
	ErrMPCMsgPlainUnknownFlags = errors.New("mpc msg plain unknown flags")
)

// MsgPlainV2 holds decoded mpc-msg-plain-v2 fields.
type MsgPlainV2 struct {
	TaskID      string
	FromIndex   int
	IsBroadcast bool
	Wire        []byte
}

// MarshalMsgPlainV2 builds AES plaintext:
//
//	0x02 || u32be(len(taskID)) || taskID || u8(fromIndex) || u8(flags) || u32be(len(wire)) || wire
func MarshalMsgPlainV2(taskID string, fromIndex int, isBroadcast bool, wire []byte) ([]byte, error) {
	if err := validateMsgPlainTaskID(taskID); err != nil {
		return nil, err
	}
	if fromIndex < 0 || fromIndex > 255 {
		return nil, fmt.Errorf("fromIndex out of range: %d", fromIndex)
	}
	if len(wire) == 0 {
		return nil, fmt.Errorf("wire is empty")
	}
	if len(wire) > MaxMsgPlainWireBytes {
		return nil, fmt.Errorf("wire too long: %d > %d", len(wire), MaxMsgPlainWireBytes)
	}
	flags := byte(0)
	if isBroadcast {
		flags |= msgPlainV2FlagBroadcast
	}
	out := make([]byte, 0, 1+4+len(taskID)+1+1+4+len(wire))
	out = append(out, MsgPlainV2Version)
	out = appendLenPrefixedString(out, taskID)
	out = append(out, byte(fromIndex), flags)
	out = binary.BigEndian.AppendUint32(out, uint32(len(wire)))
	out = append(out, wire...)
	return out, nil
}

// PeekMsgPlainTaskIDV2 reads inner taskID from v2 plaintext and compares with outerTaskID when set.
func PeekMsgPlainTaskIDV2(plaintext []byte, outerTaskID string) (string, error) {
	taskID, err := readMsgPlainTaskIDV2(plaintext)
	if err != nil {
		return "", err
	}
	if outerTaskID != "" && taskID != outerTaskID {
		return "", ErrMPCMsgPlainTaskIDMismatch
	}
	return taskID, nil
}

// ParseMsgPlainV2 decodes mpc-msg-plain-v2 and binds inner taskID to outerTaskID when non-empty.
func ParseMsgPlainV2(plaintext []byte, outerTaskID string) (MsgPlainV2, error) {
	if len(plaintext) == 0 || plaintext[0] != MsgPlainV2Version {
		return MsgPlainV2{}, ErrMPCMsgPlainDowngrade
	}
	off := 1
	taskID, n, err := readLenPrefixedString(plaintext, off, maxMsgPlainTaskIDLen, "taskID")
	if err != nil {
		return MsgPlainV2{}, err
	}
	off += n
	if err := validateMsgPlainTaskID(taskID); err != nil {
		return MsgPlainV2{}, err
	}
	if outerTaskID != "" && taskID != outerTaskID {
		return MsgPlainV2{}, ErrMPCMsgPlainTaskIDMismatch
	}
	if off+2 > len(plaintext) {
		return MsgPlainV2{}, ErrMPCMsgPlainInvalid
	}
	fromIndex := int(plaintext[off])
	flags := plaintext[off+1]
	off += 2
	if flags&msgPlainV2FlagReserved != 0 {
		return MsgPlainV2{}, ErrMPCMsgPlainUnknownFlags
	}
	wireLen, n, err := readLenPrefixedBytes(plaintext, off, MaxMsgPlainWireBytes, "wire")
	if err != nil {
		return MsgPlainV2{}, err
	}
	off += n
	if len(wireLen) == 0 {
		return MsgPlainV2{}, ErrMPCMsgPlainInvalid
	}
	if off != len(plaintext) {
		return MsgPlainV2{}, ErrMPCMsgPlainInvalid
	}
	return MsgPlainV2{
		TaskID:      taskID,
		FromIndex:   fromIndex,
		IsBroadcast: flags&msgPlainV2FlagBroadcast != 0,
		Wire:        append([]byte(nil), wireLen...),
	}, nil
}

func readMsgPlainTaskIDV2(plaintext []byte) (string, error) {
	if len(plaintext) == 0 || plaintext[0] != MsgPlainV2Version {
		return "", ErrMPCMsgPlainDowngrade
	}
	taskID, _, err := readLenPrefixedString(plaintext, 1, maxMsgPlainTaskIDLen, "taskID")
	if err != nil {
		return "", err
	}
	if err := validateMsgPlainTaskID(taskID); err != nil {
		return "", err
	}
	return taskID, nil
}

func validateMsgPlainTaskID(taskID string) error {
	if taskID == "" {
		return fmt.Errorf("taskID is empty")
	}
	if len(taskID) > maxMsgPlainTaskIDLen {
		return fmt.Errorf("taskID too long")
	}
	return nil
}

func readLenPrefixedString(b []byte, off, maxLen int, field string) (string, int, error) {
	raw, n, err := readLenPrefixedBytes(b, off, maxLen, field)
	if err != nil {
		return "", 0, err
	}
	return string(raw), n, nil
}

func readLenPrefixedBytes(b []byte, off, maxLen int, field string) ([]byte, int, error) {
	if off+4 > len(b) {
		return nil, 0, ErrMPCMsgPlainInvalid
	}
	l := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4
	if l < 0 || l > maxLen {
		return nil, 0, fmt.Errorf("%s too long", field)
	}
	if off+l > len(b) {
		return nil, 0, ErrMPCMsgPlainInvalid
	}
	return b[off : off+l], 4 + l, nil
}
