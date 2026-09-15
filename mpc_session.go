package ecc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ProtocolVersionSessionAES is the wire version for post-piggyback AES-GCM frames (0x06).
	ProtocolVersionSessionAES byte = 0x06
	// ProtocolVersionPiggyback is the wire version for first-packet KEM+AES frames (0x07).
	ProtocolVersionPiggyback byte = 0x07

	hkdfInfoMPCSessPrefix = "mpc-sess-v1|"
)

var (
	// ErrKemCtConflict indicates a second 0x07 for the same direction carried a different kemCt.
	ErrKemCtConflict = errors.New("piggyback kemCt conflict")
	// ErrUnsupportedSessionVersion indicates the frame version is not 0x06/0x07.
	ErrUnsupportedSessionVersion = errors.New("unsupported mpc session wire version")
	// ErrMPCMsgWireDowngrade is returned when a peer sends a pre-Piggyback Msg frame (e.g. 0x04).
	// Callers MUST abort the task — never fall back to DecryptMLKEM1024 for mpc*Msg.
	ErrMPCMsgWireDowngrade = errors.New("mpc msg wire downgrade rejected")
	// ErrSessionPacketTooShort indicates a truncated session frame.
	ErrSessionPacketTooShort = errors.New("mpc session packet too short")
)

// IsMPCMsgWireAllowed reports whether ver is an accepted post-cutover Msg version (0x06 or 0x07 only).
func IsMPCMsgWireAllowed(ver byte) bool {
	return ver == ProtocolVersionSessionAES || ver == ProtocolVersionPiggyback
}

// CheckMPCMsgWireVersion returns ErrMPCMsgWireDowngrade for 0x04 / unknown versions.
func CheckMPCMsgWireVersion(ver byte) error {
	if IsMPCMsgWireAllowed(ver) {
		return nil
	}
	if ver == protocolVersionMLKEM1024 {
		return fmt.Errorf("%w: got 0x%02x (legacy per-msg ML-KEM); only 0x06/0x07 accepted", ErrMPCMsgWireDowngrade, ver)
	}
	return fmt.Errorf("%w: got 0x%02x; only 0x06/0x07 accepted", ErrMPCMsgWireDowngrade, ver)
}


// SessionHKDFInfo builds HKDF info: mpc-sess-v1|{taskID}|{sender}|{receiver}|{module}|send
func SessionHKDFInfo(taskID, sender, receiver, module string) []byte {
	return []byte(hkdfInfoMPCSessPrefix + taskID + "|" + sender + "|" + receiver + "|" + module + "|send")
}

// SessionMsgAAD builds caller AAD without version byte: taskID|receiver|routeSuffix.
// Seal/Open bind the wire version (and kemCt for 0x07) via constructSecureAAD.
func SessionMsgAAD(taskID, receiver, routeSuffix string) []byte {
	return []byte(taskID + "|" + receiver + "|" + routeSuffix)
}

func hkdfKeyMPCSession(sharedKey, info []byte) ([]byte, error) {
	if len(sharedKey) == 0 {
		return nil, fmt.Errorf("sharedKey cannot be empty")
	}
	if len(info) == 0 {
		return nil, fmt.Errorf("hkdf info cannot be empty")
	}
	return hkdf.Key(sha256.New, sharedKey, nil, string(info), keyLen)
}

func sessionNonceFromCounter(ctr uint64) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	rnd, err := SecureNonce(4)
	if err != nil {
		return nil, err
	}
	copy(nonce[:4], rnd)
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	return nonce, nil
}

func aesGCMEncryptFixedNonce(plaintext, key, nonce, additionalData []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("nonce must be %d bytes", nonceLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, additionalData)
	out := make([]byte, 0, nonceLen+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// SealPiggyback constructs a one-shot 0x07 frame: version||kemCt||nonce||ct||tag.
// Call once per (task, sender→receiver). Cache firstPkt for byte-identical retries; do not reseal.
//
// info is HKDF info (see SessionHKDFInfo). aad is caller AAD without version (see SessionMsgAAD);
// the version byte and kemCt are bound into the GCM AAD inside this function.
func SealPiggyback(peerEncapsKey, plaintext, aad, info []byte) (firstPkt, K, kemCt []byte, err error) {
	if len(peerEncapsKey) != mlkem1024PubKeyLen {
		return nil, nil, nil, fmt.Errorf("encapsulation key must be %d bytes", mlkem1024PubKeyLen)
	}
	if len(aad) > 1024*1024 {
		return nil, nil, nil, fmt.Errorf("aad too large (max 1MB)")
	}

	ek, err := LoadMLKEM1024EncapsulationKey(peerEncapsKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid recipient encapsulation key: %w", err)
	}

	sharedKey, kemCt, err := EncapsulateMLKEM1024(ek)
	if err != nil {
		return nil, nil, nil, err
	}
	defer SecureZeroBytes(sharedKey)

	K, err = hkdfKeyMPCSession(sharedKey, info)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce, err := SecureNonce(nonceLen)
	if err != nil {
		SecureZeroBytes(K)
		return nil, nil, nil, fmt.Errorf("nonce: %w", err)
	}

	gcmAAD := constructSecureAAD(aad, kemCt, ProtocolVersionPiggyback)
	seal, err := aesGCMEncryptFixedNonce(plaintext, K, nonce, gcmAAD)
	if err != nil {
		SecureZeroBytes(K)
		return nil, nil, nil, fmt.Errorf("aes-gcm: %w", err)
	}

	firstPkt = make([]byte, 1+len(kemCt)+len(seal))
	firstPkt[0] = ProtocolVersionPiggyback
	copy(firstPkt[1:], kemCt)
	copy(firstPkt[1+len(kemCt):], seal)

	kemCtOut := append([]byte(nil), kemCt...)
	return firstPkt, K, kemCtOut, nil
}

// OpenPiggyback opens a 0x07 frame.
//
// expectedKemCt == nil: first open — Decaps + HKDF, return K and plaintext, isReplay=false.
// expectedKemCt equals frame kemCt: replay — isReplay=true, plaintext may be nil (no Update).
// expectedKemCt differs: ErrKemCtConflict.
func OpenPiggyback(dk *mlkem.DecapsulationKey1024, pkt, aad, info, expectedKemCt []byte) (K, kemCt, plaintext []byte, isReplay bool, err error) {
	minLen := 1 + mlkem1024CtLen + nonceLen + 16
	if len(pkt) < minLen {
		return nil, nil, nil, false, ErrSessionPacketTooShort
	}
	if pkt[0] != ProtocolVersionPiggyback {
		return nil, nil, nil, false, fmt.Errorf("%w: got 0x%02x want 0x%02x", ErrUnsupportedSessionVersion, pkt[0], ProtocolVersionPiggyback)
	}

	kemCt = append([]byte(nil), pkt[1:1+mlkem1024CtLen]...)
	seal := pkt[1+mlkem1024CtLen:]

	if expectedKemCt != nil {
		if !bytes.Equal(expectedKemCt, kemCt) {
			return nil, kemCt, nil, false, ErrKemCtConflict
		}
		// Same kemCt: treat as replay. Do not Open / return plaintext.
		return nil, kemCt, nil, true, nil
	}

	if dk == nil {
		return nil, nil, nil, false, fmt.Errorf("decapsulation key cannot be nil")
	}

	sharedKey, err := DecapsulateMLKEM1024(dk, kemCt)
	if err != nil {
		return nil, nil, nil, false, err
	}
	defer SecureZeroBytes(sharedKey)

	K, err = hkdfKeyMPCSession(sharedKey, info)
	if err != nil {
		return nil, nil, nil, false, err
	}

	gcmAAD := constructSecureAAD(aad, kemCt, ProtocolVersionPiggyback)
	plaintext, err = AesGCMDecrypt(seal, K, gcmAAD, nil)
	if err != nil {
		SecureZeroBytes(K)
		return nil, nil, nil, false, err
	}
	return K, kemCt, plaintext, false, nil
}

// SealSessionAES constructs a 0x06 frame using an established session key.
// nonceCtr must be non-nil; it is incremented once a nonce is drawn (even if seal
// later fails) so the same counter is never reused with a different plaintext.
func SealSessionAES(K, plaintext, aad []byte, nonceCtr *uint64) ([]byte, error) {
	if len(K) != keyLen {
		return nil, errors.New("session key must be 32 bytes")
	}
	if nonceCtr == nil {
		return nil, errors.New("nonceCtr cannot be nil")
	}
	nonce, err := sessionNonceFromCounter(*nonceCtr)
	if err != nil {
		return nil, err
	}
	*nonceCtr++

	gcmAAD := constructSecureAAD(aad, nil, ProtocolVersionSessionAES)
	seal, err := aesGCMEncryptFixedNonce(plaintext, K, nonce, gcmAAD)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(seal))
	out[0] = ProtocolVersionSessionAES
	copy(out[1:], seal)
	return out, nil
}

// OpenSessionAES opens a 0x06 frame with an established session key.
func OpenSessionAES(K, pkt, aad []byte) ([]byte, error) {
	if len(K) != keyLen {
		return nil, errors.New("session key must be 32 bytes")
	}
	minLen := 1 + nonceLen + 16
	if len(pkt) < minLen {
		return nil, ErrSessionPacketTooShort
	}
	if pkt[0] != ProtocolVersionSessionAES {
		return nil, fmt.Errorf("%w: got 0x%02x want 0x%02x", ErrUnsupportedSessionVersion, pkt[0], ProtocolVersionSessionAES)
	}
	gcmAAD := constructSecureAAD(aad, nil, ProtocolVersionSessionAES)
	return AesGCMDecrypt(pkt[1:], K, gcmAAD, nil)
}

// WireVersion returns the first byte of a session frame, or 0 if empty.
func WireVersion(pkt []byte) byte {
	if len(pkt) == 0 {
		return 0
	}
	return pkt[0]
}
