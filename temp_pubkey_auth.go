package ecc

import (
	"encoding/binary"
	"fmt"

	fmldsa "filippo.io/mldsa"
)

const (
	tempPubkeyAuthDomain      = "mpc-temp-pk-v2"
	tempPubkeyAuthMaxFieldLen = 1024
	// TempPubkeyMLKEMEncapsLen is ML-KEM-1024 encapsulation key size (FIPS 203).
	TempPubkeyMLKEMEncapsLen = 1568
	// TempPubkeyMLDSA87SigLen is ML-DSA-87 signature size (FIPS 204).
	TempPubkeyMLDSA87SigLen = 4627
)

// TempPubkeyAuthMessage builds the signed message for temporary ML-KEM encaps key binding.
// Encoding is length-prefixed to prevent "|" / field-boundary injection:
//
//	domain || u32be(len(taskID)) || taskID || u32be(len(module)) || module ||
//	u32be(len(subject)) || subject || encapsKeyBytes
func TempPubkeyAuthMessage(taskID, module, subject string, encapsKey []byte) ([]byte, error) {
	if err := validateTempPubkeyAuthField("taskID", taskID); err != nil {
		return nil, err
	}
	if err := validateTempPubkeyAuthField("module", module); err != nil {
		return nil, err
	}
	if err := validateTempPubkeyAuthField("subject", subject); err != nil {
		return nil, err
	}
	if len(encapsKey) != TempPubkeyMLKEMEncapsLen {
		return nil, fmt.Errorf("invalid encaps key length: got %d want %d", len(encapsKey), TempPubkeyMLKEMEncapsLen)
	}
	out := make([]byte, 0, len(tempPubkeyAuthDomain)+4*3+len(taskID)+len(module)+len(subject)+len(encapsKey))
	out = append(out, tempPubkeyAuthDomain...)
	out = appendLenPrefixedString(out, taskID)
	out = appendLenPrefixedString(out, module)
	out = appendLenPrefixedString(out, subject)
	out = append(out, encapsKey...)
	return out, nil
}

func validateTempPubkeyAuthField(name, v string) error {
	if v == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if len(v) > tempPubkeyAuthMaxFieldLen {
		return fmt.Errorf("%s too long", name)
	}
	if name == "module" && v != "keygen" && v != "sign" {
		return fmt.Errorf("invalid module %q", v)
	}
	return nil
}

func appendLenPrefixedString(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// SignTempPubkey signs a per-task ML-KEM encaps key with the node's long-term ML-DSA-87 identity key.
func SignTempPubkey(sk *fmldsa.PrivateKey, taskID, module, subject string, encapsKey []byte) ([]byte, error) {
	if sk == nil {
		return nil, fmt.Errorf("identity private key is nil")
	}
	msg, err := TempPubkeyAuthMessage(taskID, module, subject, encapsKey)
	if err != nil {
		return nil, err
	}
	return SignMLDSA87(sk, msg)
}

// VerifyTempPubkey verifies a temporary ML-KEM encaps key signature under the peer's long-term ML-DSA-87 public key.
func VerifyTempPubkey(pk *fmldsa.PublicKey, taskID, module, subject string, encapsKey, sig []byte) error {
	if pk == nil {
		return fmt.Errorf("identity public key is nil")
	}
	if len(sig) != TempPubkeyMLDSA87SigLen {
		return fmt.Errorf("invalid temp pubkey signature length: got %d want %d", len(sig), TempPubkeyMLDSA87SigLen)
	}
	msg, err := TempPubkeyAuthMessage(taskID, module, subject, encapsKey)
	if err != nil {
		return err
	}
	return VerifyMLDSA87(pk, msg, sig)
}
