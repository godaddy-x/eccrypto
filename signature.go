package ecc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

func Sign(prk *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := hash256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, prk, hash)
	if err != nil {
		return nil, errors.New("sign failed")
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

func Verify(pub *ecdsa.PublicKey, msg, sign []byte) bool {
	hash := hash256(msg)
	var r1, s1 big.Int
	sigLen := len(sign)
	r1.SetBytes(sign[:sigLen/2])
	s1.SetBytes(sign[sigLen/2:])
	return ecdsa.Verify(pub, hash, &r1, &s1)
}
