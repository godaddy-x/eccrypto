package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"github.com/godaddy-x/eccrypto/crypto"
	"github.com/godaddy-x/eccrypto/crypto/ecies"
	"math/big"
)

func CreateHexKey() (string, string, error) {
	prk, err := ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(prk.D.Bytes()), hex.EncodeToString(elliptic.Marshal(prk.Curve, prk.PublicKey.X, prk.PublicKey.Y)), nil
}

func LoadHexKey(priHex, pubHex string) (*ecies.PrivateKey, error) {
	prk := &ecies.PrivateKey{}
	if len(priHex) > 0 {
		privateKeyBytes, err := hex.DecodeString(priHex)
		if err != nil {
			return nil, err
		}
		prk.D = new(big.Int).SetBytes(privateKeyBytes)
	}
	if len(pubHex) > 0 {
		publicKeyBytes, err := hex.DecodeString(pubHex)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(crypto.S256(), publicKeyBytes)
		pub := ecies.PublicKey{Curve: crypto.S256(), X: x, Y: y, Params: ecies.ECIES_AES128_SHA256}
		prk.PublicKey = pub
	}
	return prk, nil
}

func Encrypt(pub ecies.PublicKey, msg []byte) (string, error) {
	ct, err := ecies.Encrypt(rand.Reader, &pub, msg, nil, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

func Decrypt(prk *ecies.PrivateKey, msg string) (string, error) {
	bs, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}
	ct, err := prk.Decrypt(bs, nil, nil)
	if err != nil {
		return "", err
	}
	return string(ct), nil
}
