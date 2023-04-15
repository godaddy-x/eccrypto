package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/godaddy-x/eccrypto/crypto"
	"github.com/godaddy-x/eccrypto/crypto/ecies"
	"math/big"
	"unsafe"
)

func CreateKey() ([]byte, []byte, error) {
	prk, err := ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, nil, err
	}
	prkBs := prk.D.Bytes()
	pubBs := elliptic.Marshal(prk.Curve, prk.PublicKey.X, prk.PublicKey.Y)
	return prkBs, pubBs, nil
}

func CreateHexKey() (string, string, error) {
	prkBs, pubBs, err := CreateKey()
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(prkBs), hex.EncodeToString(pubBs), nil
}

func CreateBase64Key() (string, string, error) {
	prkBs, pubBs, err := CreateKey()
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(prkBs), base64.StdEncoding.EncodeToString(pubBs), nil
}

func LoadHexKey(prkHex, pubHex string) (*ecies.PrivateKey, error) {
	prk := &ecies.PrivateKey{}
	if len(prkHex) > 0 {
		privateKeyBytes, err := hex.DecodeString(prkHex)
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

func LoadBase64Key(prkBase64, pubBase64 string) (*ecies.PrivateKey, error) {
	prk := &ecies.PrivateKey{}
	if len(prkBase64) > 0 {
		privateKeyBytes, err := base64.StdEncoding.DecodeString(prkBase64)
		if err != nil {
			return nil, err
		}
		prk.D = new(big.Int).SetBytes(privateKeyBytes)
	}
	if len(pubBase64) > 0 {
		publicKeyBytes, err := hex.DecodeString(pubBase64)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(crypto.S256(), publicKeyBytes)
		pub := ecies.PublicKey{Curve: crypto.S256(), X: x, Y: y, Params: ecies.ECIES_AES128_SHA256}
		prk.PublicKey = pub
	}
	return prk, nil
}

func Encrypt(pub *ecies.PublicKey, msg []byte) (string, error) {
	bs, err := pub.DoEncrypt(msg)
	if err != nil {
		return "", errors.New("encrypt failed")
	}
	return base64.StdEncoding.EncodeToString(bs), nil
}

func Decrypt(prk *ecies.PrivateKey, msg string) (string, error) {
	bs, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", errors.New("base64 parse failed")
	}
	ct, err := prk.DoDecrypt(bs)
	if err != nil {
		return "", err
	}
	return *(*string)(unsafe.Pointer(&ct)), nil
}
