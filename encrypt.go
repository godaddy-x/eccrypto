package ecc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	iLen   = 16
	mLen   = 32
	pLen   = 65
	minLen = 113
	secLen = 81
)

var (
	defaultCurve = elliptic.P256() // default use p256
)

func CreateECDSA() (*ecdsa.PrivateKey, error) {
	prk, err := ecdsa.GenerateKey(defaultCurve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return prk, nil
}

func LoadHexPrivateKey(h string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad private key")
	}
	prk, err := x509.ParseECPrivateKey(b)
	if err != nil {
		return nil, errors.New("parse private key failed")
	}
	return prk, nil
}

func LoadBase64PrivateKey(h string) (*ecdsa.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad private key")
	}
	prk, err := x509.ParseECPrivateKey(b)
	if err != nil {
		return nil, errors.New("parse private key failed")
	}
	return prk, nil
}

func LoadPublicKey(h []byte) (*ecdsa.PublicKey, error) {
	if len(h) != pLen {
		return nil, errors.New("publicKey invalid")
	}
	x, y := elliptic.Unmarshal(defaultCurve, h)
	if x == nil || y == nil {
		return nil, errors.New("bad point format")
	}
	return &ecdsa.PublicKey{Curve: defaultCurve, X: x, Y: y}, nil
}

func LoadBase64PublicKey(b64 string) (*ecdsa.PublicKey, []byte, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, err
	}
	pub, err := LoadPublicKey(b)
	if err != nil {
		return nil, nil, err
	}
	pubBs := elliptic.Marshal(defaultCurve, pub.X, pub.Y)
	return pub, pubBs, nil
}

func LoadHexPublicKey(h string) (*ecdsa.PublicKey, []byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, nil, err
	}
	pub, err := LoadPublicKey(b)
	if err != nil {
		return nil, nil, err
	}
	pubBs := elliptic.Marshal(defaultCurve, pub.X, pub.Y)
	return pub, pubBs, nil
}

func GetPublicKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	_, pubBs, err := GetObjectBytes(nil, pub)
	if err != nil {
		return nil, err
	}
	return pubBs, nil
}

func GetObjectBytes(prk *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	var err error
	var prkBs, pubBs []byte
	if prk != nil {
		prkBs, err = x509.MarshalECPrivateKey(prk)
		if err != nil {
			return nil, nil, err
		}
	}
	if pub != nil {
		pubBs = elliptic.Marshal(defaultCurve, pub.X, pub.Y)
	}
	return prkBs, pubBs, nil
}

func GetObjectBase64(prk *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (string, string, error) {
	prkBs, pubBs, err := GetObjectBytes(prk, pub)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(prkBs), base64.StdEncoding.EncodeToString(pubBs), nil
}

func GetObjectHex(prk *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (string, string, error) {
	prkBs, pubBs, err := GetObjectBytes(prk, pub)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(prkBs), hex.EncodeToString(pubBs), nil
}

func GenSharedKey(ownerPrk *ecdsa.PrivateKey, otherPub *ecdsa.PublicKey) ([]byte, error) {
	sharedKey, _ := defaultCurve.ScalarMult(otherPub.X, otherPub.Y, ownerPrk.D.Bytes())
	if sharedKey == nil || len(sharedKey.Bytes()) == 0 {
		return nil, errors.New("shared failed")
	}
	return fillSharedKeyHex(sharedKey.Bytes()), nil
}

func Encrypt(publicTo, message []byte) ([]byte, error) {
	if len(publicTo) != pLen {
		return nil, errors.New("bad public key")
	}
	pub, err := LoadPublicKey(publicTo)
	if err != nil {
		return nil, errors.New("public key invalid")
	}
	// temp private key
	prk, err := CreateECDSA()
	if err != nil {
		return nil, err
	}

	sharedKeyHex, err := GenSharedKey(prk, pub)
	if err != nil {
		return nil, err
	}

	sharedKeyHash := hash512(sharedKeyHex)
	macKey := sharedKeyHash[mLen:]
	encryptionKey := sharedKeyHash[0:mLen]

	iv, err := randomBytes(iLen)
	if err != nil {
		return nil, errors.New("random iv failed")
	}

	ciphertext, err := aes256CbcEncrypt(iv, encryptionKey, message)
	if err != nil {
		return nil, errors.New("encrypt failed")
	}

	ephemPublicKey, err := GetPublicKeyBytes(&prk.PublicKey)
	if err != nil {
		return nil, errors.New("temp public key invalid")
	}
	hashData := concat(iv, ephemPublicKey, ciphertext)
	realMac := hmac256(macKey, hashData)

	return concatKDF(ephemPublicKey, iv, realMac, ciphertext), nil
}

func Decrypt(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	if len(msg) <= minLen {
		return nil, errors.New("bad msg data")
	}

	ephemPublicKey := msg[0:pLen]
	pub, err := LoadPublicKey(ephemPublicKey)
	if err != nil {
		return nil, errors.New("bad public key")
	}

	sharedKey, _ := defaultCurve.ScalarMult(pub.X, pub.Y, privateKey.D.Bytes())
	if sharedKey == nil || len(sharedKey.Bytes()) == 0 {
		return nil, errors.New("shared failed")
	}

	sharedKeyHex := fillSharedKeyHex(sharedKey.Bytes())
	sharedKeyHash := hash512(sharedKeyHex)

	macKey := sharedKeyHash[mLen:]
	encryptionKey := sharedKeyHash[0:mLen]

	iv := msg[pLen:secLen]
	mac := msg[secLen:minLen]
	ciphertext := msg[minLen:]

	hashData := concat(iv, ephemPublicKey, ciphertext)

	realMac := hmac256(macKey, hashData)

	if !bytes.Equal(mac, realMac) {
		return nil, errors.New("mac invalid")
	}

	plaintext, err := aes256CbcDecrypt(iv, encryptionKey, ciphertext)
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	return plaintext, nil
}
