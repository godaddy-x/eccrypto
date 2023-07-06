package ecc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"unsafe"
)

func hmac256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func hash512(msg []byte) []byte {
	h := sha512.New()
	h.Write(msg)
	r := h.Sum(nil)
	h.Reset()
	return r
}

func hash256(msg []byte) []byte {
	h := sha256.New()
	h.Write(msg)
	r := h.Sum(nil)
	h.Reset()
	return r
}

func concat(iv, time, pub, text []byte) []byte {
	ct := make([]byte, len(iv)+len(time)+len(pub)+len(text))
	copy(ct, iv)
	copy(ct[len(iv):], time)
	copy(ct[len(iv)+len(time):], pub)
	copy(ct[len(iv)+len(time)+len(pub):], text)
	return ct
}

func concatKDF(pub, iv, time, mac, text []byte) []byte {
	ct := make([]byte, len(pub)+len(iv)+len(time)+len(mac)+len(text))
	copy(ct, pub)
	copy(ct[len(pub):], iv)
	copy(ct[len(pub)+len(iv):], time)
	copy(ct[len(pub)+len(iv)+len(time):], mac)
	copy(ct[len(pub)+len(iv)+len(time)+len(mac):], text)
	return ct
}

func randomBytes(l int) ([]byte, error) {
	bs := make([]byte, l)
	_, err := io.ReadFull(rand.Reader, bs)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

func aes256CbcDecrypt(iv, key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	plaintext = pkcs7UnPadding(plaintext)
	return plaintext, nil
}

func aes256CbcEncrypt(iv, key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func aes256CtrEncrypt(iv, key, plaintext []byte) (ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	dst := make([]byte, len(plaintext))
	stream.XORKeyStream(dst, plaintext)
	return dst, nil
}

func aes256CtrDecrypt(iv, key, ciphertext []byte) (m []byte, err error) {
	return aes256CtrEncrypt(iv, key, ciphertext)
}

func hexToBytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

func fillSharedKeyHex(b []byte) []byte {
	sharedKeyHex := hex.EncodeToString(b)
	if len(sharedKeyHex) < 64 {
		cha := 64 - len(sharedKeyHex)
		for i := 0; i < cha; i++ {
			sharedKeyHex = `0` + sharedKeyHex
		}
	}
	return hexToBytes(sharedKeyHex)
}
