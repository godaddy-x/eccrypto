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
	return h.Sum(nil)
}

func hash256(msg []byte) []byte {
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
}

func mergeMessage(pub, iv, text []byte) []byte {
	ct := make([]byte, len(pub)+len(iv)+len(text))
	copy(ct, pub)
	copy(ct[len(pub):], iv)
	copy(ct[len(pub)+len(iv):], text)
	return ct
}

func concatMessage(pub, iv, mac, text []byte) []byte {
	ct := make([]byte, len(pub)+len(iv)+len(mac)+len(text))
	copy(ct, pub)
	copy(ct[len(pub):], iv)
	copy(ct[len(pub)+len(iv):], mac)
	copy(ct[len(pub)+len(iv)+len(mac):], text)
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
	// 对明文进行 ZeroPadding 填充
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

// fillSharedKeyHex 字节操作优化版本 - 与原始字符串逻辑等价
func fillSharedKeyHex(b []byte) []byte {
	// 原始逻辑：bytes -> hex string -> 补0到64字符 -> []byte(string)
	// 等价于：创建64字节数组，前面的补0部分填入'0'的ASCII，后面填入hex字符的ASCII

	const sharedKeyHexLen = 64
	result := make([]byte, sharedKeyHexLen)

	// 生成hex字符串
	hexStr := hex.EncodeToString(b)

	// 计算需要补多少个'0'
	padding := sharedKeyHexLen - len(hexStr)

	// 处理不同情况
	if padding >= 0 {
		// 输入 <= 32字节，需要补0
		// 前面补'0'的ASCII值
		for i := 0; i < padding; i++ {
			result[i] = '0'
		}
		// 后面填入hex字符的ASCII值
		copy(result[padding:], hexStr)
	} else {
		// 输入 > 32字节，hex字符串 > 64字符
		// 复制hex字符串的前64个字符
		copy(result, hexStr[:sharedKeyHexLen])
	}

	return result
}
