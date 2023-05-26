import * as elliptic from 'elliptic'
import CryptoJS from "crypto-js";

/**
 * @param {int} len
 * @returns Buffer
 */
const randomBytes = function (length: number) {
    const str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    let result = ''
    for (let i = length; i > 0; --i) {
        result += str[Math.floor(Math.random() * str.length)]
    }
    return Buffer.from(result)
}

/**
 * Encrypts plaintext using AES-256-CBC.
 *
 * @param {Buffer} iv The initialization vector.
 * @param {Buffer} key The encryption key.
 * @param {Buffer} plaintext The plaintext to encrypt.
 * @returns {Buffer} The ciphertext.
 */
const aes256CbcEncrypt = (iv: Buffer, key: Buffer, plaintext: Buffer): Buffer => {
    const text = CryptoJS.enc.Hex.parse(plaintext.toString('hex'));
    const keyWordArray = CryptoJS.enc.Hex.parse(key.toString('hex'));
    const ivWordArray = CryptoJS.enc.Hex.parse(iv.toString('hex'));
    const encrypted = CryptoJS.AES.encrypt(text, keyWordArray, {
        iv: ivWordArray,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    });
    return Buffer.from(encrypted.ciphertext.toString(CryptoJS.enc.Hex), 'hex');
};

/**
 * Compute SHA-512 hash of the data
 *
 * @param {string} data The data to hash.
 * @returns {Buffer} The SHA-512 hash of the data.
 */
const sha512 = (data: string): Buffer => {
    const wordArray = CryptoJS.enc.Utf8.parse(data);
    const hashValue = CryptoJS.SHA512(wordArray);
    const hashString = CryptoJS.enc.Hex.stringify(hashValue);
    return Buffer.from(hashString, 'hex');
};

/**
 * Compute SHA-256 hash of the data
 *
 * @param {string} data The data to hash.
 * @returns {Buffer} The SHA-256 hash of the data.
 */
const sha256 = function (data: string): Buffer {
    const wordArray = CryptoJS.enc.Utf8.parse(data);
    const hashValue = CryptoJS.SHA256(wordArray)
    const hashString = CryptoJS.enc.Hex.stringify(hashValue);
    return Buffer.from(hashString, 'hex')
}

/**
 * Compute HMAC-SHA256 of the data.
 *
 * @param {Buffer} data The data.
 * @param {Buffer} key The key.
 * @returns {Buffer} The HMAC-SHA256 value.
 */
const hmac256 = (data: Buffer, key: Buffer): Buffer => {
    const keyWordArray = CryptoJS.enc.Hex.parse(key.toString('hex'));
    const messageWordArray = CryptoJS.enc.Hex.parse(data.toString('hex'));
    const hmacValue = CryptoJS.HmacSHA256(messageWordArray, keyWordArray);
    return Buffer.from(hmacValue.toString(CryptoJS.enc.Hex), 'hex');
};

/**
 * @param {EC} curve
 * @param {PublicKey} publicKey
 * @returns Buffer, Buffer
 */
const derivePublic = function (curve: elliptic.ec, publicKey: elliptic.ec.KeyPair) {
    const tempPrivate = curve.genKeyPair()
    const tempPublic = tempPrivate.getPublic()
    const ephemPublicKey = Buffer.from(tempPublic.encode('hex', false), 'hex')
    let shared = tempPrivate.derive(publicKey.getPublic()).toString('hex')
    if (shared.length < 64) {
        const slen = 64 - shared.length
        for (let i = 0; i < slen; i++) {
            shared = '0' + shared
        }
    }
    return { ephemPublicKey, shared }
}

/**
 * @param {hex} pub
 * @param {Buffer} msg
 * @returns string(base64)
 */
export const encrypt = function (pub: string | Uint8Array | Buffer | number[] | elliptic.ec.KeyPair | { x: string; y: string }, msg: Buffer) {
    const EC = elliptic.ec
    const curve = new EC('p256')
    const publicKey = curve.keyFromPublic(pub, 'hex')
    const { ephemPublicKey, shared } = derivePublic(curve, publicKey)

    const sharedHash = sha512(shared)

    const encryptionKey = sharedHash.slice(0, 32)
    const macKey = sharedHash.slice(32)

    const iv = randomBytes(16)
    const ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg)
    const hashData = Buffer.concat([iv, ephemPublicKey, ciphertext])

    const realMac = hmac256(hashData, macKey)

    const response = Buffer.concat([ephemPublicKey, iv, realMac, ciphertext]).toString('base64')
    return response
}

/**
 * @param {hex} privateKey
 * @param {string} msg
 * @returns string(hex)
 */
export const sign = function (privateKey: string | Uint8Array | Buffer | number[] | elliptic.ec.KeyPair, msg: any) {
    const EC = elliptic.ec
    const curve = new EC('p256')
    const keyPair = curve.keyFromPrivate(privateKey, 'hex')
    const hash = sha256(msg)
    const signature = keyPair.sign(hash)
    const r = signature.r.toString('hex')
    const s = signature.s.toString('hex')
    return r + s
}

/**
 * @param {hex} publicKey
 * @param {string} msg
 * @param {hex} sign
 * @returns boolean
 */
export const verify = function (publicKey: string | Uint8Array | Buffer | number[] | elliptic.ec.KeyPair | { x: string; y: string }, msg: any, sign: string) {
    const EC = elliptic.ec
    const curve = new EC('p256')
    const keyPair = curve.keyFromPublic(publicKey, 'hex')
    const hash = sha256(msg)
    const r = sign.slice(0, 64)
    const s = sign.slice(64)
    const signature = {
        r: Buffer.from(r, 'hex'),
        s: Buffer.from(s, 'hex')
    }
    return keyPair.verify(hash, signature)
}

/**
 * @param {string} data
 * @param {base64} publicKey
 * @returns string(base64)
 */
export const encryptByBase64Public = function (publicKey: WithImplicitCoercion<string> | { [Symbol.toPrimitive](hint: "string"): string }, data: string) {
    const result = encrypt(Buffer.from(publicKey, 'base64').toString('hex'), Buffer.from(data))
    return result
}

/**
 * @param {string} data
 * @param {hex} publicKey
 * @returns string(base64)
 */
export const encryptByHexPublic = function (publicKey: any, data: string) {
    const result = encrypt(publicKey, Buffer.from(data))
    return result
}
