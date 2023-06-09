/**
 * @author godaddy-x
 * @elliptic 6.5.4
 * @ecies AES-CBC
 * @curve P256
 */
import * as elliptic from 'elliptic'

const EC = elliptic.ec
const curve = new EC('p256')

/**
 * @param {int} len
 * @returns Buffer
 */
const randomBytes = async function (len) {
    const bytes = new Uint8Array(len)
    await window.crypto.getRandomValues(bytes)
    return Buffer.from(bytes)
}

/**
 * @param {Buffer} iv
 * @param {Buffer} key
 * @param {Buffer} plaintext
 * @returns Buffer
 */
const aes256CbcEncrypt = async function (iv, key, plaintext) {
    const algorithm = { name: 'AES-CBC', iv: iv }
    const keyObj = await window.crypto.subtle.importKey('raw', key, algorithm, false, ['encrypt'])
    const dataBuffer = new TextEncoder().encode(plaintext)
    const encryptedBuffer = await window.crypto.subtle.encrypt(algorithm, keyObj, dataBuffer)
    const encryptedArray = new Uint8Array(encryptedBuffer)
    const encryptedData = Array.prototype.map.call(encryptedArray, x => ('00' + x.toString(16)).slice(-2)).join('')
    return Buffer.from(encryptedData, 'hex')
}

/**
 * @param {string} data
 * @returns Buffer
 */
const sha512 = async function (data) {
    const hashBuffer = await window.crypto.subtle.digest('SHA-512', Buffer.from(data))
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashValue = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    return Buffer.from(hashValue, 'hex')
}

/**
 * @param {string} data
 * @returns Buffer
 */
const sha256 = async function (data) {
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', Buffer.from(data))
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashValue = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    return Buffer.from(hashValue, 'hex')
}

/**
 * @param {Buffer} data
 * @param {Buffer} key
 * @returns Buffer
 */
const hmac256 = async function (data, key) {
    const keyImported = await window.crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: { name: 'SHA-256' } },
        false,
        ['sign']
    )
    const hmacBuffer = await window.crypto.subtle.sign(
        { name: 'HMAC' },
        keyImported,
        data
    )
    const hmacArray = Array.from(new Uint8Array(hmacBuffer))
    const hmacValue = hmacArray.map(b => b.toString(16).padStart(2, '0')).join('')
    return Buffer.from(hmacValue, 'hex')
}

/**
 * @param {PublicKey} publicKey
 * @returns Buffer, Buffer
 */
const derivePublic = function (publicKey) {
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
export const encrypt = async function (pub, msg) {
    const publicKey = curve.keyFromPublic(pub, 'hex')

    const { ephemPublicKey, shared } = derivePublic(publicKey)

    const sharedHash = await sha512(shared)

    const encryptionKey = Buffer.from(sharedHash.buffer, 0, 32)
    const macKey = Buffer.from(sharedHash.buffer, 32)

    const iv = await randomBytes(16)

    const ciphertext = await aes256CbcEncrypt(iv, encryptionKey, msg)

    const hashData = Buffer.concat([iv, ephemPublicKey, ciphertext])

    const realMac = await hmac256(hashData, macKey)

    const response = Buffer.concat([ephemPublicKey, iv, realMac, ciphertext]).toString('base64')
    return response
}

/**
 * @param {hex} privateKey
 * @param {string} msg
 * @returns string(hex)
 */
export const sign = async function (privateKey, msg) {
    const EC = elliptic.ec
    const curve = new EC('p256')
    const keyPair = curve.keyFromPrivate(privateKey, 'hex')
    const hash = await sha256(msg)
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
export const verify = async function (publicKey, msg, sign) {
    const EC = elliptic.ec
    const curve = new EC('p256')
    const keyPair = curve.keyFromPublic(publicKey, 'hex')
    const hash = await sha256(msg)
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
export const encryptByBase64Public = async function (publicKey, data) {
    const result = await encrypt(Buffer.from(publicKey, 'base64').toString('hex'), Buffer.from(data))
    return result
}

/**
 * @param {string} data
 * @param {hex} publicKey
 * @returns string(base64)
 */
export const encryptByHexPublic = async function (publicKey, data) {
    const result = await encrypt(publicKey, Buffer.from(data))
    return result
}
