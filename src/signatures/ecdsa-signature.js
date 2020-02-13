import { concat, toBigInt } from '../../../buffer-js/buffer.js'
import { mod_inv } from '../../../numbers-js/numbers.js'
import { generateRandomNonce } from './nonce-generation.js'

/**
 * Sign a message with a private key.
 * 
 * @param {Uint8Array} message - The message.
 * @param {BigInt} privateKey - The private key.
 * @param {Function?} generateNonce - The function to generate a nonce. Default is a random nonce.
 * @return {ArrayBuffer} - The signature.
 *
 * @see https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
 * @see https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
 * @see https://delfr.com/bitcoin/bitcoin-ecdsa-signature
 */
export async function sign(message, privateKey, Curve, Hash, generateNonce = generateRandomNonce) {
    // 1 - Calculate the message hash, using a cryptographic hash function
    const h = (await Hash.hash(message)).toBigInt()

    // 2 - Generate securely a random number k in the range [1..n-1]
    const k = await generateNonce(Curve)
    const k_inv = mod_inv(k, Curve.order)

    // 3 - Calculate the random point R = k * G and take its x-coordinate: r = R.x
    const R = Curve.G.multiply(k)
    const r = R.x.n

    // 4 - Calculate the signature proof s = k^-1 * (h + r * x) mod n
    const x = privateKey
    const s = (k_inv * (h + r * privateKey)) % Curve.order

    // 5 - Return the signature {r, s}
    return { r, s }
}

/**
 * Verify a public key's signature for message.
 * 
 * @param {Uint8Array} message - The message.
 * @param {ArrayBuffer} signature - The signature.
 * @param {Uint8Array} publicKey - The public key.
 * @return {ArrayBuffer} - The signature.
 */
export async function verify(message, signature, publicKey, Curve, Hash) {
    let { r, s } = signature

    // 1 - Calculate the message hash, with the same cryptographic hash function
    const h = (await Hash.hash(message)).toBigInt()

    // 2 - Calculate the modular inverse of the signature proof: s1 = s^−1 (mod n)
    const s_inv = mod_inv(s, Curve.order)

    // 3 - Recover the random point used during the signing: 
    //     R' = (h * s1) * G + (r * s1) * pubKey
    publicKey = Curve.decompress(publicKey)
    const R1 = Curve.G.multiply(h * s_inv).add(publicKey.multiply(r * s_inv))

    // 4 - Take from R' its x-coordinate: r' = R'.x
    const r1 = R1.x

    // 5 - Calculate the signature validation result by comparing whether r' == r
    return r1.equals(r)
}