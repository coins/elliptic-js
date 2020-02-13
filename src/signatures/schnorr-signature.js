import { concat } from '../../../buffer-js/buffer.js'
import { generateNonceRFC6979 } from './nonce-generation.js'

/**
 * Sign a message with a private key.
 * @param {Uint8Array} message - The message.
 * @param {Uint8Array} privateKey - The private key.
 * @param {Function} generateNonce - The function to generate a nonce. Default is RFC6979.
 * @return {ArrayBuffer} - The signature
 */
export async function sign(message, privateKey, Curve, Hash, generateNonce = generateNonceRFC6979) {
    const r = await generateNonce(message, privateKey)
    const R = Curve.G.multiply(r).compress()
    const m = concat(message, R)
    const h = (await Hash.hash(m)).toBigInt()
    const s = (r + h * privateKey) % Curve.order
    return { R, s }
}

/**
 * Verify a public key's signature for message.
 * @param {Uint8Array} message - The message.
 * @param {ArrayBuffer} signature - The signature.
 * @param {Uint8Array} publicKey - The public key.
 * @return {ArrayBuffer} - The signature
 */
export async function verify(message, signature, publicKey, Curve, Hash) {
    let { R, s } = signature
    const m = concat(message, R)
    const h = (await Hash.hash(m)).toBigInt()

    const S = Curve.G.multiply(s)

    R = Curve.decompress(R)
    publicKey = Curve.decompress(publicKey)
    return publicKey.multiply(h).add(R).equals(S)

}