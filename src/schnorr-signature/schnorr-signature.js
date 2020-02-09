import * as Buffer from '../../../buffer-js/src/buffer-utils.js'

/**
 * Sign a message with a private key.
 * @param {Uint8Array} message - The message.
 * @param {Uint8Array} privateKey - The private key.
 * @param {Function} generateNonce - The function to generate a nonce. Default is RFC6979.
 * @return {ArrayBuffer} - The signature
 */
export async function sign(message, privateKey, Curve, Hash, generateNonce = generateNonceRFC6979) {
    const r = await generateNonce(message, privateKey, Hash);
    const R = Buffer.fromBigInt(Curve.G.multiply(r).compress());
    const m = Buffer.concat(message, R);
    const h = Buffer.toBigInt(await Hash(m));
    const s = (r + h * privateKey) % (Curve.modulus - 1n);
    return { R, s }
}


/** An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
 * https://tools.ietf.org/html/rfc6979
 */
async function generateNonceRFC6979(message, privateKey, Hash) {
    const m = Buffer.concat(message, Buffer.fromBigInt(privateKey));
    return Buffer.toBigInt(await Hash(m));
}

/**
 * Verify a public key's signature for message.
 * @param {Uint8Array} message - The message.
 * @param {ArrayBuffer} signature - The signature.
 * @param {Uint8Array} publicKey - The public key.
 * @return {ArrayBuffer} - The signature
 */
export function verify(message, signature, publicKey, Curve, Hash) {
    const { R, s } = signature;
    const h = Buffer.toBigInt( Buffer.concat(message, R) );

    const S = Curve.G.multiply(s);

    console.log(message, signature, publicKey, Curve, Hash)
    return publicKey.multiply(h).add(R).equals(S)

}