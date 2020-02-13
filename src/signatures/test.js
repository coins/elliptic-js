import { generateNonceRFC6979, generateRandomNonce } from './nonce-generation.js'
import { Buffer } from '../../../buffer-js/buffer.js'
import { Secp256k1 } from '../secp256k1/secp256k1.js'

/**
 * @see https://crypto.stackexchange.com/questions/20838/request-for-data-to-test-deterministic-ecdsa-signature-algorithm-for-secp256k1
 * @see https://bitcointalk.org/index.php?topic=285142.msg3150733
 */
describe('The function "generateNonceRFC6979"', function() {

    xit('generates deterministic nonces', async function() {
        const privateKey = 1n
        const message = Buffer.fromUnicode('Satoshi Nakamoto')
        const nonce = await generateNonceRFC6979(message, privateKey)
        const expectedNonce = BigInt('0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15')
        expect(nonce).toBe(expectedNonce)
    })

})

describe('The function "generateRandomNonce"', function() {

    it('generates non-deterministic nonces', async function() {
        const nonce = await generateRandomNonce(Secp256k1)
        expect(nonce < Secp256k1.order).toBe(true)
    })

})