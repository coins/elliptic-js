/**
 * Tests for secp256k1
 * @see https://bitcoin.stackexchange.com/questions/50980/test-r-s-values-for-signature-generation
 */
import { Secp256k1 } from '../secp256k1/secp256k1.js';
import * as Schnorr from '../signatures/schnorr-signature.js';
import * as ECDSA from '../signatures/ecdsa-signature.js';
import { Buffer } from '../../../buffer-js/buffer.js';
import { SHA256d } from '../../../hash-js/hash.js';

describe('Secp256k1', function() {

    it('can generate a public key', function() {
        const privateKey = BigInt('0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725')
        const publicKey = Secp256k1.publicKey(privateKey)
        expect(publicKey.toHex()).toBe(('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'))
    })

    describe('Points on the curve', function() {

        it('can be multiplied by a scalar', function() {
            const P = Secp256k1.G.multiply(42n)
            const Q = Secp256k1.fromPoint(
                115136800820456833737994126771386015026287095034625623644186278108926690779567n,
                3479535755779840016334846590594739014278212596066547564422106861430200972724n
            )
            expect(P.equals(Q)).toBeTrue()
        })

        it('are well defined', function() {
            const P = Secp256k1.fromPoint(
                "0x01",
                "0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441"
            );
            expect(P.isWellDefined()).toBeTrue();
        })

        it('can be compressed and decompressed', function() {
            const P = Secp256k1.G.multiply(103n)

            const compressed = P.compress()
            expect(compressed).toBeTruthy()
            const decompressed = Secp256k1.decompress(compressed)

            expect(P.equals(decompressed)).toBeTrue()
        })

    })

    describe('ECDSA Signatures', function() {

        it('can sign and verify a message', async function() {
            const privateKey = 42n
            const publicKey = Secp256k1.publicKey(privateKey)
            const message = Buffer.fromUnicode('abc')
            const signature = await ECDSA.sign(message, privateKey, Secp256k1, SHA256d)
            const result = await ECDSA.verify(message, signature, publicKey, Secp256k1, SHA256d)
            expect(result).toBeTrue()
        })

        it('can sign and verify like bitcoin', async function(){
            const privateKey = 1n
            const message = Buffer.fromUnicode('Satoshi Nakamoto')
            const generateNonce = _ => BigInt('0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15')
            const signature = await ECDSA.sign(message, privateKey, Secp256k1, SHA256d, generateNonce)
            expect(signature.r).toBe(66622713665624427733710315200720396955896638749566533714623508373930515555288n)
            expect(signature.s).toBe(104547365282402277427930334588853961202488080074579832666060404000093909658466n)
        })        

        // it('can sign and verify like bitcoin', async function(){
        //     const privateKey = 8171090786263848904607461762690044565423067553208656222936554536288344837941n
        //     const message = Buffer.fromHex('0100000001b9ee7ae0ad9dad39e9f404e40af5286ad2bc02d5cdb6666aaab89abd7926c0de0000000000ffffffff01e8030000000000001976a9140658b86fc42f78ac1403e187bca17e8431bbf53b88ac00000000')
        //     const generateNonce = _ => BigInt('0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15')
        //     const signature = await ECDSA.sign(message, privateKey, Secp256k1, SHA256d, generateNonce)
        //     console.log(signature)
        //     expect(signature.r).toBe(66622713665624427733710315200720396955896638749566533714623508373930515555288n)
        //     expect(signature.s).toBe(104547365282402277427930334588853961202488080074579832666060404000093909658466n)
        // })
    })

    // describe('Schnorr Signatures', function() {
    //     it('can sign and verify a message', async function() {
    //         const privateKey = 42n
    //         const publicKey = Secp256k1.publicKey(privateKey)
    //         const message = Buffer.fromUnicode('abc')
    //         const signature = await Schnorr.sign(message, privateKey, Secp256k1, SHA256d)
    //         const result = await Schnorr.verify(message, signature, publicKey, Secp256k1, SHA256d)
    //         expect(result).toBeTrue()
    //     })
    // })
})