/**
 * Tests for secp256k1
 * @see https://bitcoin.stackexchange.com/questions/50980/test-r-s-values-for-signature-generation
 */
import { Secp256k1 } from '../secp256k1/secp256k1.js';
import { SHA256d } from '../../../hash-js/hash.js';
import * as Schnorr from '../signatures/schnorr-signature.js';
import * as ECDSA from '../signatures/ecdsa-signature.js';
import { Buffer } from '../../../buffer-js/buffer.js';
import { SignatureDER } from '../signature-DER/signature-DER.js';

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
            expect(P.isWellDefined()).toBeTrue()
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
            expect(signature.s).toBe(11244723954913917995640650419833946650349484204495071716544759141424251835871n) // 104547365282402277427930334588853961202488080074579832666060404000093909658466n) // strict DER encoding
        })        


        it('can verify a DER encoded signature', async function() {
            const message = Buffer.fromHex('0100000001449d45bbbfe7fc93bbe649bb7b6106b248a15da5dbd6fdc9bdfc7efede83235e010000001976a914a235bdde3bb2c326f291d9c281fdc3fe1e956fe088acffffffff014062b007000000001976a914f86f0bc0a2232970ccdf4569815db500f126836188ac0000000001000000')
            const signature = SignatureDER.fromHex('3045022100e15a8ead9013d1de55e71f195c9dc613483f07c8a0692a2144ffa90506436822022062bc9466b9e1941037fc23e1cfadf24c8833f96942beb8f4340df60d506f784b012101')
            const publicKey = Buffer.fromHex('03969a4ac9b1521cfae44a929a614193b0467a20e0a15973cae9ba1efb9627d830')
            const result = await ECDSA.verify(message, signature, publicKey, Secp256k1, SHA256d)
            expect(result).toBeTrue()
        })
    })

    describe('Schnorr Signatures', function() {
        xit('can sign and verify a message', async function() {
            const privateKey = 42n
            const publicKey = Secp256k1.publicKey(privateKey)
            const message = Buffer.fromUnicode('abc')
            const signature = await Schnorr.sign(message, privateKey, Secp256k1, SHA256d)
            const result = await Schnorr.verify(message, signature, publicKey, Secp256k1, SHA256d)
            expect(result).toBeTrue()
        })
    })
})