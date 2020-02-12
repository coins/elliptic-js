import { Secp256k1 } from '../secp256k1/secp256k1.js';
import * as Schnorr from '../schnorr-signature/schnorr-signature.js';
import * as ECDSA from '../ecdsa-signature/ecdsa-signature.js';
import * as Buffer from '../../../buffer-js/src/buffer-utils/buffer-utils.js';
import { SHA256 } from '../../../hash-js/hash.js';

describe('Secp256k1', function() {

    it('can generate a public key', function() {
        const privateKey = BigInt('0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725')
        const publicKey = Secp256k1.publicKey(privateKey)
        expect(publicKey.toHex()).toBe(('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'))
    });

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
            const P = Secp256k1.fromPoint(
                115136800820456833737994126771386015026287095034625623644186278108926690779567n,
                3479535755779840016334846590594739014278212596066547564422106861430200972724n
            );

            const compressed = P.compress()
            expect(compressed).toBeTruthy()
            const decompressed = Secp256k1.decompress(compressed)

            expect(P.equals(decompressed)).toBeTrue()
        })
    })

    describe('Schnorr Signatures', function() {
        it('can sign and verify a message', async function() {
            const privateKey = 42n;
            const publicKey = Secp256k1.publicKey(privateKey)
            const message = Buffer.fromUnicode('abc');
            const signature = await Schnorr.sign(message, privateKey, Secp256k1, SHA256);
            const result = await Schnorr.verify(message, signature, publicKey, Secp256k1, SHA256);
            expect(result).toBeTrue()
        })
    })

    describe('ECDSA Signatures', function() {
        it('can sign and verify a message', async function() {
            const privateKey = 42n;
            const publicKey = Secp256k1.publicKey(privateKey)
            const message = Buffer.fromUnicode('abc')
            const signature = await ECDSA.sign(message, privateKey, Secp256k1, SHA256);
            const result = await ECDSA.verify(message, signature, publicKey, Secp256k1, SHA256);
            expect(result).toBeTrue()
        });
    });

});