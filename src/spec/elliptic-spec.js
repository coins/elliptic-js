import './jasmine-3.5.0/boot.js';

// include source files here... 
import { Secp256k1 } from '../secp256k1/secp256k1.js';
import { sign, verify } from '../schnorr-signature/schnorr-signature.js';
import * as Buffer from '../../../buffer-js/src/buffer-utils.js';
import { sha256 } from '../../../hash-js/src/sha.js';

describe('elliptic', function() {

    describe('Points on the curve', function() {

        it('can be multiplied by a scalar', function() {
            const P = Secp256k1.G.multiply(42n)
            const Q = Secp256k1.fromPoint(
                115136800820456833737994126771386015026287095034625623644186278108926690779567n,
                3479535755779840016334846590594739014278212596066547564422106861430200972724n
            )
            expect( P.equals(Q) ).toBeTrue()
        });

        it('are well defined', function() {
            const P = Secp256k1.fromPoint(
                "0x01",
                "0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441"
            );
            expect(P.isWellDefined()).toBeTrue();
        });

        it('can be compressed and decompressed', function() {
            const P = Secp256k1.fromPoint(
                "0x01",
                "0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441"
            );

            const compressed = P.compress();
            expect(compressed).toBeTruthy()
            const decompressed = Secp256k1.decompress(compressed);

            expect(P.equals(decompressed)).toBeTrue()
        });

    });

});


describe('Schnorr Signatures', function() {
    it('can be multiplied by a scalar', async function() {
        const privateKey = 42n;
        const publicKey = Secp256k1.G.multiply(privateKey);
        const message = Buffer.fromUnicode('abc');
        const signature = await sign(message, privateKey, Secp256k1, sha256);
        const result = await verify(message, signature, publicKey, Secp256k1, sha256);
        expect(result).toBeTrue()
    });
});