import './jasmine-3.5.0/boot.js';

// include source files here... 
import './spec-helper.js';
import { Secp256k1 } from '../secp256k1/secp256k1.js';
import { sign, verify } from '../schnorr-signature/schnorr-signature.js';
import * as Buffer from '../../../buffer-js/src/buffer-utils.js';
import { sha256 } from '../../../hash-js/src/sha.js';

describe('elliptic', function() {
    let curvePoint;

    beforeEach(function() {
        curvePoint = new Secp256k1()
    });

    describe('A point on the curve', function() {

        it('can be multiplied by a scalar', function() {
            curvePoint.multiply(42n)
        });

        it('are well defined', function() {
            const p = Secp256k1.fromPoint(
                "0x01",
                "0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441"
            );

            expect(p.isWellDefined()).toBeTrue();

        });

        it('can be compressed and decompressed', function() {
            const p = Secp256k1.fromPoint(
                "0x01",
                "0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441"
            );

            const compressed = p.compress();
            const decompressed = Secp256k1.decompress(compressed);

            expect(p.equals(decompressed)).toBeTrue()
        });

    });

});


describe('Schnorr Signatures', function() {
    let curvePoint;

    beforeEach(function() {
        curvePoint = new Secp256k1();
    });

    describe('can sign a message', function() {
        it('can be multiplied by a scalar', async function() {
            const privateKey = 42n;
            const publicKey = curvePoint.multiply(privateKey);
            const message = Buffer.fromUnicode('abc');
            const signature = await sign(message, privateKey, Secp256k1, sha256);
            console.log(signature)
            verify(message, signature, publicKey, Secp256k1, sha256);
        });
    });

});