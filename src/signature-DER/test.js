import { SignatureDER } from './signature-DER.js'

describe('Signature DER (distinguished encoding rules)', function() {

    it('can encode and decode a signature', async function() {
        const encodedExample = '304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a9'
        const decoded = SignatureDER.fromHex(encodedExample)
        const encoded = decoded.toHex()
        expect(encoded).toBe(encodedExample)
    })    


    it('can encode and decode a signature', async function() {
        const encodedExample = '3045022100afff580595971b8c1700e77069d73602aef4c2a760dbd697881423dfff845de80220579adb6a1ac03acde461b5821a049ebd39a8a8ebf2506b841b15c27342d2e342'
        const decoded = SignatureDER.fromHex(encodedExample)
        const encoded = decoded.toHex()
        expect(encoded).toBe(encodedExample)
    })



})