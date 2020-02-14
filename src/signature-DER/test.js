import { SignatureDER } from './signature-DER.js'

describe('Signature DER (distinguished encoding rules)', function() {

    it('can encode and decode a signature', async function() {
    	const sigHashFlag = '01'
        const encodedExample = '304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a9' + sigHashFlag
        const decoded = SignatureDER.fromHex(encodedExample)
        const encoded = decoded.toHex()
        expect(encoded).toBe(encodedExample)
    })

})