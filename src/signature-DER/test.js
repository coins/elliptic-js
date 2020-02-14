import { SignatureDER } from './signature-DER.js'
// import { Buffer } from '../../../buffer-js/buffer.js'

describe('Signature DER (distinguished encoding rules)', function() {

    it('can encode and decode a signature', async function() {
        const encodedExample = '304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a9'
   		const decoded = SignatureDER.fromHex(encodedExample)
   		const encoded = decoded.toHex()
   		expect(encoded).toBe(encodedExample)



   		// console.log( new SignatureDER(
   		// 	Buffer.fromBigInt(66622713665624427733710315200720396955896638749566533714623508373930515555288n), 
   		// 	Buffer.fromBigInt(68653793658067006591589941737427614138567411446828702337612173227483835203372n)
   		// ) )
    })

})