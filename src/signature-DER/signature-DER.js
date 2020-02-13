import { SerialBuffer, Uint8 } from '../../../buffer-js/buffer.js'
/**
 * DER encoding for signatures
 * @see https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature
 */
export class SignatureDER extends SerialBuffer {

    constructor(rValue, sValue) {
        super()
        this.rValue = rValue
        this.sValue = sValue
    }

    /**
     * @override
     */
    write(writer) {
        // write the "tag"
        const tag = new Uint8(48)
        tag.write(writer)

        // write the sequence length
        const sequenceLength = new Uint8(this.rValue.byteLength + this.sValue.byteLength + 4)
        sequenceLength.write(writer)

        writer.writeByte(2) // integerElement1
        writer.writeByte(this.rValue.byteLength) // element1Length
        writer.writeBytes(this.rValue)

        writer.writeByte(2) // integerElement2
        writer.writeByte(this.sValue.byteLength) // element2Length
        writer.writeBytes(this.sValue)
    }

    /**
     * @override
     */
    byteLength() {
        return this.rValue.byteLength + this.sValue.byteLength + 4 + 2
    }

    /**
     * @override
     */
    static read(reader) {
        const tag = Uint8.read(reader)
        const sequenceLength = Uint8.read(reader)
        const integerElement1 = Uint8.read(reader)
        const elementLength1 = Uint8.read(reader)
        const rValue = reader.readBytes(elementLength1)

        const integerElement2 = Uint8.read(reader)
        const elementLength2 = Uint8.read(reader)
        const sValue = reader.readBytes(elementLength2)

        return new SignatureDER(rValue, sValue)
    }
}