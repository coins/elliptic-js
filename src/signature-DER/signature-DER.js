import { SerialBuffer, Uint8, toBigInt, fromBigInt } from '../../../buffer-js/buffer.js'
import { Secp256k1 } from '../secp256k1/secp256k1.js'


/**
 * 
 * Class for DER encoded ECC signatures.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#der-encoding
 * @see https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki#der-encoding-reference
 * @see https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature
 * @see https://github.com/libbitcoin/libbitcoin-system/wiki/Sighash-and-TX-Signing
 *
 * 
 * Encoding scheme: 
 *     
 *     `0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]`
 * 
 */
export class SignatureDER extends SerialBuffer {

    /**
     * The r-value of the signature.
     * @type {Uint8Array}
     */
    rValue

    /**
     * The s-value of the signature.
     * @type {Uint8Array}
     */
    sValue

    /** 
     * Convert a pair of Uint8Arrays to a DER encoded Signature.
     * @param  {Uint8Array} rValue - The r-value of the signature.
     * @param  {Uint8Array} sValue - The s-value of the signature.
     */
    constructor(rValue, sValue) {
        super()
        this.rValue = rValue
        this.sValue = sValue

        // Check for low S values in signatures.
        // @see https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
        if (this.s > Secp256k1.order / 2n) {
            this.sValue = fromBigInt(Secp256k1.order - this.s)
        }
    }

    /** 
     * Convert a pair of BigInt to a DER encoded Signature.
     * @param  {BigInt} r - The r-value of the signature.
     * @param  {BigInt} s - The s-value of the signature.
     * @return {SignatureDER}
     */
    static fromBigInts(r, s) {
        r = fromBigInt(r)
        s = fromBigInt(s)
        return new SignatureDER(r, s)
    }

    /** 
     * The signatures "s"-value as BigInt
     * @return {BigInt}
     */
    get s() {
        return toBigInt(this.sValue)
    }

    /** 
     * The signatures "r"-value as BigInt
     * @return {BigInt}
     */
    get r() {
        return toBigInt(this.rValue)
    }

    /**
     * @override
     */
    write(writer) {
        // "DER prefix tag"
        const tag = new Uint8(0x30)
        tag.write(writer)

        // sequence length
        const sequenceLength = new Uint8(this.rValue.byteLength + this.sValue.byteLength + 4)
        sequenceLength.write(writer)

        // marker for the r value
        writer.writeByte(0x02)
        // length of the r value
        writer.writeByte(this.rValue.byteLength)
        // the r value
        writer.writeBytes(this.rValue)

        // marker for the s value
        writer.writeByte(0x02)
        // length of the s value
        writer.writeByte(this.sValue.byteLength)
        // the s value
        writer.writeBytes(this.sValue)
    }

    /**
     * @override
     */
    static read(reader) {
        // "DER prefix tag"
        const tag = Uint8.read(reader)
        // sequence length
        const sequenceLength = Uint8.read(reader)

        // marker for r value
        const rValueMarker = Uint8.read(reader)
        // length of the r value
        const rValueLength = Uint8.read(reader)
        // the r value
        const rValue = reader.readBytes(rValueLength)

        // marker for s value
        const sValueMarker = Uint8.read(reader)
        // length of the s value
        const sValueLength = Uint8.read(reader)
        // the s value
        const sValue = reader.readBytes(sValueLength)

        return new SignatureDER(rValue, sValue)
    }

    /**
     * @override
     */
    byteLength() {
        /*
            1 byte - DER prefix tag
            1 byte - sequenceLength
            1 byte - marker for r value
            1 byte - length of the r value
            1 byte - marker for s value
            1 byte - length of the s value
            ------------------------------
            6 byte - total overhead
         */
        return 6 + this.rValue.byteLength + this.sValue.byteLength
    }
}