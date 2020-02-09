import { instantiateField } from '../../../finite-field-js/src/finite-field.js'
import { CurvePoint } from '../elliptic.js'

// The finite field FQ
export const FQ = instantiateField(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn)

/**
* The group of points on curve Secp256k1 over FQ
*/
export class Secp256k1 extends CurvePoint {

    static get order() {
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n
    }

    static get a() {
        return new FQ(0)
    }

    static get b() {
        return new FQ(7)
    }

    static get G() {
        return new Secp256k1(
            new FQ(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n),
            new FQ(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n)
        )
    }
}
