import { Buffer } from '../../buffer-js/buffer.js'
// Abstract group of elliptic curve points
export class CurvePoint {

    constructor(x, y, isIdentity = false) {
        if (x === undefined) { // Return the default point aka the generator
            this.P = this.constructor.G.P;
        } else if (isIdentity) {
            this._isIdentity = true
        } else {
            this.P = [x, y]
        }
    }

    get x() {
        return this.P[0]
    }

    get y() {
        return this.P[1]
    }

    isIdentity() {
        return this._isIdentity || false
    }

    static identity() {
        return new this.constructor(null, null, true);
    }

    // Check that a point is on the curve defined by y**2 == x**3 + x*a + b
    isWellDefined() {
        if (this.isIdentity())
            return true
        const [x, y] = this.P;
        const [a, b] = [this.constructor.a, this.constructor.b]
        return y.pow(2n).sub(x.pow(3n)).sub(x.mul(a)).equals(b)
    }

    // Elliptic curve doubling
    double() {
        const [x, y] = this.P;
        const a = this.constructor.a || 0
        const l = x.pow(2n).mul(3n).add(a).div(y.mul(2n))
        const newx = l.pow(2n).sub(x.mul(2n))
        const newy = l.neg().mul(newx).add(l.mul(x)).sub(y)
        return new this.constructor(newx, newy)
    }

    // Elliptic curve addition
    add(other) {
        if (this.isIdentity())
            return other
        if (other.isIdentity())
            return this
        if (this.equals(other))
            return this.double()
        if (this.x.equals(other.x))
            return this.constructor.identity()

        const [x1, y1] = this.P
        const [x2, y2] = other.P
        const l = y2.sub(y1).div(x2.sub(x1))
        const newx = l.mul(l).sub(x1).sub(x2)
        const newy = l.neg().mul(newx).add(l.mul(x1)).sub(y1)
        return new this.constructor(newx, newy)
    }

    // Convert P => -P
    neg() {
        if (this.isIdentity())
            return this
        return new this.constructor(this.x, this.y.neg())
    }

    // Elliptic curve point multiplication
    multiply(n) {
        n = BigInt(n)
        if (this.isIdentity())
            return this
        if (n == 0n)
            return this.constructor.identity()
        else if (n == 1n) // FIXME compare to field elements
            return this
        else if (n % 2n === 0n) // FIXME compare to field elements
            return this.double().multiply(n / 2n)
        else
            return this.double().multiply(n / 2n).add(this)
    }

    equals(other) {
        return this.x.equals(other.x) && this.y.equals(other.y)
    }

    toHex() {
        return this.x.n.toString(16)
    }

    isEven(){
        const x = this.x;
        const a = this.constructor.a
        const b = this.constructor.b
        const isEvenY = this.y.n !== x.pow(3n).add(x.mul(a)).add(b).sqrt().n
        return isEvenY
    }

    compress() {
        const isEven = this.isEven() ? '02' : '01'
        return Buffer.fromHex(isEven + this.toHex())
    }

    static decompress(compressed) {
        const isEven = compressed.slice(0, 1)[0] === 2
        const x_int = compressed.slice(1).toBigInt()
        const x = new this.CURVE.FieldElement(x_int)
        const a = this.CURVE.a
        const b = this.CURVE.b
        let y = x.pow(3n).add(x.mul(a)).add(b).sqrt()
        if (isEven) {
            y = y.neg()
        }
        return this.CURVE.fromPoint(x, y)
    }

    static fromPoint(x, y) {
        x = new this.CURVE.FieldElement(x)
        y = new this.CURVE.FieldElement(y)
        return new this.CURVE(x, y)
    }

    static get FieldElement() {
        throw 'Error: abstract method!';
    }

    static get order() {
        throw 'Error: abstract method!';
    }

    static get CURVE() {
        return this.prototype.constructor
    }

    static publicKey(privateKey) {
        return this.G.multiply(privateKey).compress()
    }
}