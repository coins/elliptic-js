import { hmac_sha256 } from '../../../hash-js/hash.js'
import { concat, fromBigInt, toBigInt, randomBytes } from '../../../buffer-js/buffer.js'

/**
 * Generates a random nonce for a signature.
 * @param  {Curve} - The class of curve points.
 * @return {BigInt} - A random nonce.
 */
export async function generateRandomNonce(Curve) {
    // TODO: replace this function with randomBigInt from bigint-math.js
    let nonce = toBigInt(randomBytes(32))
    // The nonce must be an element of the scalar field 
    while (nonce > Curve.order) {
        // If it is too big, we generate another one
        nonce = toBigInt(randomBytes(32))
    }
    return nonce
}

/**
 * An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
 * @param  {Buffer} message - The message.
 * @param  {BigInt} privateKey - The private key.
 * @param  {Function?} hmac - The HMAC function (optional).
 * @return {BigInt} - The generated nonce.
 *
 * @see https://tools.ietf.org/html/rfc6979#section-3.2
 */
export async function generateNonceRFC6979(message, privateKey, hmac = hmac_sha256) {
    console.warn('Caution! RFC6979 not implemented properly.')
    const nonce = await hmac(fromBigInt(privateKey), message)
    return toBigInt(nonce)
}

// TODO: actually implement RFC6979...

/*

3.2 Generation of k
Given the input message m, the following process is applied:

   a.  Process m through the hash function H, yielding:

          h1 = H(m)

       (h1 is a sequence of hlen bits).

   b.  Set:

          V = 0x01 0x01 0x01 ... 0x01

       such that the length of V, in bits, is equal to 8*ceil(hlen/8).
       For instance, on an octet-based system, if H is SHA-256, then V
       is set to a sequence of 32 octets of value 1.  Note that in this
       step and all subsequent steps, we use the same H function as the
       one used in step 'a' to process the input message; this choice
       will be discussed in more detail in Section 3.6.

   c.  Set:

          K = 0x00 0x00 0x00 ... 0x00

       such that the length of K, in bits, is equal to 8*ceil(hlen/8).

   d.  Set:

          K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))

       where '||' denotes concatenation.  In other words, we compute
       HMAC with key K, over the concatenation of the following, in
       order: the current value of V, a sequence of eight bits of value
       0, the encoding of the (EC)DSA private key x, and the hashed
       message (possibly truncated and extended as specified by the
       bits2octets transform).  The HMAC result is the new value of K.
       Note that the private key x is in the [1, q-1] range, hence a
       proper input for int2octets, yielding rlen bits of output, i.e.,
       an integral number of octets (rlen is a multiple of 8).

   e.  Set:

          V = HMAC_K(V)

   f.  Set:

          K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))

       Note that the "internal octet" is 0x01 this time.

   g.  Set:

          V = HMAC_K(V)

   h.  Apply the following algorithm until a proper value is found for
       k:

       1.  Set T to the empty sequence.  The length of T (in bits) is
           denoted tlen; thus, at that point, tlen = 0.

       2.  While tlen < qlen, do the following:

              V = HMAC_K(V)

              T = T || V

       3.  Compute:

              k = bits2int(T)

           If that value of k is within the [1,q-1] range, and is
           suitable for DSA or ECDSA (i.e., it results in an r value
           that is not 0; see Section 3.4), then the generation of k is
           finished.  The obtained value of k is used in DSA or ECDSA.
           Otherwise, compute:

              K = HMAC_K(V || 0x00)

              V = HMAC_K(V)

           and loop (try to generate a new T, and so on).

   Please note that when k is generated from T, the result of bits2int
   is compared to q, not reduced modulo q.  If the value is not between
   1 and q-1, the process loops.  Performing a simple modular reduction
   would induce biases that would be detrimental to signature security.


 */