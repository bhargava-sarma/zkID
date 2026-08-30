pragma circom 2.1.6;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";

/*
 * CredentialAgeProof
 *
 * Proves, in zero knowledge, all of the following about one credential at once:
 *
 *   1. The issuer whose modulus is public signed a payload (RSASSA-PKCS1-v1_5
 *      over SHA-256).
 *   2. That payload contains the key `"dob":"` exactly once.
 *   3. The 10-byte value following that key is a well-formed YYYY-MM-DD date.
 *   4. That date is on or before a public threshold date, i.e. the subject is
 *      old enough.
 *
 * The binding is the point. The date is not an input -- it is extracted from the
 * very bytes the signature covers, so there is no way to present a date that
 * differs from the signed one. A prover supplies `dobIndex` as a hint, but the
 * uniqueness scan constrains it to the one position where the key actually is.
 *
 * Private: msg, signature, dobIndex.  Public: modulus, thresholdDate.
 * A verifier learns which issuer signed and that the subject is old enough.
 * It does not learn the name, the id number, the gender, or the date of birth.
 *
 * SCOPE: this is fixed-key, fixed-width extraction from a canonically
 * serialized payload -- NOT a general JSON parser. It requires the key to be
 * exactly `"dob":"` with no whitespace variation, and the value to be exactly
 * 10 bytes. It does NOT require the field to be in any particular position.
 */
template CredentialAgeProof(PAYLOAD_BYTES) {
    // The signed payload, space-padded to a fixed width by the issuer.
    signal input msg[PAYLOAD_BYTES];
    signal input signature[17];
    signal input modulus[17];
    // Prover hint: byte offset of `"dob":"`. Fully constrained below, so a wrong
    // value cannot produce a witness.
    signal input dobIndex;
    // year*10000 + month*100 + day. Subject is old enough iff dob <= this.
    signal input thresholdDate;

    var PAYLOAD_BITS = PAYLOAD_BYTES * 8;
    var N = 121;
    var K = 17;

    // =========================================================================
    // 1. Bytes -> bits
    // =========================================================================
    // Num2Bits doubles as a range check: it constrains each msg[i] to 8 bits, so
    // a prover cannot smuggle a field element larger than a byte into the hash.
    component byteBits[PAYLOAD_BYTES];
    signal shaIn[PAYLOAD_BITS];
    for (var i = 0; i < PAYLOAD_BYTES; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== msg[i];
        for (var j = 0; j < 8; j++) {
            // SHA-256 consumes bits most-significant-first within each byte;
            // Num2Bits emits least-significant-first. Hence the 7 - j.
            shaIn[i * 8 + j] <== byteBits[i].out[7 - j];
        }
    }

    // =========================================================================
    // 2. SHA-256 over the whole padded payload
    // =========================================================================
    component sha = Sha256(PAYLOAD_BITS);
    for (var i = 0; i < PAYLOAD_BITS; i++) {
        sha.in[i] <== shaIn[i];
    }

    // =========================================================================
    // 3. Digest bits -> 121-bit limbs (the SHA->RSA glue)
    // =========================================================================
    // sha.out[0] is the MOST significant bit of the digest. Reading the digest
    // as a big-endian integer D, the bit at LSB-position p is sha.out[255 - p].
    // Limb j holds bits [121j, 121j+121). Limbs 3..16 are zero because the
    // digest is only 256 bits -- RSAPad separately constrains exactly that.
    component digestLimb[K];
    signal message[K];
    for (var j = 0; j < K; j++) {
        digestLimb[j] = Bits2Num(N);
        for (var k = 0; k < N; k++) {
            var bitPos = j * N + k;
            if (bitPos < 256) {
                digestLimb[j].in[k] <== sha.out[255 - bitPos];
            } else {
                digestLimb[j].in[k] <== 0;
            }
        }
        message[j] <== digestLimb[j].out;
    }

    // =========================================================================
    // 4. RSA verification
    // =========================================================================
    // RSAVerifier65537 pads `message` per EMSA-PKCS1-v1_5 internally and checks
    // signature^65537 mod modulus against it.
    component rsa = RSAVerifier65537(N, K);
    rsa.message <== message;
    rsa.signature <== signature;
    rsa.modulus <== modulus;

    // =========================================================================
    // 5. Locate `"dob":"` -- exactly once
    // =========================================================================
    var PLEN = 7;
    var PAT[7] = [34, 100, 111, 98, 34, 58, 34];   // " d o b " : "
    var POS = PAYLOAD_BYTES - PLEN + 1;

    signal acc[POS][PLEN + 1];
    component isz[POS];
    signal matchAt[POS];
    var matchTotal = 0;
    var indexTotal = 0;
    for (var p = 0; p < POS; p++) {
        acc[p][0] <== 0;
        for (var k = 0; k < PLEN; k++) {
            // Squared difference: zero iff the byte matches the pattern byte.
            acc[p][k + 1] <== acc[p][k] + (msg[p + k] - PAT[k]) * (msg[p + k] - PAT[k]);
        }
        isz[p] = IsZero();
        isz[p].in <== acc[p][PLEN];
        matchAt[p] <== isz[p].out;
        matchTotal += matchAt[p];
        indexTotal += p * matchAt[p];
    }
    // Exactly one occurrence. Without this a prover could point dobIndex at any
    // other position where the pattern happened to appear.
    matchTotal === 1;
    // And that occurrence is the one the prover claims.
    indexTotal === dobIndex;

    // =========================================================================
    // 6. Shift the payload so dobIndex sits at offset 0
    // =========================================================================
    // One O(n log n) pass; afterwards every byte of interest is at a constant
    // offset, which is far cheaper than an indexed lookup per byte.
    component shifter = VarShiftLeft(PAYLOAD_BYTES, 17);
    shifter.in <== msg;
    shifter.shift <== dobIndex;

    // Redundant with the scan, but cheap (linear) and makes the layout explicit.
    for (var k = 0; k < PLEN; k++) {
        shifter.out[k] === PAT[k];
    }
    // YYYY-MM-DD: separators at value offsets 4 and 7.
    shifter.out[PLEN + 4] === 45;   // '-'
    shifter.out[PLEN + 7] === 45;   // '-'

    // =========================================================================
    // 7. Range-check the 8 digit bytes
    // =========================================================================
    // Not optional. zk-email's DigitBytesToInt assumes 48..57 without checking,
    // and an unchecked byte here would let a crafted payload encode an arbitrary
    // "date". Num2Bits(4) bounds the digit below 16; LessThan(4) pins it under 10.
    var DIG[8] = [0, 1, 2, 3, 5, 6, 8, 9];
    component digitBits[8];
    component digitLt[8];
    signal d[8];
    for (var i = 0; i < 8; i++) {
        d[i] <== shifter.out[PLEN + DIG[i]] - 48;
        digitBits[i] = Num2Bits(4);
        digitBits[i].in <== d[i];
        digitLt[i] = LessThan(4);
        digitLt[i].in[0] <== d[i];
        digitLt[i].in[1] <== 10;
        digitLt[i].out === 1;
    }

    // =========================================================================
    // 8. Digits -> a comparable date number
    // =========================================================================
    // All linear: multiplication by a constant costs no constraints. This is
    // what replaces days-since-epoch -- no modulo, no leap-year arithmetic.
    signal year;  year  <== 1000 * d[0] + 100 * d[1] + 10 * d[2] + d[3];
    signal month; month <== 10 * d[4] + d[5];
    signal day;   day   <== 10 * d[6] + d[7];
    signal dateNum; dateNum <== year * 10000 + month * 100 + day;

    // =========================================================================
    // 9. Age assertion
    // =========================================================================
    // Born on or before the threshold date => old enough. Asserted, not output:
    // a witness exists only for a subject who passes, so there is no way to
    // produce a proof for someone under age.
    component ageOk = LessEqThan(32);
    ageOk.in[0] <== dateNum;
    ageOk.in[1] <== thresholdDate;
    ageOk.out === 1;
}

component main { public [modulus, thresholdDate] } = CredentialAgeProof(119);
