pragma circom 2.1.6;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";

// Proves an issuer signed `msg` (RSA-2048, PKCS1-v1_5, SHA-256) and that the DOB
// inside those signed bytes is <= thresholdDate. The DOB is extracted in-circuit,
// never supplied, so it can't differ from the signed one.
//
// Private: msg, signature, dobIndex. Public: modulus, thresholdDate.
// Fixed-key, fixed-width extraction (`"dob":"` + 10 bytes), not a JSON parser.
template CredentialAgeProof(PAYLOAD_BYTES) {
    signal input msg[PAYLOAD_BYTES];   // signed payload, space-padded
    signal input signature[17];
    signal input modulus[17];
    signal input dobIndex;             // prover hint, constrained by the scan below
    signal input thresholdDate;        // year*10000 + month*100 + day

    var PAYLOAD_BITS = PAYLOAD_BYTES * 8;
    var N = 121;
    var K = 17;

    // 1. Bytes -> bits. Num2Bits(8) also range-checks each byte.
    component byteBits[PAYLOAD_BYTES];
    signal shaIn[PAYLOAD_BITS];
    for (var i = 0; i < PAYLOAD_BYTES; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== msg[i];
        for (var j = 0; j < 8; j++) {
            // SHA-256 wants MSB-first; Num2Bits emits LSB-first.
            shaIn[i * 8 + j] <== byteBits[i].out[7 - j];
        }
    }

    // 2. SHA-256 over the whole padded payload.
    component sha = Sha256(PAYLOAD_BITS);
    for (var i = 0; i < PAYLOAD_BITS; i++) {
        sha.in[i] <== shaIn[i];
    }

    // 3. Digest -> 121-bit limbs, LSB-first. sha.out[0] is the digest's MSB.
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

    // 4. RSA verification (applies PKCS1-v1_5 padding internally).
    component rsa = RSAVerifier65537(N, K);
    rsa.message <== message;
    rsa.signature <== signature;
    rsa.modulus <== modulus;

    // 5. `"dob":"` must occur exactly once, at dobIndex.
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
            // Sum of squared differences: zero iff every byte matches.
            acc[p][k + 1] <== acc[p][k] + (msg[p + k] - PAT[k]) * (msg[p + k] - PAT[k]);
        }
        isz[p] = IsZero();
        isz[p].in <== acc[p][PLEN];
        matchAt[p] <== isz[p].out;
        matchTotal += matchAt[p];
        indexTotal += p * matchAt[p];
    }
    matchTotal === 1;
    indexTotal === dobIndex;

    // 6. Shift so the key sits at offset 0, then check the YYYY-MM-DD layout.
    component shifter = VarShiftLeft(PAYLOAD_BYTES, 17);
    shifter.in <== msg;
    shifter.shift <== dobIndex;

    for (var k = 0; k < PLEN; k++) {
        shifter.out[k] === PAT[k];
    }
    shifter.out[PLEN + 4] === 45;   // '-'
    shifter.out[PLEN + 7] === 45;   // '-'

    // 7. Each of the 8 date characters must be a digit 0-9.
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

    // 8. Digits -> year*10000 + month*100 + day.
    signal year;  year  <== 1000 * d[0] + 100 * d[1] + 10 * d[2] + d[3];
    signal month; month <== 10 * d[4] + d[5];
    signal day;   day   <== 10 * d[6] + d[7];
    signal dateNum; dateNum <== year * 10000 + month * 100 + day;

    // 9. Age check, asserted: no witness exists for an underage subject.
    component ageOk = LessEqThan(32);
    ageOk.in[0] <== dateNum;
    ageOk.in[1] <== thresholdDate;
    ageOk.out === 1;
}

component main { public [modulus, thresholdDate] } = CredentialAgeProof(119);
