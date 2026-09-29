pragma circom 2.1.6;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";

// Proves an issuer signed `msg` (RSA-2048, PKCS1-v1_5, SHA-256) and that the
// name and/or gender inside those signed bytes match public claims. Same signed
// payload as CredentialAgeProof: the values are read from msg, never supplied.
//
// Private: msg, signature, nameLength. Public: modulus, claimedNameHash, claimedGender.
// claimedNameHash: Poseidon of the lowercased name, packed as below; 0 = not claimed.
// claimedGender: 1 = M, 2 = F, 3 = O; 0 = not claimed.

// matchAt[p] = 1 exactly where `pattern` starts in `in`; asserts one match.
template UniqueMatch(N, PLEN) {
    signal input in[N];
    signal input pattern[PLEN];
    var POS = N - PLEN + 1;
    signal output matchAt[POS];

    signal acc[POS][PLEN + 1];
    component isz[POS];
    var total = 0;
    for (var p = 0; p < POS; p++) {
        acc[p][0] <== 0;
        for (var k = 0; k < PLEN; k++) {
            // Sum of squared byte differences: zero iff every byte matches.
            acc[p][k + 1] <== acc[p][k] + (in[p + k] - pattern[k]) * (in[p + k] - pattern[k]);
        }
        isz[p] = IsZero();
        isz[p].in <== acc[p][PLEN];
        matchAt[p] <== isz[p].out;
        total += matchAt[p];
    }
    total === 1;
}

template CredentialMatchProof(PAYLOAD_BYTES, NAME_MAX) {
    signal input msg[PAYLOAD_BYTES];   // signed payload, space-padded
    signal input signature[17];
    signal input modulus[17];
    signal input nameLength;           // prover hint, constrained below
    signal input claimedNameHash;
    signal input claimedGender;

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

    // 5. Gender: `"gender":"` occurs exactly once, followed by M, F or O and a quote.
    var GLEN = 10;
    var GPAT[10] = [34, 103, 101, 110, 100, 101, 114, 34, 58, 34];   // "gender":"
    var GPOS = PAYLOAD_BYTES - GLEN + 1;
    component gScan = UniqueMatch(PAYLOAD_BYTES, GLEN);
    gScan.in <== msg;
    for (var k = 0; k < GLEN; k++) {
        gScan.pattern[k] <== GPAT[k];
    }

    // The single match selects the bytes after it; past the end counts as 0.
    signal gValue[GPOS];
    signal gQuote[GPOS];
    var genderByte = 0;
    var closingQuote = 0;
    for (var p = 0; p < GPOS; p++) {
        gValue[p] <== gScan.matchAt[p] * (p + GLEN < PAYLOAD_BYTES ? msg[p + GLEN] : 0);
        gQuote[p] <== gScan.matchAt[p] * (p + GLEN + 1 < PAYLOAD_BYTES ? msg[p + GLEN + 1] : 0);
        genderByte += gValue[p];
        closingQuote += gQuote[p];
    }
    closingQuote === 34;

    component isM = IsEqual();
    isM.in[0] <== genderByte;
    isM.in[1] <== 77;
    component isF = IsEqual();
    isF.in[0] <== genderByte;
    isF.in[1] <== 70;
    component isO = IsEqual();
    isO.in[0] <== genderByte;
    isO.in[1] <== 79;
    isM.out + isF.out + isO.out === 1;
    signal genderCode;
    genderCode <== isM.out + 2 * isF.out + 3 * isO.out;

    // Checked only when claimed.
    claimedGender * (genderCode - claimedGender) === 0;

    // 6. Name: `"name":"` occurs exactly once. The issuer rejects quotes in
    //    values, so the name runs to the next quote.
    var NLEN = 8;
    var NPAT[8] = [34, 110, 97, 109, 101, 34, 58, 34];   // "name":"
    var NPOS = PAYLOAD_BYTES - NLEN + 1;
    component nScan = UniqueMatch(PAYLOAD_BYTES, NLEN);
    nScan.in <== msg;
    for (var k = 0; k < NLEN; k++) {
        nScan.pattern[k] <== NPAT[k];
    }
    var start = 0;
    for (var p = 0; p < NPOS; p++) {
        start += nScan.matchAt[p] * (p + NLEN);
    }
    signal nameStart;
    nameStart <== start;

    component shifter = VarShiftLeft(PAYLOAD_BYTES, NAME_MAX + 1);
    shifter.in <== msg;
    shifter.shift <== nameStart;

    // nameLength is in [1, NAME_MAX] and the value ends inside msg, so the
    // shift (a rotation) never wraps within the name or its closing quote.
    component lenBits = Num2Bits(6);
    lenBits.in <== nameLength;
    component lenMax = LessEqThan(6);
    lenMax.in[0] <== nameLength;
    lenMax.in[1] <== NAME_MAX;
    lenMax.out === 1;
    component lenZero = IsZero();
    lenZero.in <== nameLength;
    lenZero.out === 0;
    component inBounds = LessThan(8);
    inBounds.in[0] <== nameStart + nameLength;
    inBounds.in[1] <== PAYLOAD_BYTES;
    inBounds.out === 1;

    // No quote before nameLength, and a quote exactly at nameLength.
    component isQuote[NAME_MAX + 1];
    component before[NAME_MAX + 1];
    component atEnd[NAME_MAX + 1];
    signal endQuote[NAME_MAX + 1];
    var quotesAtEnd = 0;
    for (var i = 0; i <= NAME_MAX; i++) {
        isQuote[i] = IsEqual();
        isQuote[i].in[0] <== shifter.out[i];
        isQuote[i].in[1] <== 34;
        before[i] = LessThan(6);
        before[i].in[0] <== i;
        before[i].in[1] <== nameLength;
        before[i].out * isQuote[i].out === 0;
        atEnd[i] = IsEqual();
        atEnd[i].in[0] <== i;
        atEnd[i].in[1] <== nameLength;
        endQuote[i] <== atEnd[i].out * isQuote[i].out;
        quotesAtEnd += endQuote[i];
    }
    quotesAtEnd === 1;

    // Lowercase A-Z, and zero every byte from the closing quote on.
    component geA[NAME_MAX];
    component leZ[NAME_MAX];
    signal isUpper[NAME_MAX];
    signal nameByte[NAME_MAX];
    for (var i = 0; i < NAME_MAX; i++) {
        geA[i] = GreaterEqThan(8);
        geA[i].in[0] <== shifter.out[i];
        geA[i].in[1] <== 65;
        leZ[i] = LessEqThan(8);
        leZ[i].in[0] <== shifter.out[i];
        leZ[i].in[1] <== 90;
        isUpper[i] <== geA[i].out * leZ[i].out;
        nameByte[i] <== before[i].out * (shifter.out[i] + 32 * isUpper[i]);
    }

    // 31 bytes per field element, little-endian, then Poseidon.
    var packed0 = 0;
    var packed1 = 0;
    for (var i = 0; i < 31; i++) {
        packed0 += nameByte[i] * (256 ** i);
    }
    for (var i = 31; i < NAME_MAX; i++) {
        packed1 += nameByte[i] * (256 ** (i - 31));
    }
    component nameHash = Poseidon(2);
    nameHash.inputs[0] <== packed0;
    nameHash.inputs[1] <== packed1;

    // Checked only when claimed.
    claimedNameHash * (nameHash.out - claimedNameHash) === 0;
}

// 119-byte payload as in CredentialAgeProof; 49 is the longest name that fits.
component main { public [modulus, claimedNameHash, claimedGender] } = CredentialMatchProof(119, 49);
