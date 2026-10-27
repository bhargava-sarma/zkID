pragma circom 2.1.6;

// Prototype: what a DigiLocker PAN Verification Record shows, proved without
// revealing it. The record is XML signed by DigiLocker (XMLDSig, enveloped,
// exclusive canonicalization): SHA-256 of the canonical record is the
// DigestValue inside SignedInfo, and SignedInfo is signed with RSA-SHA1 under
// DigiLocker's 2048-bit key. This circuit takes the canonical record and the
// signature, and checks:
//   - SHA-256 of the record, as base64, in DigiLocker's exact SignedInfo; SHA-1
//     of that SignedInfo; the RSA PKCS#1 v1.5 signature over it;
//   - the record's fixed head (format.mjs): a PAN record, status "A", issued
//     through DigiLocker by the Income Tax Department;
//   - the date of birth, gender, uid and <PAN> attributes where the prover's
//     hints say, each matched by its exact markup.
// Outputs: the key's hash (as Anon Aadhaar computes it), a per-verifier
// nullifier from the PAN number and uid, the hour DigiLocker verified the PAN,
// whether the holder was born on or before a date the verifier chose, and the
// gender if the holder reveals it.

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";
include "./sha1.circom";
include "./constants.circom";

// An ASCII digit's value; anything else fails.
template Digit() {
    signal input in;
    signal output out;
    out <== in - 48;
    component bits = Num2Bits(4);
    bits.in <== out;
    component lt = LessThan(4);
    lt.in[0] <== out;
    lt.in[1] <== 10;
    lt.out === 1;
}

// DD-MM-YYYY at `in`, as the number YYYYMMDD.
template DateValue() {
    signal input in[10];
    signal output out;
    in[2] === 45; // -
    in[5] === 45;
    component d[8];
    var at[8] = [0, 1, 3, 4, 6, 7, 8, 9];
    for (var i = 0; i < 8; i++) {
        d[i] = Digit();
        d[i].in <== in[at[i]];
    }
    out <== (d[4].out * 1000 + d[5].out * 100 + d[6].out * 10 + d[7].out) * 10000 + (d[2].out * 10 + d[3].out) * 100 + d[0].out * 10 + d[1].out;
}

// 1 if `in` holds the ASCII text `text`, of length `len`, else 0.
template Matches(len, text) {
    signal input in[len];
    signal output out;
    component eq[len];
    component all = MultiAND(len);
    for (var i = 0; i < len; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== in[i];
        eq[i].in[1] <== text[i];
        all.in[i] <== eq[i].out;
    }
    out <== all.out;
}

// Bytes as one integer, first byte lowest.
template Pack(len) {
    signal input in[len];
    signal output out;
    var acc = 0;
    for (var i = 0; i < len; i++) acc += in[i] * (1 << (8 * i));
    out <== acc;
}

// a < b for values below 2^bits; fails otherwise.
template AssertLess(bits) {
    signal input a;
    signal input b;
    component lt = LessThan(bits);
    lt.in[0] <== a;
    lt.in[1] <== b;
    lt.out === 1;
}

// One base64 character for a 6-bit value.
template Base64Char() {
    signal input in; // 0..63, from bits
    signal output out;
    component lt26 = LessThan(6);
    lt26.in[0] <== in;
    lt26.in[1] <== 26;
    component lt52 = LessThan(6);
    lt52.in[0] <== in;
    lt52.in[1] <== 52;
    component lt62 = LessThan(6);
    lt62.in[0] <== in;
    lt62.in[1] <== 62;
    component is62 = IsEqual();
    is62.in[0] <== in;
    is62.in[1] <== 62;
    // A-Z, a-z, 0-9, then + and /.
    signal upper <== lt26.out * (65 + in);
    signal lower <== (lt52.out - lt26.out) * (71 + in);
    signal digit <== (lt62.out - lt52.out) * (in - 4);
    signal symbol <== (1 - lt62.out) * (47 - 4 * is62.out);
    out <== upper + lower + digit + symbol;
}

template PanVerifier(n, k, maxDocBytes, windowBytes) {
    signal input doc[maxDocBytes]; // canonical record, then SHA-256 padding, then zeros
    signal input docPaddedLength;
    signal input signature[k];
    signal input modulus[k];
    signal input genderAt; // where ` gender="` starts
    signal input uidAt; // where ` uid="` starts (the Person's)
    signal input panAt; // where `<PAN num="` starts
    signal input revealGender;

    signal input dobCutoff; // YYYYMMDD
    signal input nullifierSeed;
    signal input signalHash;

    signal output pubkeyHash;
    signal output nullifier;
    signal output verifiedHour; // YYYYMMDDHH, as DigiLocker wrote it (IST)
    signal output bornBy; // 1 if the date of birth is on or before dobCutoff
    signal output gender; // 77, 70 or 84 (M, F, T) if revealGender, else 0

    // ---- 1. SHA-256 of the record, in base64 ---------------------------------
    component sha = Sha256Bytes(maxDocBytes);
    sha.paddedIn <== doc;
    sha.paddedInLength <== docPaddedLength;

    // 256 bits, most significant first: 43 characters of 6 bits, then "=".
    component b64[43];
    for (var c = 0; c < 43; c++) {
        b64[c] = Base64Char();
        var value = 0;
        for (var j = 0; j < 6; j++) {
            var bit = 6 * c + j;
            if (bit < 256) value += sha.out[bit] * (1 << (5 - j));
        }
        b64[c].in <== value;
    }

    // ---- 2. SHA-1 of SignedInfo, whose first blocks are constant --------------
    var tail[128] = signedInfoTail();
    var digestAt = signedInfoDigestAt();
    signal signedInfoTailBytes[128];
    for (var i = 0; i < 128; i++) {
        if (i >= digestAt && i < digestAt + 43) signedInfoTailBytes[i] <== b64[i - digestAt].out;
        else if (i == digestAt + 43) signedInfoTailBytes[i] <== 61; // =
        else signedInfoTailBytes[i] <== tail[i];
    }
    var mid[5] = signedInfoMidstate();
    component midstate = Sha1ConstState(mid[0], mid[1], mid[2], mid[3], mid[4]);
    component sha1a = Sha1Compression();
    component sha1b = Sha1Compression();
    sha1a.state <== midstate.out;
    for (var i = 0; i < 64; i++) sha1a.block[i] <== signedInfoTailBytes[i];
    sha1b.state <== sha1a.out;
    for (var i = 0; i < 64; i++) sha1b.block[i] <== signedInfoTailBytes[64 + i];

    // ---- 3. RSA PKCS#1 v1.5 with SHA-1 ------------------------------------------
    // EM = 00 01 FF..FF 00 || DigestInfo(SHA-1) || H, as n*k bits, least significant first.
    var digestInfo[15] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
    signal em[n * k];
    for (var b = 0; b < n * k; b++) {
        if (b < 160) {
            // H's bit b: word 4 - b \ 32, bit b % 32 (state words are least significant bit first).
            em[b] <== sha1b.out[4 - b \ 32][b % 32];
        } else if (b < 280) {
            var byteIndex = 14 - (b - 160) \ 8; // DigestInfo's bytes, last one lowest
            em[b] <== (digestInfo[byteIndex] >> ((b - 160) % 8)) & 1;
        } else if (b < 288) {
            em[b] <== 0;
        } else if (b < 2032) {
            em[b] <== 1;
        } else if (b == 2032) {
            em[b] <== 1; // the 01 byte
        } else {
            em[b] <== 0;
        }
    }
    component modulusBits[k];
    component signatureBits[k];
    component sigLessThan = BigLessThan(n, k);
    component pow = FpPow65537Mod(n, k);
    for (var i = 0; i < k; i++) {
        modulusBits[i] = Num2Bits(n);
        modulusBits[i].in <== modulus[i];
        signatureBits[i] = Num2Bits(n);
        signatureBits[i].in <== signature[i];
        sigLessThan.a[i] <== signature[i];
        sigLessThan.b[i] <== modulus[i];
        pow.base[i] <== signature[i];
        pow.modulus[i] <== modulus[i];
    }
    sigLessThan.out === 1;
    for (var i = 0; i < k; i++) {
        var limb = 0;
        for (var j = 0; j < n; j++) limb += em[i * n + j] * (1 << j);
        pow.out[i] === limb;
    }

    // The key's hash: Poseidon over the 17 limbs merged in pairs (Anon Aadhaar's).
    component keyHash = Poseidon(9);
    for (var i = 0; i < 9; i++) {
        if (i < 8) keyHash.inputs[i] <== modulus[2 * i] + modulus[2 * i + 1] * (1 << n);
        else keyHash.inputs[i] <== modulus[16];
    }
    pubkeyHash <== keyHash.out;

    // ---- 4. The record's fixed head, and the date of birth after it -----------
    var head[docHeadLength()] = docHead();
    var panStart = panOffset();
    for (var i = 0; i < docHeadLength(); i++) {
        if (i < panStart || i >= panStart + 10) doc[i] === head[i];
    }
    var dobAt = docHeadLength();
    component dob = DateValue();
    for (var i = 0; i < 10; i++) dob.in[i] <== doc[dobAt + i];
    doc[dobAt + 10] === 34; // closing quote

    component dobCutoffBits = Num2Bits(32);
    dobCutoffBits.in <== dobCutoff;
    component born = LessEqThan(32);
    born.in[0] <== dob.out;
    born.in[1] <== dobCutoff;
    bornBy <== born.out;

    // ---- 5. gender, uid and <PAN>, at the hinted places ------------------------
    var genderLen = 21;
    var uidLen = 40;
    var panLen = 61;
    signal window[windowBytes];
    for (var i = 0; i < windowBytes; i++) window[i] <== doc[i];

    // In order, inside the field window: after the date of birth, gender, uid, <PAN>.
    component order[4];
    for (var i = 0; i < 4; i++) order[i] = AssertLess(11);
    order[0].a <== dobAt + 10;
    order[0].b <== genderAt;
    order[1].a <== genderAt;
    order[1].b <== uidAt;
    order[2].a <== uidAt;
    order[2].b <== panAt;
    order[3].a <== panAt;
    order[3].b <== windowBytes - panLen;

    component genderShift = VarShiftLeft(windowBytes, genderLen);
    genderShift.in <== window;
    genderShift.shift <== genderAt;
    var genderTag[9] = [32, 103, 101, 110, 100, 101, 114, 61, 34]; // ` gender="`
    for (var i = 0; i < 9; i++) genderShift.out[i] === genderTag[i];
    component isMale = Matches(5, [77, 65, 76, 69, 34]); // MALE"
    component isFemale = Matches(7, [70, 69, 77, 65, 76, 69, 34]); // FEMALE"
    component isTrans = Matches(12, [84, 82, 65, 78, 83, 71, 69, 78, 68, 69, 82, 34]); // TRANSGENDER"
    for (var i = 0; i < 12; i++) {
        if (i < 5) isMale.in[i] <== genderShift.out[9 + i];
        if (i < 7) isFemale.in[i] <== genderShift.out[9 + i];
        isTrans.in[i] <== genderShift.out[9 + i];
    }
    isMale.out + isFemale.out + isTrans.out === 1;
    revealGender * (revealGender - 1) === 0;
    gender <== (77 * isMale.out + 70 * isFemale.out + 84 * isTrans.out) * revealGender;

    component uidShift = VarShiftLeft(windowBytes, uidLen);
    uidShift.in <== window;
    uidShift.shift <== uidAt;
    var uidTag[6] = [32, 117, 105, 100, 61, 34]; // ` uid="`
    for (var i = 0; i < 6; i++) uidShift.out[i] === uidTag[i];
    uidShift.out[38] === 34; // "
    uidShift.out[39] === 62; // >

    component panShift = VarShiftLeft(windowBytes, panLen);
    panShift.in <== window;
    panShift.shift <== panAt;
    var panTag[10] = [60, 80, 65, 78, 32, 110, 117, 109, 61, 34]; // `<PAN num="`
    var verifiedTag[14] = [34, 32, 118, 101, 114, 105, 102, 105, 101, 100, 79, 110, 61, 34]; // `" verifiedOn="`
    var panEnd[8] = [34, 62, 60, 47, 80, 65, 78, 62]; // `"></PAN>`
    for (var i = 0; i < 10; i++) panShift.out[i] === panTag[i];
    for (var i = 0; i < 10; i++) panShift.out[10 + i] === doc[panStart + i]; // the same PAN as the head's
    for (var i = 0; i < 14; i++) panShift.out[20 + i] === verifiedTag[i];
    for (var i = 0; i < 8; i++) panShift.out[53 + i] === panEnd[i];

    // verifiedOn: DD-MM-YYYY HH:MM:SS
    component verifiedDate = DateValue();
    for (var i = 0; i < 10; i++) verifiedDate.in[i] <== panShift.out[34 + i];
    panShift.out[44] === 32; // space
    panShift.out[47] === 58; // :
    panShift.out[50] === 58;
    component hour[2];
    for (var i = 0; i < 2; i++) {
        hour[i] = Digit();
        hour[i].in <== panShift.out[45 + i];
    }
    verifiedHour <== verifiedDate.out * 100 + hour[0].out * 10 + hour[1].out;

    // ---- 6. Nullifier, and the binding to the request ---------------------------
    component pan = Pack(10);
    for (var i = 0; i < 10; i++) pan.in[i] <== doc[panStart + i];
    component uidHi = Pack(16);
    component uidLo = Pack(16);
    for (var i = 0; i < 16; i++) {
        uidHi.in[i] <== uidShift.out[6 + i];
        uidLo.in[i] <== uidShift.out[22 + i];
    }
    component nullifierHash = Poseidon(4);
    nullifierHash.inputs[0] <== nullifierSeed;
    nullifierHash.inputs[1] <== pan.out;
    nullifierHash.inputs[2] <== uidHi.out;
    nullifierHash.inputs[3] <== uidLo.out;
    nullifier <== nullifierHash.out;

    signal signalHashSquare <== signalHash * signalHash;
}

component main { public [dobCutoff, nullifierSeed, signalHash] } = PanVerifier(121, 17, 3584, 1280);
