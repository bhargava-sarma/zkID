// zkID's circuit for DigiLocker PAN Verification Records, proved with
// Barretenberg's UltraHonk, which needs no per-circuit setup ceremony
// (docs/circuit-spec.md, section 7). It checks:
//   - SHA-256 of the canonical record, as base64, in DigiLocker's exact
//     SignedInfo; SHA-1 of that SignedInfo; the RSA PKCS#1 v1.5 signature;
//   - the record's fixed head: a PAN record, status "A", issued through
//     DigiLocker by the Income Tax Department;
//   - the date of birth, gender, uid and <PAN> attributes where the prover's
//     hints say, each matched by its exact markup, inside the hashed bytes.
// It returns the key's hash, a per-verifier nullifier from the PAN number and
// uid, the hour DigiLocker verified the PAN, whether the holder was born on or
// before the verifier's date, and the gender if the holder reveals it. Both
// hashes are Barretenberg's Poseidon2 (poseidon2.nr).

mod bignum;
mod constants;
mod poseidon2;
mod sha1;

use constants::{
    BASE64, DIGEST_AT, DOC_HEAD, DOC_HEAD_LEN, EM_WITHOUT_HASH, FEMALE, GENDER_TAG, MALE, PAN_END,
    PAN_LEN, PAN_OFFSET, PAN_TAG, SIGNED_INFO_MIDSTATE, SIGNED_INFO_TAIL, TRANSGENDER, UID_TAG,
    VERIFIED_TAG,
};

global MAX_DOC_BYTES: u32 = 3584; // 56 SHA-256 blocks
global WINDOW: u32 = 1280; // gender, uid and <PAN> must end within it
global SHA256_IV: [u32; 8] =
    [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
global RSA_STEPS: u32 = 17; // 65537 = 2^16 + 1: sixteen squarings, then one multiplication

fn main(
    doc: [u8; MAX_DOC_BYTES], // canonical record, SHA-256 padding, then zeros
    doc_padded_length: u32,
    signature: [Field; bignum::LIMBS],
    modulus: [Field; bignum::LIMBS],
    rsa_q: [[Field; bignum::LIMBS]; RSA_STEPS],
    rsa_r: [[Field; bignum::LIMBS]; RSA_STEPS],
    gender_at: u32, // where ` gender="` starts
    uid_at: u32, // where ` uid="` starts (the Person's)
    pan_at: u32, // where `<PAN num="` starts
    reveal_gender: bool,
    dob_cutoff: pub u32, // YYYYMMDD
    nullifier_seed: pub Field,
    signal_hash: pub Field,
) -> pub (Field, Field, u32, bool, u8) {
    let _ = signal_hash; // bound to the proof as a public input

    // ---- 1. SHA-256 of the record ------------------------------------------
    assert(doc_padded_length % 64 == 0);
    assert(doc_padded_length <= MAX_DOC_BYTES);
    let blocks = doc_padded_length / 64;
    let mut state = SHA256_IV;
    for i in 0..(MAX_DOC_BYTES / 64) {
        let mut words: [u32; 16] = [0; 16];
        for j in 0..16 {
            let at = 64 * i + 4 * j;
            words[j] = ((doc[at] as u32) << 24)
                | ((doc[at + 1] as u32) << 16)
                | ((doc[at + 2] as u32) << 8)
                | (doc[at + 3] as u32);
        }
        let next = std::hash::sha256_compression(words, state);
        if i < blocks {
            state = next;
        }
    }

    // ---- 2. its base64 in SignedInfo, and SHA-1 of SignedInfo ---------------
    let mut digest: [u8; 32] = [0; 32];
    for i in 0..8 {
        digest[4 * i] = (state[i] >> 24) as u8;
        digest[4 * i + 1] = (state[i] >> 16) as u8;
        digest[4 * i + 2] = (state[i] >> 8) as u8;
        digest[4 * i + 3] = state[i] as u8;
    }
    let encoded = base64_digest(digest);
    let mut tail = SIGNED_INFO_TAIL;
    for i in 0..44 {
        tail[DIGEST_AT + i] = encoded[i];
    }
    let mut first: [u8; 64] = [0; 64];
    let mut second: [u8; 64] = [0; 64];
    for i in 0..64 {
        first[i] = tail[i];
        second[i] = tail[64 + i];
    }
    let h = sha1::compress(sha1::compress(SIGNED_INFO_MIDSTATE, first), second);

    // ---- 3. RSA PKCS#1 v1.5 with SHA-1: signature^65537 = EM mod n ----------
    bignum::assert_limbs(signature);
    bignum::assert_limbs(modulus);
    let mut x = signature;
    for step in 0..(RSA_STEPS - 1) {
        bignum::assert_mul_mod(x, x, rsa_q[step], rsa_r[step], modulus);
        x = rsa_r[step];
    }
    bignum::assert_mul_mod(x, signature, rsa_q[RSA_STEPS - 1], rsa_r[RSA_STEPS - 1], modulus);
    // EM's lowest 160 bits are H (h[0] most significant): limb 0 holds its low
    // 120 bits, limb 1 the other 40.
    let mut em = EM_WITHOUT_HASH;
    em[0] += (h[4] as Field)
        + (h[3] as Field) * 0x100000000
        + (h[2] as Field) * 0x10000000000000000
        + ((h[1] & 0xffffff) as Field) * 0x1000000000000000000000000;
    em[1] += ((h[1] >> 24) as Field) + (h[0] as Field) * 0x100;
    for i in 0..bignum::LIMBS {
        assert(rsa_r[RSA_STEPS - 1][i] == em[i]);
    }
    let pubkey_hash = poseidon2::hash(modulus);

    // ---- 4. the fixed head, and the date of birth after it ------------------
    for i in 0..DOC_HEAD_LEN {
        if (i < PAN_OFFSET) | (i >= PAN_OFFSET + PAN_LEN) {
            assert(doc[i] == DOC_HEAD[i]);
        }
    }
    let dob = date_value(doc, DOC_HEAD_LEN);
    assert(doc[DOC_HEAD_LEN + 10] == 34); // closing quote
    let born_by = dob <= dob_cutoff;

    // ---- 5. gender, uid and <PAN>, at the hinted places ---------------------
    // In order after the date of birth, and inside both the window and the
    // hashed bytes.
    assert(DOC_HEAD_LEN + 10 < gender_at);
    assert(gender_at < uid_at);
    assert(uid_at < pan_at);
    assert(pan_at + 61 <= WINDOW);
    assert(pan_at + 61 <= doc_padded_length, "the fields must lie in the hashed bytes");

    assert(matches(doc, gender_at, GENDER_TAG));
    let is_male = matches(doc, gender_at + 9, MALE);
    let is_female = matches(doc, gender_at + 9, FEMALE);
    let is_trans = matches(doc, gender_at + 9, TRANSGENDER);
    assert((is_male as u8) + (is_female as u8) + (is_trans as u8) == 1);
    let letter: u8 = if is_male {
        77 // M
    } else if is_female {
        70 // F
    } else {
        84 // T
    };
    let gender: u8 = if reveal_gender { letter } else { 0 };

    assert(matches(doc, uid_at, UID_TAG));
    assert(doc[uid_at + 38] == 34); // "
    assert(doc[uid_at + 39] == 62); // >, the Person's last attribute

    assert(matches(doc, pan_at, PAN_TAG));
    for i in 0..PAN_LEN {
        assert(doc[pan_at + 10 + i] == doc[PAN_OFFSET + i]); // the head's PAN number
    }
    assert(matches(doc, pan_at + 20, VERIFIED_TAG));
    // verifiedOn: DD-MM-YYYY HH:MM:SS
    let verified_date = date_value(doc, pan_at + 34);
    assert(doc[pan_at + 44] == 32); // space
    assert(doc[pan_at + 47] == 58); // :
    assert(doc[pan_at + 50] == 58);
    let verified_hour = verified_date * 100 + digit(doc[pan_at + 45]) * 10 + digit(doc[pan_at + 46]);
    assert(matches(doc, pan_at + 53, PAN_END));

    // ---- 6. nullifier ------------------------------------------------------
    let nullifier = poseidon2::hash(
        [nullifier_seed, pack::<PAN_LEN>(doc, PAN_OFFSET), pack::<16>(doc, uid_at + 6), pack::<16>(doc, uid_at + 22)],
    );

    (pubkey_hash, nullifier, verified_hour, born_by, gender)
}

// SHA-256 digest as base64: 43 characters, then "=".
fn base64_digest(d: [u8; 32]) -> [u8; 44] {
    let mut out: [u8; 44] = [0; 44];
    for g in 0..10 {
        let b0 = d[3 * g];
        let b1 = d[3 * g + 1];
        let b2 = d[3 * g + 2];
        out[4 * g] = BASE64[(b0 >> 2) as u32];
        out[4 * g + 1] = BASE64[(((b0 & 3) << 4) | (b1 >> 4)) as u32];
        out[4 * g + 2] = BASE64[(((b1 & 15) << 2) | (b2 >> 6)) as u32];
        out[4 * g + 3] = BASE64[(b2 & 63) as u32];
    }
    out[40] = BASE64[(d[30] >> 2) as u32];
    out[41] = BASE64[(((d[30] & 3) << 4) | (d[31] >> 4)) as u32];
    out[42] = BASE64[((d[31] & 15) << 2) as u32];
    out[43] = 61; // =
    out
}

fn matches<let N: u32>(doc: [u8; MAX_DOC_BYTES], at: u32, text: [u8; N]) -> bool {
    let mut all = true;
    for i in 0..N {
        all &= doc[at + i] == text[i];
    }
    all
}

// An ASCII digit's value; anything else fails.
fn digit(c: u8) -> u32 {
    assert((c >= 48) & (c <= 57));
    (c - 48) as u32
}

// DD-MM-YYYY at `at`, as the number YYYYMMDD.
fn date_value(doc: [u8; MAX_DOC_BYTES], at: u32) -> u32 {
    assert(doc[at + 2] == 45); // -
    assert(doc[at + 5] == 45);
    let day = digit(doc[at]) * 10 + digit(doc[at + 1]);
    let month = digit(doc[at + 3]) * 10 + digit(doc[at + 4]);
    let year = digit(doc[at + 6]) * 1000
        + digit(doc[at + 7]) * 100
        + digit(doc[at + 8]) * 10
        + digit(doc[at + 9]);
    year * 10000 + month * 100 + day
}

// N bytes as one integer, first byte lowest.
fn pack<let N: u32>(doc: [u8; MAX_DOC_BYTES], at: u32) -> Field {
    let mut acc: Field = 0;
    let mut scale: Field = 1;
    for i in 0..N {
        acc += (doc[at + i] as Field) * scale;
        scale *= 256;
    }
    acc
}
