// 2048-bit modular multiplication, checked rather than computed: the prover
// supplies the quotient and remainder of a * b by n (inputs.mjs), and the
// circuit checks a * b = q * n + r over the integers, in 18 limbs of 120 bits.
// Each column of the product is carried into the next; a carry is exact only
// if the column is a multiple of 2^120, and the range check on it fails
// otherwise. The result is congruent to a * b mod n, which is all RSA
// verification needs: the last remainder must equal the encoded message.

pub global LIMBS: u32 = 18;
global COLUMNS: u32 = 2 * LIMBS - 1;
global SHIFT_INV: Field = 1 / 0x1000000000000000000000000000000; // 2^-120
global CARRY_OFFSET: Field = 0x80000000000000000000000000000000; // 2^127

pub fn assert_limbs(x: [Field; LIMBS]) {
    for i in 0..LIMBS {
        x[i].assert_max_bit_size::<120>();
    }
}

// Requires a, b and n to be range-checked by the caller; checks q and r.
pub fn assert_mul_mod(
    a: [Field; LIMBS],
    b: [Field; LIMBS],
    q: [Field; LIMBS],
    r: [Field; LIMBS],
    n: [Field; LIMBS],
) {
    assert_limbs(q);
    assert_limbs(r);
    let mut columns: [Field; COLUMNS] = [0; COLUMNS];
    for i in 0..LIMBS {
        for j in 0..LIMBS {
            columns[i + j] += a[i] * b[j] - q[i] * n[j];
        }
    }
    for k in 0..LIMBS {
        columns[k] -= r[k];
    }
    // Every column is below 18 * 2^240 in size, so every carry is below 2^126.
    let mut carry: Field = 0;
    for k in 0..COLUMNS {
        carry = (columns[k] + carry) * SHIFT_INV;
        (carry + CARRY_OFFSET).assert_max_bit_size::<128>();
    }
    assert(carry == 0);
}
