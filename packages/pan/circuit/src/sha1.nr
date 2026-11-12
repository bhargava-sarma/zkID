// SHA-1's compression function, for SignedInfo's last two blocks. SHA-1 is not
// a Noir built-in; this follows FIPS 180-4, section 6.1.2.

use std::ops::WrappingAdd;

fn rotl(x: u32, n: u64) -> u32 {
    let wide = (x as u64) << n;
    (wide as u32) | ((wide >> 32) as u32)
}

pub fn compress(state: [u32; 5], block: [u8; 64]) -> [u32; 5] {
    let mut w: [u32; 80] = [0; 80];
    for t in 0..16 {
        w[t] = ((block[4 * t] as u32) << 24)
            | ((block[4 * t + 1] as u32) << 16)
            | ((block[4 * t + 2] as u32) << 8)
            | (block[4 * t + 3] as u32);
    }
    for t in 16..80 {
        w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    for t in 0..80 {
        let mut f: u32 = 0;
        let mut k: u32 = 0;
        if t < 20 {
            f = (b & c) | (!b & d);
            k = 0x5a827999;
        } else if t < 40 {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if t < 60 {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        let temp = rotl(a, 5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[t]);
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }
    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
    ]
}
