pragma circom 2.1.6;

// SHA-1 compression in circom, for the one SHA-1 in DigiLocker's signature: the
// hash of SignedInfo inside RSA-SHA1. Words are 32 bits, least significant bit
// first; a block is 64 bytes. Built from circomlib's SHA-256 gadgets.

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/binsum.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/sha256/xor3.circom";
include "circomlib/circuits/sha256/ch.circom";
include "circomlib/circuits/sha256/maj.circom";

// ROTL(x, s) on a word of bits, least significant first.
function rotlIndex(i, s) { return (i + 32 - s) % 32; }

template Sha1Compression() {
    signal input state[5][32];
    signal input block[64]; // bytes
    signal output out[5][32];

    // The message schedule.
    signal w[80][32];
    component byteBits[64];
    for (var i = 0; i < 64; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== block[i];
    }
    for (var t = 0; t < 16; t++) {
        for (var i = 0; i < 32; i++) {
            // Big-endian words: bit i of word t is bit (i % 8) of byte 4t + 3 - i \ 8.
            w[t][i] <== byteBits[4 * t + 3 - i \ 8].out[i % 8];
        }
    }
    component x3[64];
    component x2[64][32];
    for (var t = 16; t < 80; t++) {
        x3[t - 16] = Xor3(32);
        for (var i = 0; i < 32; i++) {
            x3[t - 16].a[i] <== w[t - 3][i];
            x3[t - 16].b[i] <== w[t - 8][i];
            x3[t - 16].c[i] <== w[t - 14][i];
        }
        for (var i = 0; i < 32; i++) {
            x2[t - 16][i] = XOR();
            x2[t - 16][i].a <== x3[t - 16].out[i];
            x2[t - 16][i].b <== w[t - 16][i];
        }
        for (var i = 0; i < 32; i++) w[t][i] <== x2[t - 16][rotlIndex(i, 1)].out;
    }

    // The 80 rounds.
    signal a[81][32];
    signal b[81][32];
    signal c[81][32];
    signal d[81][32];
    signal e[81][32];
    for (var i = 0; i < 32; i++) {
        a[0][i] <== state[0][i];
        b[0][i] <== state[1][i];
        c[0][i] <== state[2][i];
        d[0][i] <== state[3][i];
        e[0][i] <== state[4][i];
    }
    var K[4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
    component ch[20];
    component parity[40];
    component maj[20];
    component sum[80];
    for (var t = 0; t < 80; t++) {
        sum[t] = BinSum(32, 5);
        for (var i = 0; i < 32; i++) {
            sum[t].in[0][i] <== a[t][rotlIndex(i, 5)];
            sum[t].in[2][i] <== e[t][i];
            sum[t].in[3][i] <== (K[t \ 20] >> i) & 1;
            sum[t].in[4][i] <== w[t][i];
        }
        if (t < 20) {
            ch[t] = Ch_t(32);
            for (var i = 0; i < 32; i++) {
                ch[t].a[i] <== b[t][i];
                ch[t].b[i] <== c[t][i];
                ch[t].c[i] <== d[t][i];
            }
            for (var i = 0; i < 32; i++) sum[t].in[1][i] <== ch[t].out[i];
        } else if (t >= 40 && t < 60) {
            maj[t - 40] = Maj_t(32);
            for (var i = 0; i < 32; i++) {
                maj[t - 40].a[i] <== b[t][i];
                maj[t - 40].b[i] <== c[t][i];
                maj[t - 40].c[i] <== d[t][i];
            }
            for (var i = 0; i < 32; i++) sum[t].in[1][i] <== maj[t - 40].out[i];
        } else {
            var p = t < 40 ? t - 20 : t - 40;
            parity[p] = Xor3(32);
            for (var i = 0; i < 32; i++) {
                parity[p].a[i] <== b[t][i];
                parity[p].b[i] <== c[t][i];
                parity[p].c[i] <== d[t][i];
            }
            for (var i = 0; i < 32; i++) sum[t].in[1][i] <== parity[p].out[i];
        }
        for (var i = 0; i < 32; i++) {
            a[t + 1][i] <== sum[t].out[i]; // mod 2^32: the carry bits are dropped
            b[t + 1][i] <== a[t][i];
            c[t + 1][i] <== b[t][rotlIndex(i, 30)];
            d[t + 1][i] <== c[t][i];
            e[t + 1][i] <== d[t][i];
        }
    }

    // Add the round result to the input state, mod 2^32.
    component add[5];
    for (var j = 0; j < 5; j++) add[j] = BinSum(32, 2);
    for (var i = 0; i < 32; i++) {
        add[0].in[0][i] <== state[0][i];
        add[0].in[1][i] <== a[80][i];
        add[1].in[0][i] <== state[1][i];
        add[1].in[1][i] <== b[80][i];
        add[2].in[0][i] <== state[2][i];
        add[2].in[1][i] <== c[80][i];
        add[3].in[0][i] <== state[3][i];
        add[3].in[1][i] <== d[80][i];
        add[4].in[0][i] <== state[4][i];
        add[4].in[1][i] <== e[80][i];
    }
    for (var j = 0; j < 5; j++) {
        for (var i = 0; i < 32; i++) out[j][i] <== add[j].out[i];
    }
}

// SHA-1 state words as bits, from 32-bit numbers known at compile time.
template Sha1ConstState(s0, s1, s2, s3, s4) {
    signal output out[5][32];
    var s[5] = [s0, s1, s2, s3, s4];
    for (var j = 0; j < 5; j++) {
        for (var i = 0; i < 32; i++) out[j][i] <== (s[j] >> i) & 1;
    }
}
