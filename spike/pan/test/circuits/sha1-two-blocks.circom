pragma circom 2.1.6;

// Test harness: two SHA-1 compressions from any state.
include "../../circuits/sha1.circom";

template Sha1TwoBlocks() {
    signal input state[5][32];
    signal input blocks[2][64];
    signal output out[5][32];
    component first = Sha1Compression();
    component second = Sha1Compression();
    first.state <== state;
    first.block <== blocks[0];
    second.state <== first.out;
    second.block <== blocks[1];
    out <== second.out;
}

component main = Sha1TwoBlocks();
