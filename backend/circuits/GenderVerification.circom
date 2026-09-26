pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

// Proves the stored gender code (1=Male, 2=Female, 3=Other) equals a claimed code.
template GenderVerification() {
    signal input genderCode;     // private
    signal input claimedGender;  // public

    component eq = IsEqual();
    eq.in[0] <== genderCode;
    eq.in[1] <== claimedGender;
    eq.out === 1;
}

component main {public [claimedGender]} = GenderVerification();
