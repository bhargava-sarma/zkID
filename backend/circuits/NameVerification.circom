pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

// Proves the stored name hash equals a claimed hash without revealing it.
template NameVerification() {
    signal input nameHash;         // private
    signal input claimedNameHash;  // public

    component eq = IsEqual();
    eq.in[0] <== nameHash;
    eq.in[1] <== claimedNameHash;
    eq.out === 1;
}

component main {public [claimedNameHash]} = NameVerification();
