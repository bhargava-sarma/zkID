pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

// Proves DOB <= thresholdDate without revealing DOB.
// Dates are year*10000 + month*100 + day, so integer order is date order.
template AgeVerification() {
    signal input dobEncoded;      // private
    signal input thresholdDate;   // public: latest qualifying DOB

    // 32 bits covers encodings up to 99991231.
    component le = LessEqThan(32);
    le.in[0] <== dobEncoded;
    le.in[1] <== thresholdDate;

    // Asserted: a witness exists only for someone who passes.
    le.out === 1;
}

component main {public [thresholdDate]} = AgeVerification();
