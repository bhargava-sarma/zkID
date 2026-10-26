pragma circom 2.1.6;
include "@zk-email/circuits/lib/sha.circom";
// SHA-256 over at most 1152 bytes (already SHA-padded), as zk-email and Anon Aadhaar hash Secure QR data.
component main = Sha256Bytes(1152);
