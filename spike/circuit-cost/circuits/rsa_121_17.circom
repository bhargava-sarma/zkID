pragma circom 2.1.6;
include "@zk-email/circuits/lib/rsa.circom";
// RSA-2048 PKCS#1 v1.5 verification (e = 65537), 17 limbs of 121 bits.
component main { public [modulus] } = RSAVerifier65537(121, 17);
