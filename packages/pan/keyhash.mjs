// Barretenberg's Poseidon2 hash, as the circuit computes it (poseidon2.nr),
// and the key hash the circuit outputs for a DigiLocker signing key: Poseidon2
// over the modulus's 18 limbs of 120 bits. The issuer registry pins keys by it.

import { poseidon2Hash } from '@zkpassport/poseidon2';
import { limbs } from './limbs.mjs';

export const poseidon2 = (inputs) => poseidon2Hash(inputs);

// Decimal, as the registry stores key hashes.
export const panKeyHash = (modulusHex) => poseidon2Hash(limbs(BigInt(`0x${modulusHex}`)).map(BigInt)).toString();
