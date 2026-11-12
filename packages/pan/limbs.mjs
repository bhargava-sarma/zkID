// RSA numbers as the circuit takes them: 18 limbs of 120 bits, lowest first.
export const LIMB_BITS = 120;
export const LIMBS = 18;
const MASK = (1n << BigInt(LIMB_BITS)) - 1n;

export function limbs(value) {
  if (value < 0n || value >> BigInt(LIMB_BITS * LIMBS)) throw new RangeError('value does not fit in 18 limbs of 120 bits');
  return Array.from({ length: LIMBS }, (_, i) => ((value >> BigInt(LIMB_BITS * i)) & MASK).toString());
}
