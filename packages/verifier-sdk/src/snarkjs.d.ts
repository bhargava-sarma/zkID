// The part of snarkjs (0.7.6, no bundled types) that this package uses.
declare module 'snarkjs' {
  export const groth16: {
    verify(verificationKey: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  };
}
