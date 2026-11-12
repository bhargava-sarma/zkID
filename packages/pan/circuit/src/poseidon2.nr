// Poseidon2 hash over field elements, as Barretenberg's poseidon2Hash computes
// it (rate 3, capacity 1, the input length in the capacity): each block of three
// inputs is added to the state and permuted, and a last partial block too. The
// JavaScript side computes the same with @zkpassport/poseidon2 (keyhash.mjs).
// Noir's standard library keeps its own hasher private, and that one permutes
// once more when the length is a multiple of three, so it is not used here.

pub fn hash<let N: u32>(input: [Field; N]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, (N as Field) * 18446744073709551616];
    for i in 0..(N / 3) {
        for j in 0..3 {
            state[j] += input[3 * i + j];
        }
        state = std::hash::poseidon2_permutation(state);
    }
    if N % 3 != 0 {
        for i in 0..(N % 3) {
            state[i] += input[(N / 3) * 3 + i];
        }
        state = std::hash::poseidon2_permutation(state);
    }
    state[0]
}
