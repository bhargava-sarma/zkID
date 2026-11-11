// Poseidon2 hash over field elements: the sponge of Noir's standard library
// (rate 3, capacity 1, the input length in the capacity), which the standard
// library keeps private, over its public permutation. inputs.mjs computes the
// same with Barretenberg's permutation.

pub fn hash<let N: u32>(input: [Field; N]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, (N as Field) * 18446744073709551616];
    for i in 0..(N / 3) {
        for j in 0..3 {
            state[j] += input[3 * i + j];
        }
        state = std::hash::poseidon2_permutation(state);
    }
    for i in 0..(N % 3) {
        state[i] += input[(N / 3) * 3 + i];
    }
    std::hash::poseidon2_permutation(state)[0]
}

#[test]
fn matches_the_standard_library() {
    // The standard library's own test vector for 1, 2, 3, 4, 5.
    assert(hash([1, 2, 3, 4, 5]) == 0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db);
}
