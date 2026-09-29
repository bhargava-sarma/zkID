import { ethers } from "ethers";
import { CHAIN, POLICY_ABI, POLICY_ADDRESS, POLICY_RESULTS } from "./contractConfig";

// snarkjs -> Solidity calldata. pi_b's inner pairs are reversed for the verifier.
function formatProofForSolidity(proof) {
  const pA = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
  const pB = [
    [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
    [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
  ];
  const pC = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
  return { pA, pB, pC };
}

// Asks ZkIdPolicy whether it accepts the proof. A read-only view call: no wallet
// or gas. kind: 'age' for the age proof, anything else for a name/gender proof.
// result is one of POLICY_RESULTS, or null when the call itself failed.
export async function checkOnChain(proof, publicSignals, kind) {
  if (!POLICY_ADDRESS) {
    return { result: null, contractAddress: null, error: "No ZkIdPolicy is deployed." };
  }

  try {
    const provider = new ethers.JsonRpcProvider(CHAIN.rpc);
    const policy = new ethers.Contract(POLICY_ADDRESS, POLICY_ABI, provider);
    const { pA, pB, pC } = formatProofForSolidity(proof);
    const signals = publicSignals.map((s) => BigInt(s));
    const code = kind === "age" ? await policy.checkAge(pA, pB, pC, signals) : await policy.checkMatch(pA, pB, pC, signals);
    return { result: POLICY_RESULTS[Number(code)] ?? `Unknown (${code})`, contractAddress: POLICY_ADDRESS, error: null };
  } catch (err) {
    console.error(`[ON-CHAIN:${kind.toUpperCase()}] Policy check error:`, err);
    let errorMessage = err.message || "Unknown error during on-chain verification.";
    if (errorMessage.length > 200) {
      errorMessage = errorMessage.substring(0, 200) + "...";
    }
    return { result: null, contractAddress: POLICY_ADDRESS, error: errorMessage };
  }
}
