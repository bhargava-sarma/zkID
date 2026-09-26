import { ethers } from "ethers";
import { VERIFIERS, AMOY_RPC, verifierAbi } from "./contractConfig";

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

// Read-only view call on Polygon Amoy: no wallet or gas needed.
export async function verifyOnChain(proof, publicSignals, proofType) {
  const verifier = VERIFIERS[proofType];
  const contractAddress = verifier?.address;
  if (!contractAddress) {
    return {
      onChainValid: false,
      contractAddress: null,
      error: `No on-chain verifier deployed for "${proofType}" proofs.`,
    };
  }

  try {
    const provider = new ethers.JsonRpcProvider(AMOY_RPC);
    const contract = new ethers.Contract(contractAddress, verifierAbi(verifier.publicSignals), provider);
    const { pA, pB, pC } = formatProofForSolidity(proof);
    const result = await contract.verifyProof(pA, pB, pC, publicSignals.map((s) => BigInt(s)));
    return { onChainValid: Boolean(result), contractAddress, error: null };
  } catch (err) {
    console.error(`[ON-CHAIN:${proofType.toUpperCase()}] Verification error:`, err);
    let errorMessage = err.message || "Unknown error during on-chain verification.";
    if (errorMessage.length > 200) {
      errorMessage = errorMessage.substring(0, 200) + "...";
    }
    return { onChainValid: false, contractAddress, error: errorMessage };
  }
}
