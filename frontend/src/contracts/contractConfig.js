import addresses from "./addresses.json";

// ZkIdPolicy checks every proof on-chain: trusted issuer, the age cutoff, then
// the Groth16 verifier. Written by `npm run deploy:policy`; without it the app
// hides the on-chain check.
export const POLICY_ADDRESS = addresses.ZkIdPolicy || null;
export const hasPolicy = () => Boolean(POLICY_ADDRESS);

// The RPC must be CORS-enabled: calls come from the browser.
export const CHAIN = {
  name: "Ethereum Sepolia",
  rpc: import.meta.env.VITE_SEPOLIA_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com",
  explorer: "https://sepolia.etherscan.io",
};

const PROOF_ARGS = "uint256[2] pA, uint256[2][2] pB, uint256[2] pC";
export const POLICY_ABI = [
  `function checkAge(${PROOF_ARGS}, uint256[18] pubSignals) view returns (uint8)`,
  `function checkMatch(${PROOF_ARGS}, uint256[19] pubSignals) view returns (uint8)`,
];

// ZkIdPolicy.Result, in declaration order.
export const POLICY_RESULTS = ["Accepted", "UntrustedIssuer", "CutoffTooLate", "NothingClaimed", "InvalidProof"];
