import addresses from "./addresses.json";

// Written by `hardhat deploy-verifier`. A proof type without an address has no on-chain check.
export const VERIFIERS = {
  age: { address: addresses.AgeVerifier, publicSignals: 1 },
  name: { address: addresses.NameVerifier, publicSignals: 1 },
  gender: { address: addresses.GenderVerifier, publicSignals: 1 },
  signed: { address: addresses.CredentialAgeVerifier, publicSignals: 18 },
};

export const hasVerifier = (proofType) => Boolean(VERIFIERS[proofType]?.address);

// The RPC must be CORS-enabled: calls come from the browser.
export const CHAIN = {
  name: "Ethereum Sepolia",
  rpc: import.meta.env.VITE_SEPOLIA_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com",
  explorer: "https://sepolia.etherscan.io",
};

export const verifierAbi = (publicSignals) => [
  `function verifyProof(uint256[2] calldata _pA, uint256[2][2] calldata _pB, uint256[2] calldata _pC, uint256[${publicSignals}] calldata _pubSignals) public view returns (bool)`,
];
