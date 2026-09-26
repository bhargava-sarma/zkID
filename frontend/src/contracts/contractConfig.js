export const CONTRACT_ADDRESSES = {
  age: "0xa5075F2E83167C3c7fE5c3C3F1Fc5FCF1d378232",
  name: "0x23715a3216ACdF715a75463939A342b844dd01eE",
};

// Must be CORS-enabled: this runs in the browser.
export const AMOY_RPC =
  import.meta.env.VITE_AMOY_RPC_URL || "https://polygon-amoy-bor-rpc.publicnode.com";

// Both deployed verifiers take one public signal.
export const VERIFIER_ABI = [
  "function verifyProof(uint256[2] calldata _pA, uint256[2][2] calldata _pB, uint256[2] calldata _pC, uint256[1] calldata _pubSignals) public view returns (bool)",
];
