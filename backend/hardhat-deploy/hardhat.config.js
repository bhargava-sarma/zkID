require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: ".env.hardhat" });
const { task } = require("hardhat/config");

task("deploy-verifier", "Deploy one Groth16 verifier contract")
  .addParam("contract", "CredentialAgeVerifier | CredentialMatchVerifier")
  .setAction(async ({ contract }, hre) => require("./scripts/deploy-verifier").deployContract(hre, contract));

task("deploy-policy", "Deploy ZkIdPolicy over the deployed verifiers, trusting the mock issuer")
  .setAction(async (_, hre) => require("./scripts/deploy-verifier").deployPolicy(hre));

task("verify-verifiers", "Publish verifier source to Sourcify (and Etherscan with ETHERSCAN_API_KEY)")
  .setAction(async (_, hre) => require("./scripts/verify-verifiers")(hre));

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    // Tests start the day before the fixture proofs' cutoff date (test/policy.test.js).
    hardhat: {
      initialDate: "2026-09-27T12:00:00Z"
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 11155111
    }
  }
};
