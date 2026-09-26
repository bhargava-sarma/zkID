require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: ".env.hardhat" });
const { task } = require("hardhat/config");

task("deploy-verifier", "Deploy one Groth16 verifier contract")
  .addParam("contract", "AgeVerifier | NameVerifier | GenderVerifier | CredentialAgeVerifier")
  .setAction(async ({ contract }, hre) => require("./scripts/deploy-verifier")(hre, contract));

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
    amoy: {
      url: process.env.AMOY_RPC_URL || "https://polygon-amoy-bor-rpc.publicnode.com",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 80002,
      gasPrice: "auto"
    }
  }
};
