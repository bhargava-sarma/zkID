require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: ".env.hardhat" });

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
    polygonCardona: {
      url: process.env.RPC_URL || "https://rpc.cardona.zkevm-rpc.com",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 2442,
      gasPrice: "auto"
    },
    amoy: {
      // Overridable because the official endpoint has been unreliable — it was
      // returning nothing at all during the v2 verifier deploy. Same pattern as
      // polygonCardona above. Any Amoy (chainId 80002) RPC works.
      url: process.env.AMOY_RPC_URL || "https://rpc-amoy.polygon.technology",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 80002,
      gasPrice: "auto"
    }
  }
};
