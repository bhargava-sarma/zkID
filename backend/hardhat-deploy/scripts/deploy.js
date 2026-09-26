// Deploys all three verifiers. To redeploy only AgeVerifier, use deploy-age.js:
// this script mints new addresses for every contract.
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const CONTRACTS = ["AgeVerifier", "NameVerifier", "GenderVerifier"];

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("\nDeploying contracts with account:", deployer.address);
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("Account balance:", ethers.formatEther(balance), "MATIC\n");

  const deployedAddresses = {};
  for (const name of CONTRACTS) {
    console.log(`Deploying ${name}...`);
    const contract = await (await ethers.getContractFactory(name)).deploy();
    await contract.waitForDeployment();
    deployedAddresses[name] = await contract.getAddress();
    console.log(`${name} deployed to:`, deployedAddresses[name]);
  }

  const outputPath = path.join(__dirname, "../abis/deployed-addresses.json");
  fs.writeFileSync(outputPath, JSON.stringify(deployedAddresses, null, 2));
  console.log("\nAll contracts deployed. Addresses saved to abis/deployed-addresses.json");
  console.log(JSON.stringify(deployedAddresses, null, 2));

  const artifactsBase = path.join(__dirname, "../artifacts/contracts");
  for (const name of CONTRACTS) {
    const artifactPath = path.join(artifactsBase, `${name}.sol/${name}.json`);
    if (fs.existsSync(artifactPath)) {
      const artifact = JSON.parse(fs.readFileSync(artifactPath));
      fs.writeFileSync(path.join(__dirname, `../abis/${name}.json`), JSON.stringify(artifact.abi, null, 2));
      console.log(`ABI saved: abis/${name}.json`);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
