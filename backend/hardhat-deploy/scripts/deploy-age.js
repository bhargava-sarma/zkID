// Deploys only AgeVerifier and merges its address into abis/deployed-addresses.json.
// The previous address is kept under `retired`.

const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");

const ADDRESSES_PATH = path.join(__dirname, "..", "abis", "deployed-addresses.json");

async function main() {
  const [deployer] = await ethers.getSigners();
  const net = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`Network  : ${network.name} (chainId ${net.chainId})`);
  console.log(`Deployer : ${deployer.address}`);
  console.log(`Balance  : ${ethers.formatEther(balance)}`);

  if (balance === 0n) {
    throw new Error("Deployer has zero balance; fund it before deploying.");
  }

  const existing = fs.existsSync(ADDRESSES_PATH)
    ? JSON.parse(fs.readFileSync(ADDRESSES_PATH, "utf8"))
    : {};
  const previous = existing.AgeVerifier;
  console.log(`Previous AgeVerifier: ${previous || "(none)"}`);

  console.log("\nDeploying AgeVerifier (date-comparison v2, 1 public signal)...");
  const AgeVerifier = await ethers.getContractFactory("AgeVerifier");
  const c = await AgeVerifier.deploy();
  await c.waitForDeployment();
  const address = await c.getAddress();
  const tx = c.deploymentTransaction();

  console.log(`AgeVerifier deployed to: ${address}`);
  console.log(`Deploy tx: ${tx.hash}`);

  const updated = {
    ...existing,
    AgeVerifier: address,
    retired: {
      ...(existing.retired || {}),
      // days-since-epoch verifier: 2 public signals, ABI-incompatible with v2.
      AgeVerifier_v1_dobDays: previous || null,
    },
    _meta: {
      ...(existing._meta || {}),
      network: network.name,
      chainId: Number(net.chainId),
      ageVerifierDeployTx: tx.hash,
    },
  };

  fs.writeFileSync(ADDRESSES_PATH, JSON.stringify(updated, null, 2) + "\n");
  console.log(`\nWrote ${path.relative(process.cwd(), ADDRESSES_PATH)}`);
  console.log(JSON.stringify(updated, null, 2));
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
