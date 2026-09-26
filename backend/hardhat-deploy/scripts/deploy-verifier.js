// Deploys one verifier and records its address in the frontend's addresses.json.
// A replaced address moves to `retired`.
const fs = require("fs");
const path = require("path");

const ADDRESSES_PATH = path.join(__dirname, "..", "..", "..", "frontend", "src", "contracts", "addresses.json");

module.exports = async function deployVerifier(hre, contract) {
  const { ethers, network } = hre;
  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Network  : ${network.name}`);
  console.log(`Deployer : ${deployer.address}`);
  console.log(`Balance  : ${ethers.formatEther(balance)} ETH`);

  // Refuse up front rather than fail mid-deploy.
  const factory = await ethers.getContractFactory(contract);
  const gas = await ethers.provider.estimateGas(await factory.getDeployTransaction());
  // Nodes require balance >= gas * maxFeePerGas, so check against that.
  const { gasPrice, maxFeePerGas } = await ethers.provider.getFeeData();
  const cost = gas * (maxFeePerGas ?? gasPrice);
  console.log(`Estimate : ${gas} gas, at most ${ethers.formatEther(cost)} ETH`);
  if (balance < cost) {
    throw new Error(`Insufficient balance. Fund ${deployer.address} with ~${ethers.formatEther(cost)} ETH.`);
  }

  const c = await factory.deploy();
  await c.waitForDeployment();
  const address = await c.getAddress();
  console.log(`\n${contract} deployed to ${address}`);
  console.log(`Tx: ${c.deploymentTransaction().hash}`);

  if (network.name !== "sepolia") return;

  const existing = fs.existsSync(ADDRESSES_PATH) ? JSON.parse(fs.readFileSync(ADDRESSES_PATH, "utf8")) : {};
  const previous = existing[contract];
  const updated = { ...existing, [contract]: address };
  if (previous && previous.startsWith("0x")) {
    updated.retired = { ...(existing.retired || {}), [`${contract}_${new Date().toISOString().slice(0, 10)}`]: previous };
  }
  fs.writeFileSync(ADDRESSES_PATH, JSON.stringify(updated, null, 2) + "\n");
  console.log(`Recorded in ${path.relative(process.cwd(), ADDRESSES_PATH)}. Commit it to publish.`);
};
