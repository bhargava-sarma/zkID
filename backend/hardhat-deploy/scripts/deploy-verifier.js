// Deploys one contract and records its address in the frontend's addresses.json.
// A replaced address moves to `retired`. Constructor arguments, if any, are kept
// in constructor-args.json for source verification on Etherscan.
const fs = require("fs");
const path = require("path");

const ADDRESSES_PATH = path.join(__dirname, "..", "..", "..", "frontend", "src", "contracts", "addresses.json");
const ARGS_PATH = path.join(__dirname, "..", "constructor-args.json");

async function deployContract(hre, contract, args = []) {
  const { ethers, network } = hre;
  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Network  : ${network.name}`);
  console.log(`Deployer : ${deployer.address}`);
  console.log(`Balance  : ${ethers.formatEther(balance)} ETH`);

  // Refuse up front rather than fail mid-deploy.
  const factory = await ethers.getContractFactory(contract);
  const gas = await ethers.provider.estimateGas(await factory.getDeployTransaction(...args));
  // Nodes require balance >= gas * maxFeePerGas, so check against that.
  const { gasPrice, maxFeePerGas } = await ethers.provider.getFeeData();
  const cost = gas * (maxFeePerGas ?? gasPrice);
  console.log(`Estimate : ${gas} gas, at most ${ethers.formatEther(cost)} ETH`);
  if (balance < cost) {
    throw new Error(`Insufficient balance. Fund ${deployer.address} with ~${ethers.formatEther(cost)} ETH.`);
  }

  const c = await factory.deploy(...args);
  await c.waitForDeployment();
  const address = await c.getAddress();
  console.log(`\n${contract} deployed to ${address}`);
  console.log(`Tx: ${c.deploymentTransaction().hash}`);

  if (network.name !== "sepolia") return address;

  const existing = fs.existsSync(ADDRESSES_PATH) ? JSON.parse(fs.readFileSync(ADDRESSES_PATH, "utf8")) : {};
  const previous = existing[contract];
  const updated = { ...existing, [contract]: address };
  if (previous && previous.startsWith("0x")) {
    updated.retired = { ...(existing.retired || {}), [`${contract}_${new Date().toISOString().slice(0, 10)}`]: previous };
  }
  fs.writeFileSync(ADDRESSES_PATH, JSON.stringify(updated, null, 2) + "\n");
  console.log(`Recorded in ${path.relative(process.cwd(), ADDRESSES_PATH)}. Commit it to publish.`);

  if (args.length) {
    const encoded = factory.interface.encodeDeploy(args).slice(2);
    const saved = fs.existsSync(ARGS_PATH) ? JSON.parse(fs.readFileSync(ARGS_PATH, "utf8")) : {};
    fs.writeFileSync(ARGS_PATH, JSON.stringify({ ...saved, [address]: encoded }, null, 2) + "\n");
  }
  return address;
}

// ZkIdPolicy over the deployed verifiers, trusting the mock issuer's key.
async function deployPolicy(hre) {
  const addresses = JSON.parse(fs.readFileSync(ADDRESSES_PATH, "utf8"));
  for (const name of ["CredentialAgeVerifier", "CredentialMatchVerifier"]) {
    if (!addresses[name]) throw new Error(`Deploy ${name} first: it is not in addresses.json.`);
  }
  const issuer = require("../../../mock-issuer/circuit_inputs.json").modulus_limbs;
  return deployContract(hre, "ZkIdPolicy", [addresses.CredentialAgeVerifier, addresses.CredentialMatchVerifier, issuer]);
}

module.exports = { deployContract, deployPolicy };
