// Publishes the source of every verifier in addresses.json: to Sourcify always
// (no key needed), and to Etherscan when ETHERSCAN_API_KEY is set.
const ADDRESSES = require("../../../frontend/src/contracts/addresses.json");

const SOURCIFY = "https://sourcify.dev/server";
const ETHERSCAN = "https://api.etherscan.io/v2/api";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function sourcify(chainId, address, fqn, buildInfo) {
  const existing = await fetch(`${SOURCIFY}/v2/contract/${chainId}/${address}`);
  if (existing.ok) {
    const { match } = await existing.json();
    if (match) return `already verified (${match})`;
  }
  const res = await fetch(`${SOURCIFY}/v2/verify/${chainId}/${address}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ stdJsonInput: buildInfo.input, compilerVersion: buildInfo.solcLongVersion, contractIdentifier: fqn }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(body.message || `HTTP ${res.status}`);
  for (let i = 0; i < 40; i++) {
    await sleep(3000);
    const job = await (await fetch(`${SOURCIFY}/v2/verify/${body.verificationId}`)).json();
    if (job.isJobCompleted) {
      if (job.error) throw new Error(job.error.message);
      return job.contract.match;
    }
  }
  throw new Error("timed out");
}

async function etherscan(chainId, address, fqn, buildInfo, apikey) {
  const get = (params) => fetch(`${ETHERSCAN}?${new URLSearchParams({ chainid: chainId, apikey, ...params })}`).then((r) => r.json());
  const current = await get({ module: "contract", action: "getsourcecode", address });
  if (current.status === "1" && current.result[0]?.SourceCode) return "already verified";

  const submit = await fetch(`${ETHERSCAN}?chainid=${chainId}`, {
    method: "POST",
    body: new URLSearchParams({
      apikey,
      module: "contract",
      action: "verifysourcecode",
      contractaddress: address,
      sourceCode: JSON.stringify(buildInfo.input),
      codeformat: "solidity-standard-json-input",
      contractname: fqn,
      compilerversion: `v${buildInfo.solcLongVersion}`,
    }),
  }).then((r) => r.json());
  if (submit.status !== "1") {
    if (/already verified/i.test(submit.result)) return "already verified";
    throw new Error(submit.result);
  }
  for (let i = 0; i < 40; i++) {
    await sleep(3000);
    const { result } = await get({ module: "contract", action: "checkverifystatus", guid: submit.result });
    if (/^Pass/i.test(result)) return "verified";
    if (!/pending|queue/i.test(result)) throw new Error(result);
  }
  throw new Error("timed out");
}

module.exports = async function verifyVerifiers(hre) {
  const chainId = hre.network.config.chainId;
  const apikey = process.env.ETHERSCAN_API_KEY;
  let failed = false;
  for (const [contract, address] of Object.entries(ADDRESSES)) {
    if (contract === "retired" || typeof address !== "string") continue;
    const fqn = `contracts/${contract}.sol:${contract}`;
    const buildInfo = await hre.artifacts.getBuildInfo(fqn);
    const targets = [["Sourcify", () => sourcify(chainId, address, fqn, buildInfo)]];
    if (apikey) targets.push(["Etherscan", () => etherscan(chainId, address, fqn, buildInfo, apikey)]);
    for (const [name, run] of targets) {
      try {
        console.log(`${contract.padEnd(22)} ${name.padEnd(9)} ${await run()}`);
      } catch (err) {
        failed = true;
        console.log(`${contract.padEnd(22)} ${name.padEnd(9)} FAILED: ${err.message}`);
      }
    }
  }
  if (!apikey) console.log("\nEtherscan skipped: set ETHERSCAN_API_KEY in .env.hardhat to publish there too.");
  if (failed) process.exitCode = 1;
};
