#!/usr/bin/env node
// Read-only audit of the v1 ZkIdPolicy on Ethereum Sepolia: does it trust a key
// listed in security/compromised-keys.json? Uses eth_call, eth_getCode and
// eth_getLogs only. Sends no transactions and needs no private key.
//
// Usage: node check_sepolia_issuer.mjs   (SEPOLIA_RPC_URL overrides the RPC list)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..', '..');
const addresses = JSON.parse(fs.readFileSync(path.join(root, 'frontend/src/contracts/addresses.json'), 'utf8'));
const compromised = JSON.parse(fs.readFileSync(path.join(root, 'security/compromised-keys.json'), 'utf8')).keys;

const SEPOLIA_CHAIN_ID = 11155111n;
// v1 address. Kept here so the check still works after addresses.json marks it retired.
const POLICY = '0x8eDa6b1A54900c60C6b730796FfDd51a5327714f';
const RPCS = process.env.SEPOLIA_RPC_URL
  ? [process.env.SEPOLIA_RPC_URL]
  : ['https://ethereum-sepolia-rpc.publicnode.com', 'https://sepolia.drpc.org'];

const ABI = [
  'function owner() view returns (address)',
  'function ageVerifier() view returns (address)',
  'function matchVerifier() view returns (address)',
  'function trustedIssuers(bytes32) view returns (bool)',
  'function issuerKeyHash(uint256[17] modulus) pure returns (bytes32)',
  'event IssuerTrustChanged(bytes32 indexed keyHash, bool trusted)',
];

// RSA-2048 modulus as 17 x 121-bit limbs, least significant first (the circuit layout).
function limbs(modulusHex) {
  const mask = (1n << 121n) - 1n;
  let n = BigInt(`0x${modulusHex}`);
  const out = [];
  for (let i = 0; i < 17; i++) {
    out.push(n & mask);
    n >>= 121n;
  }
  if (n !== 0n) throw new Error('Modulus does not fit in 17 x 121 bits.');
  return out;
}

// keccak256(abi.encodePacked(uint256[17])): each element padded to 32 bytes.
const keyHash = (ls) => ethers.keccak256(ethers.concat(ls.map((l) => ethers.toBeHex(l, 32))));

async function check(rpc) {
  const provider = new ethers.JsonRpcProvider(rpc, undefined, { staticNetwork: true });
  const { chainId } = await provider.getNetwork();
  if (chainId !== SEPOLIA_CHAIN_ID) throw new Error(`${rpc} is chain ${chainId}, not Sepolia`);
  const block = await provider.getBlock('latest');
  const code = await provider.getCode(POLICY);
  if (code === '0x') throw new Error(`No contract code at ${POLICY}`);

  const policy = new ethers.Contract(POLICY, ABI, provider);
  const result = {
    rpc,
    block: block.number,
    blockTime: new Date(block.timestamp * 1000).toISOString(),
    owner: await policy.owner(),
    ageVerifier: await policy.ageVerifier(),
    matchVerifier: await policy.matchVerifier(),
    keys: [],
  };
  for (const key of compromised) {
    const ls = limbs(key.modulus_hex);
    const local = keyHash(ls);
    const onChain = await policy.issuerKeyHash(ls);
    if (local !== onChain) throw new Error(`issuerKeyHash mismatch for ${key.label}: ${local} vs ${onChain}`);
    result.keys.push({ label: key.label, keyHash: local, trusted: await policy.trustedIssuers(local) });
  }

  // Every trust change since deployment. Free public RPCs prune old logs or cap
  // log ranges; report that rather than guess.
  try {
    const events = await policy.queryFilter(policy.filters.IssuerTrustChanged(), 0, block.number);
    result.trustChanges = events.map((e) => ({ block: e.blockNumber, keyHash: e.args.keyHash, trusted: e.args.trusted }));
  } catch (err) {
    result.trustChanges = `unavailable from this RPC: ${err.shortMessage || err.message}`;
  }
  return result;
}

// The same history from Blockscout's public indexer (third party, no API key),
// for when the RPCs cannot serve old logs. Also lists every transaction sent to
// the policy, so a setIssuer call could not be missed.
async function blockscoutHistory() {
  const base = `https://eth-sepolia.blockscout.com/api/v2/addresses/${POLICY}`;
  const pages = async (url) => {
    const items = [];
    let params = null;
    do {
      const res = await fetch(params ? `${url}?${new URLSearchParams(params)}` : url);
      if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
      const body = await res.json();
      items.push(...body.items);
      params = body.next_page_params;
    } while (params);
    return items;
  };
  const iface = new ethers.Interface(ABI);
  const topic = iface.getEvent('IssuerTrustChanged').topicHash;
  const logs = await pages(`${base}/logs`);
  const txs = await pages(`${base}/transactions`);
  return {
    source: 'eth-sepolia.blockscout.com',
    trustChanges: logs
      .filter((l) => l.topics[0] === topic)
      .map((l) => {
        const parsed = iface.parseLog({ topics: l.topics.filter(Boolean), data: l.data });
        return { block: l.block_number, tx: l.transaction_hash, keyHash: parsed.args.keyHash, trusted: parsed.args.trusted };
      }),
    transactions: txs.map((t) => ({ block: t.block_number, tx: t.hash, from: t.from?.hash, method: t.method, status: t.status })),
  };
}

// The deployment's constructor arguments, as recorded for Etherscan verification.
function constructorIssuerMatches(key) {
  const args = JSON.parse(fs.readFileSync(path.join(root, 'backend/hardhat-deploy/constructor-args.json'), 'utf8'))[POLICY];
  if (!args) return null;
  const words = args.match(/.{64}/g).map((w) => BigInt(`0x${w}`));
  // (address ageVerifier, address matchVerifier, uint256[17] issuerModulus)
  return words.slice(2, 19).every((w, i) => w === limbs(key.modulus_hex)[i]);
}

let failed = 0;
for (const rpc of RPCS) {
  try {
    const r = await check(rpc);
    console.log(JSON.stringify(r, null, 2));
    console.log(`policy verifiers match addresses.json: ` +
      `${r.ageVerifier === (addresses.CredentialAgeVerifier ?? addresses.retired?.CredentialAgeVerifier)}`);
  } catch (err) {
    failed++;
    console.error(`[${rpc}] ${err.message}`);
  }
}
for (const key of compromised) {
  console.log(`constructor-args.json trusts "${key.label}": ${constructorIssuerMatches(key)}`);
}
try {
  console.log(JSON.stringify(await blockscoutHistory(), null, 2));
} catch (err) {
  console.error(`[blockscout] ${err.message}`);
}
process.exit(failed === RPCS.length ? 1 : 0);
