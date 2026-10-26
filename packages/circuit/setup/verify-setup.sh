#!/usr/bin/env bash
# Checks that the proving key pinned in artifacts.json (Anon Aadhaar v2.0.0)
# was generated from Anon Aadhaar's circuit source and the Hermez powers of
# tau: rebuilds the circuit, then runs `snarkjs zkey verify`, which also checks
# every phase-2 contribution and the beacon.
#
# About 15 minutes, 4 GB of memory and 3 GB of downloads.
# Needs: git, curl, sha256sum, b2sum, node 20+.
# Usage: bash setup/verify-setup.sh [work dir]   (default: setup/work, gitignored)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
work="${1:-$here/setup/work}"

# Circuit source: the commit the published key was built from (2024-06-25).
AA_REPO=https://github.com/anon-aadhaar/anon-aadhaar
AA_COMMIT=b61b687c116c9ec25e0835b69b6c5a824e9072d4
# Toolchain that reproduces the key's 1,040,218 constraints (docs/circuit-spec.md).
CIRCOM_URL=https://github.com/iden3/circom/releases/download/v2.1.9/circom-linux-amd64
CIRCOM_SHA256=e5575829252d763b7818049df9de2ef9304df834697de77fa63ce7babc23c967
# Hermez powers of tau, 2^20. The original hosts now deny access; the snarkjs
# README links this host and gives this BLAKE2b-512 hash.
PTAU_URL=https://circom.info/powersOfTau28_hez_final_20.ptau
PTAU_B2=89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c7556a52b323178269d64af325d8fdddb33da3a27c34409b821de82aa2bf1a27b

mkdir -p "$work"
cd "$work"

echo "== circuit source $AA_COMMIT"
[ -d anon-aadhaar ] || git clone --quiet "$AA_REPO" anon-aadhaar
git -C anon-aadhaar checkout --quiet "$AA_COMMIT"

echo "== libraries pinned by its yarn.lock at that commit"
[ -f package.json ] || echo '{ "private": true }' > package.json
npm install --no-audit --no-fund --silent @zk-email/circuits@6.1.1 circomlib@2.0.5 snarkjs@0.7.6

echo "== circom 2.1.9"
[ -f circom ] || curl -sSfL -o circom "$CIRCOM_URL"
echo "$CIRCOM_SHA256  circom" | sha256sum -c -
chmod +x circom

echo "== compile (--O2)"
./circom anon-aadhaar/packages/circuits/src/aadhaar-verifier.circom --r1cs --O2 -l node_modules -o . | tail -3

echo "== powers of tau"
[ -f pot20.ptau ] || curl -sSfL -o pot20.ptau "$PTAU_URL"
echo "$PTAU_B2  pot20.ptau" | b2sum -c -

echo "== proving key"
(cd "$here" && node fetch-artifacts.mjs circuit_final.zkey)

echo "== snarkjs zkey verify"
node --max-old-space-size=12000 node_modules/snarkjs/build/cli.cjs zkey verify \
  aadhaar-verifier.r1cs pot20.ptau "$here/artifacts/circuit_final.zkey" | sed -e 's/\x1b\[[0-9;]*m//g' > zkey-verify.log
grep -E "Circuit hash|contribution #|ZKey" zkey-verify.log | head -4
grep -q "ZKey Ok!" zkey-verify.log && echo "OK: the pinned proving key matches the circuit source and the Hermez powers of tau."
