#!/usr/bin/env bash
# Compiles each measured circuit with circom (--O1 is circom 2.2.3's default,
# --O2 is full simplification) and records snarkjs r1cs info in results/.
# Needs: circom on PATH, npm install here, and the Anon Aadhaar clone at
# $ANON_AADHAAR (default /home/user/anon-aadhaar/anon-aadhaar, commit 4dad918).
set -euo pipefail
cd "$(dirname "$0")"
ANON_AADHAAR="${ANON_AADHAAR:-/home/user/anon-aadhaar/anon-aadhaar}"
V1_AGE="../../backend/circuits/credential-age-proof/circuits/credential_age_proof.circom"
OUT=results
BUILD="${BUILD:-build}"
mkdir -p "$OUT" "$BUILD"

circuits=(
  "sha256_bytes_640:circuits/sha256_bytes_640.circom"
  "sha256_bytes_1152:circuits/sha256_bytes_1152.circom"
  "sha256_bytes_1536:circuits/sha256_bytes_1536.circom"
  "sha256_bytes_2048:circuits/sha256_bytes_2048.circom"
  "rsa_121_17:circuits/rsa_121_17.circom"
  "zkid_v1_age:$V1_AGE"
  "anon_aadhaar_4dad918:$ANON_AADHAAR/packages/circuits/src/aadhaar-verifier.circom"
)

echo "circom: $(circom --version) sha256 $(sha256sum "$(command -v circom)" | cut -c1-16)" | tee "$OUT/toolchain.txt"
echo "anon-aadhaar: $(git -C "$ANON_AADHAAR" rev-parse HEAD)" | tee -a "$OUT/toolchain.txt"
echo "@zk-email/circuits $(node -p "require('@zk-email/circuits/package.json').version"), circomlib $(node -p "require('circomlib/package.json').version"), snarkjs $(node -p "JSON.parse(require('fs').readFileSync('node_modules/snarkjs/package.json','utf8')).version")" | tee -a "$OUT/toolchain.txt"
echo "machine: $(node -p "require('os').cpus()[0].model") x$(nproc) cores, $(node -p "Math.round(require('os').totalmem()/2**30)") GB RAM, Node $(node --version)" | tee -a "$OUT/toolchain.txt"
: > "$OUT/constraints.txt"

for entry in "${circuits[@]}"; do
  name="${entry%%:*}"; src="${entry#*:}"
  for opt in O1 O2; do
    dir="$BUILD/$name-$opt"; mkdir -p "$dir"
    start=$(date +%s)
    circom "$src" --r1cs "--$opt" -l node_modules -o "$dir" > "$dir/circom.log" 2>&1
    secs=$(( $(date +%s) - start ))
    r1cs=$(ls "$dir"/*.r1cs)
    info=$(npx snarkjs r1cs info "$r1cs" 2>&1 | sed -n 's/.*# of \(Wires\|Constraints\|Private Inputs\|Public Inputs\|Outputs\): \([0-9]*\).*/\1=\2/p' | tr '\n' ' ')
    echo "$name $opt compile=${secs}s $info" | tee -a "$OUT/constraints.txt"
  done
done
