#!/bin/bash
# Compiles the legacy circuits and runs Groth16 setup.
# Requires circom 2.x and snarkjs. New keys invalidate the deployed verifiers.
set -e

cd "$(dirname "$0")"

npm install --silent

# Hermez ceremony file, mirrored in the zkID release (the original hosts are gone).
PTAU_URL=https://github.com/bhargava-sarma/zkID/releases/download/circuit-v1/powersOfTau28_hez_final_12.ptau
PTAU_B2=ded2694169b7b08e898f736d5de95af87c3f1a64594013351b1a796dbee393bd825f88f9468c84505ddd11eb0b1465ac9b43b9064aa8ec97f2b73e04758b8a4a
if [ ! -f pot12_final.ptau ]; then
    curl -fsSL "$PTAU_URL" -o pot12_final.ptau
fi
echo "$PTAU_B2  pot12_final.ptau" | b2sum -c --quiet

setup_circuit() {
    local NAME=$1
    local PREFIX=$2
    echo "--- ${NAME} ---"
    circom "${NAME}.circom" --r1cs --wasm --sym -o .
    snarkjs groth16 setup "${NAME}.r1cs" pot12_final.ptau "${PREFIX}_0000.zkey"
    snarkjs zkey contribute "${PREFIX}_0000.zkey" "${PREFIX}_final.zkey" \
        --name="zkID" -v -e="zkid-${PREFIX}-entropy"
    snarkjs zkey export verificationkey "${PREFIX}_final.zkey" "${PREFIX}_vkey.json"
    rm -f "${PREFIX}_0000.zkey"
}

setup_circuit AgeVerification age
setup_circuit NameVerification name
setup_circuit GenderVerification gender

echo "Done."
