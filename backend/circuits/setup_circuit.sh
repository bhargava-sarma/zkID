#!/bin/bash
# Compiles the legacy circuits and runs Groth16 setup.
# Requires circom 2.x and snarkjs. New keys invalidate the deployed verifiers.
set -e

cd "$(dirname "$0")"

npm install --silent

if [ ! -f pot12_final.ptau ]; then
    wget -q https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau -O pot12_final.ptau
fi

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
