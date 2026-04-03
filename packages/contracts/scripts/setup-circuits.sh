#!/usr/bin/env bash
# setup-circuits.sh
# Compiles the OpenACGPPresentation circuit and generates the Groth16 proving/verification keys.
# Run this once before deployment. Requires circom 2.x and snarkjs.
#
# Prerequisites:
#   npm install -g snarkjs
#   curl -fsSL https://install.snarkjs.org | bash  # or build circom from source
#
# Output:
#   ../../circuits/build/OpenACGPPresentation_js/        — witness calculator
#   ../../circuits/build/OpenACGPPresentation.r1cs       — R1CS
#   ../../circuits/build/OpenACGPPresentation.zkey        — proving key (after setup)
#   ../../circuits/build/OpenACGPPresentation_vk.json     — verification key
#   contracts/verifiers/OpenACSnarkVerifier_generated.sol — production Solidity verifier

set -euo pipefail

CIRCUITS_DIR="$(dirname "$0")/../../circuits"
BUILD_DIR="${CIRCUITS_DIR}/build"
CIRCUIT="${CIRCUITS_DIR}/presentation/OpenACGPPresentation.circom"
PTAU="${BUILD_DIR}/powersOfTau28_hez_final_18.ptau"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "==> Compiling circuit..."
circom "${CIRCUIT}" --r1cs --wasm --sym --output "${BUILD_DIR}" \
  --include "${CIRCUITS_DIR}/lib" \
  --include "$(npm root -g)/circomlib/circuits"

echo "==> Constraint count:"
snarkjs r1cs info OpenACGPPresentation.r1cs

# Download Powers of Tau (18 = up to 2^18 constraints, sufficient for this circuit)
if [ ! -f "${PTAU}" ]; then
  echo "==> Downloading Powers of Tau..."
  curl -fSL \
    "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_18.ptau" \
    -o "${PTAU}"
fi

echo "==> Running Groth16 setup (Phase 2)..."
snarkjs groth16 setup OpenACGPPresentation.r1cs "${PTAU}" OpenACGPPresentation_0.zkey

echo "==> Contributing to Phase 2 ceremony (random entropy)..."
echo "acta-poc-dev-ceremony-$(date +%s)" | \
  snarkjs zkey contribute OpenACGPPresentation_0.zkey OpenACGPPresentation_1.zkey \
    --name="ACTA PoC Dev Ceremony" -v

echo "==> Exporting verification key..."
snarkjs zkey export verificationkey OpenACGPPresentation_1.zkey OpenACGPPresentation_vk.json

echo "==> Generating Solidity verifier..."
snarkjs zkey export solidityverifier OpenACGPPresentation_1.zkey \
  "$(dirname "$0")/../contracts/verifiers/OpenACSnarkVerifier_generated.sol"

echo "==> Copying final zkey..."
cp OpenACGPPresentation_1.zkey OpenACGPPresentation.zkey

echo ""
echo "==> Setup complete!"
echo "    Proving key:      ${BUILD_DIR}/OpenACGPPresentation.zkey"
echo "    Verification key: ${BUILD_DIR}/OpenACGPPresentation_vk.json"
echo "    Solidity verifier: contracts/verifiers/OpenACSnarkVerifier_generated.sol"
echo ""
echo "IMPORTANT: Replace OpenACSnarkVerifier.sol with OpenACSnarkVerifier_generated.sol"
echo "           before deploying to a public network."
