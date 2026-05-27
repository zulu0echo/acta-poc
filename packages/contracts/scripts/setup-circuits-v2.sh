#!/usr/bin/env bash
# setup-circuits-v2.sh
# Compiles the V2 OpenACGPPresentation circuit (zkID generalized predicates)
# and generates the Groth16 proving/verification keys.
#
# v0.4 status: this script encodes the v0.4 ceremony plan. It mirrors
# `setup-circuits.sh` but targets `OpenACGPPresentationV2.circom`.
#
# Prerequisites:
#   - circom 2.1.x (https://docs.circom.io/)
#   - snarkjs >= 0.7 (`npm i -g snarkjs`)
#   - Powers-of-Tau ≥ 2^20 (V2 has higher constraint count than V1)
#
# Output:
#   - circuits/build/OpenACGPPresentationV2_js/  — witness calculator
#   - circuits/build/OpenACGPPresentationV2.r1cs — R1CS
#   - circuits/build/OpenACGPPresentationV2.zkey — proving key
#   - circuits/build/OpenACGPPresentationV2_vk.json — verification key
#   - contracts/verifiers/OpenACGPV2SnarkVerifier_generated.sol — production Solidity verifier
#
# After this script succeeds, swap `OpenACSnarkVerifier.sol` for
# `OpenACGPV2SnarkVerifier_generated.sol` in `deploy.ts` and re-deploy
# `GeneralizedPredicateVerifier` so it references the new verifier.

set -euo pipefail

CIRCUITS_DIR="$(dirname "$0")/../../circuits"
BUILD_DIR="${CIRCUITS_DIR}/build"
CIRCUIT="${CIRCUITS_DIR}/presentation/OpenACGPPresentationV2.circom"
PTAU_POWER=20
PTAU="${BUILD_DIR}/powersOfTau28_hez_final_${PTAU_POWER}.ptau"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "==> Compiling V2 circuit..."
circom "${CIRCUIT}" --r1cs --wasm --sym --output "${BUILD_DIR}" \
  --include "${CIRCUITS_DIR}/lib" \
  --include "$(npm root -g)/circomlib/circuits"

echo "==> Constraint count:"
snarkjs r1cs info OpenACGPPresentationV2.r1cs | tee r1cs-info-v2.txt

# Download Powers of Tau if missing (2^20 supports up to ~1M constraints).
if [ ! -f "${PTAU}" ]; then
  echo "==> Downloading Powers of Tau (2^${PTAU_POWER})..."
  curl -fSL \
    "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_${PTAU_POWER}.ptau" \
    -o "${PTAU}"
fi

echo "==> Running Groth16 Phase 2 setup..."
snarkjs groth16 setup OpenACGPPresentationV2.r1cs "${PTAU}" OpenACGPPresentationV2_0.zkey

# v0.4 dev ceremony: single-contributor random entropy. Production deploys
# MUST replace this with a multi-party ceremony.
echo "==> Contributing to Phase 2 ceremony (dev entropy)..."
echo "acta-v0.4-dev-ceremony-$(date +%s)" | \
  snarkjs zkey contribute OpenACGPPresentationV2_0.zkey OpenACGPPresentationV2_1.zkey \
    --name="ACTA v0.4 Dev Ceremony" -v

echo "==> Exporting verification key..."
snarkjs zkey export verificationkey OpenACGPPresentationV2_1.zkey OpenACGPPresentationV2_vk.json

echo "==> Generating Solidity verifier..."
snarkjs zkey export solidityverifier OpenACGPPresentationV2_1.zkey \
  "$(dirname "$0")/../contracts/verifiers/OpenACGPV2SnarkVerifier_generated.sol"

echo "==> Copying final zkey..."
cp OpenACGPPresentationV2_1.zkey OpenACGPPresentationV2.zkey

cat <<EOF

==> V2 ceremony complete.

    Proving key:       ${BUILD_DIR}/OpenACGPPresentationV2.zkey
    Verification key:  ${BUILD_DIR}/OpenACGPPresentationV2_vk.json
    Solidity verifier: contracts/verifiers/OpenACGPV2SnarkVerifier_generated.sol

Next steps:
  1. Run \`npx hardhat compile\` to build the generated verifier.
  2. Update \`deploy.ts\` to wire \`GeneralizedPredicateVerifier\`
     against \`OpenACGPV2SnarkVerifier_generated\`.
  3. Re-deploy and update the SDK's verifier-address env var.
  4. Run the V2 integration tests (packages/contracts/test/integration/FullFlowV2.test.ts).
EOF
