// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ICircuitVerifier } from "../interfaces/ICircuitVerifier.sol";

/**
 * @title OpenACSnarkVerifier
 * @notice Production Groth16 verifier slot for OpenACGPPresentation.
 *
 * @dev Replace this file (or deploy OpenACSnarkVerifier_generated.sol from
 *      `packages/contracts/scripts/setup-circuits.sh`) after a multi-party ceremony.
 *      This placeholder intentionally rejects all proofs so a sentinel test verifier
 *      cannot be deployed to mainnet by mistake.
 */
contract OpenACSnarkVerifier is ICircuitVerifier {
    bytes32 private constant CIRCUIT_ID_HASH =
        keccak256("OpenACGPPresentation.v1");

    uint256 private constant EXPECTED_PUBLIC_SIGNAL_COUNT = 7;

    error VerifierNotConfigured();

    function circuitId() external pure override returns (bytes32) {
        return CIRCUIT_ID_HASH;
    }

    function publicSignalCount() external pure override returns (uint256) {
        return EXPECTED_PUBLIC_SIGNAL_COUNT;
    }

    function verifyProof(
        bytes calldata /* proof */,
        uint256[] calldata /* pubSignals */
    ) external pure override returns (bool valid) {
        revert VerifierNotConfigured();
    }
}
