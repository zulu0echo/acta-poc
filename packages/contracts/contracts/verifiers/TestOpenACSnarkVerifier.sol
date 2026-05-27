// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ICircuitVerifier } from "../interfaces/ICircuitVerifier.sol";

/**
 * @title TestOpenACSnarkVerifier
 * @notice Local-dev / Hardhat ONLY. Accepts the OPENAC_TEST_PROOF_V1 sentinel.
 *         Never deploy to a public network — use ceremony-generated OpenACSnarkVerifier.
 */
contract TestOpenACSnarkVerifier is ICircuitVerifier {
    bytes32 private constant CIRCUIT_ID_HASH =
        keccak256("OpenACGPPresentation.v1");

    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 private constant EXPECTED_PUBLIC_SIGNAL_COUNT = 7;

    bytes32 private constant SENTINEL =
        keccak256(abi.encodePacked("OPENAC_TEST_PROOF_V1"));

    function circuitId() external pure override returns (bytes32) {
        return CIRCUIT_ID_HASH;
    }

    function publicSignalCount() external pure override returns (uint256) {
        return EXPECTED_PUBLIC_SIGNAL_COUNT;
    }

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external pure override returns (bool valid) {
        if (proof.length != 256) return false;
        if (pubSignals.length != EXPECTED_PUBLIC_SIGNAL_COUNT) return false;
        for (uint256 i = 0; i < pubSignals.length; i++) {
            if (pubSignals[i] >= SNARK_SCALAR_FIELD) return false;
        }
        return keccak256(proof) == SENTINEL;
    }
}
