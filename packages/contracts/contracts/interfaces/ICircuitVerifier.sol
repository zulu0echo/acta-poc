// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ICircuitVerifier
 * @notice Abstract interface for any SNARK verifier (Groth16, PLONK, etc.).
 *         The ACTA core contracts are proof-system agnostic — they only depend
 *         on this interface. Swap implementations without touching protocol logic.
 * @dev Implementors MUST NOT store state. Verification is a pure function of
 *      proof bytes and public signals.
 */
interface ICircuitVerifier {
    /**
     * @notice Verifies a ZK proof against a set of public signals.
     * @param proof      ABI-encoded proof bytes (format is verifier-specific).
     * @param pubSignals Array of field elements constituting the public input/output.
     *                   Ordering MUST match the circuit's public signal ordering.
     * @return valid     True iff the proof is valid for the given public signals.
     */
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external view returns (bool valid);

    /**
     * @notice Returns the circuit identifier this verifier is bound to.
     *         Used by GeneralizedPredicateVerifier to look up the correct verifier
     *         for a given policy's circuit.
     */
    function circuitId() external pure returns (bytes32);

    /**
     * @notice Returns the expected number of public signals for this circuit.
     *         GeneralizedPredicateVerifier validates pubSignals.length against this.
     */
    function publicSignalCount() external pure returns (uint256);
}
