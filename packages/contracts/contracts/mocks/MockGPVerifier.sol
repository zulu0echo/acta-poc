// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockGPVerifier
 * @notice Test mock that reports one specific nullifier as accepted.
 *         Used by AgentAccessGate.test.ts to test the gate in isolation.
 */
contract MockGPVerifier {
    bytes32 private immutable _acceptedNullifier;
    bytes32 private immutable _acceptedPolicyId;

    constructor(bytes32 acceptedNullifier) {
        _acceptedNullifier = acceptedNullifier;
        _acceptedPolicyId  = bytes32(0); // matches any policy in test scenarios
    }

    function isAccepted(bytes32 nullifier) external view returns (bool) {
        return nullifier == _acceptedNullifier;
    }

    function isAcceptedForPolicy(bytes32 nullifier, bytes32 /*policyId*/) external view returns (bool) {
        // Mock accepts the nullifier regardless of policyId — tests supply the correct policyId
        return nullifier == _acceptedNullifier;
    }
}
