// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ICircuitVerifier } from "./ICircuitVerifier.sol";

/**
 * @title IGeneralizedPredicateVerifier
 * @notice Central on-chain verifier for ACTA ZK presentations.
 *         Implements the 10-step verification sequence defined in the ACTA spec.
 *         Any protocol wishing to gate access on a verified ZK credential calls
 *         verifyAndRegister() and listens for PresentationAccepted.
 */
interface IGeneralizedPredicateVerifier {
    /// @notice Emitted when a presentation passes all 10 verification steps.
    event PresentationAccepted(
        bytes32 indexed policyId,
        bytes32 indexed nullifier,
        bytes32 contextHash,
        address indexed verifier,
        uint256 blockNumber
    );

    /// @notice Emitted when a new policy is registered.
    event PolicyRegistered(
        bytes32 indexed policyId,
        address indexed verifier,
        bytes32 predicateProgramHash,
        bytes32 circuitId
    );

    /// @notice Emitted when a policy is deactivated.
    event PolicyDeactivated(bytes32 indexed policyId);

    /// @notice Emitted when the Poseidon context hasher is updated.
    event ContextHasherSet(address indexed hasher);

    error PolicyNotFound(bytes32 policyId);
    error PolicyInactive(bytes32 policyId);
    error PolicyExpired(bytes32 policyId, uint256 expiryBlock);
    error InvalidPublicSignalCount(uint256 got, uint256 expected);
    error PredicateHashMismatch(bytes32 got, bytes32 expected);
    error ExpiryBlockPassed(uint256 expiryBlock, uint256 currentBlock);
    error MerkleRootNotCurrent(bytes32 merkleRoot);
    error IssuerCommitmentMismatch(bytes32 got, bytes32 expected);
    error ContextHashMismatch(bytes32 got, bytes32 expected);
    error ProofInvalid();
    error NullifierConflict(bytes32 nullifier);
    error CircuitVerifierNotRegistered(bytes32 circuitId);
    error UnauthorizedPolicyOwner(address caller, bytes32 policyId);

    /**
     * @notice PolicyDescriptor — stored on-chain for each registered policy.
     */
    struct PolicyDescriptor {
        address verifier;            // must be msg.sender when registering
        bytes32 predicateProgramHash;
        bytes32 credentialType;      // keccak256("AgentCapabilityCredential")
        bytes32 circuitId;           // maps to ICircuitVerifier implementation
        uint256 expiryBlock;         // policy expires at this block (0 = never)
        bytes32 issuerCommitment;    // Poseidon hash of trusted issuer's public key
        bool active;
    }

    /**
     * @notice Register a new policy. Returns a deterministic policyId.
     * @param desc  PolicyDescriptor with all fields populated.
     * @return policyId keccak256 of canonical policy encoding.
     */
    function registerPolicy(PolicyDescriptor calldata desc) external returns (bytes32 policyId);

    /**
     * @notice Deactivate a policy. Only callable by the policy owner (verifier address).
     */
    function deactivatePolicy(bytes32 policyId) external;

    /**
     * @notice Verify a ZK presentation and register the nullifier atomically.
     *         Implements the 10-step ACTA verification sequence:
     *
     *         1.  Load policy — revert PolicyNotFound / PolicyInactive / PolicyExpired
     *         2.  Decode public signals from pubSignals array
     *         3.  Verify predicateProgramHash == policy.predicateProgramHash
     *         4.  Verify expiryBlock > block.number
     *         5.  Verify credentialMerkleRoot is current in OpenACCredentialAnchor
     *         6.  Verify issuerPubKeyCommitment == policy.issuerCommitment
     *         7.  Verify contextHash == keccak256(msg.sender || policyId || nonce)
     *         8.  Call ICircuitVerifier.verifyProof(proof, pubSignals)
     *         9.  Register nullifier in NullifierRegistry
     *         10. Emit PresentationAccepted
     *
     * @param policyId    Policy to verify against.
     * @param proof       ABI-encoded proof bytes for the circuit.
     * @param pubSignals  Array of public signals — order: [nullifier, contextHash,
     *                    predicateProgramHash, issuerPubKeyCommitment,
     *                    credentialMerkleRoot, expiryBlock].
     * @param agentId     uint256(uint160(agentEthAddress)) — used to look up Merkle root.
     * @param nonce       Session nonce from the OID4VP request.
     */
    function verifyAndRegister(
        bytes32 policyId,
        bytes calldata proof,
        uint256[] calldata pubSignals,
        uint256 agentId,
        uint256 nonce
    ) external;

    /**
     * @notice Returns the PolicyDescriptor for a given policyId.
     */
    function getPolicy(bytes32 policyId) external view returns (PolicyDescriptor memory desc);

    /**
     * @notice Returns true if a nullifier was accepted in any verified presentation.
     * @dev Policy-agnostic. Use isAcceptedForPolicy for access-gating to prevent
     *      cross-policy nullifier reuse.
     */
    function isAccepted(bytes32 nullifier) external view returns (bool);

    /**
     * @notice Returns true if a nullifier was accepted specifically under the given policyId.
     * @dev Use this in consumer contracts (e.g., AgentAccessGate) to ensure the nullifier
     *      was verified against the policy that matches the gate's requirements.
     *      A nullifier accepted under a weaker policy MUST NOT grant access under a stronger one.
     */
    function isAcceptedForPolicy(bytes32 nullifier, bytes32 policyId) external view returns (bool);

    /**
     * @notice Register an ICircuitVerifier implementation for a circuit.
     * @dev Only callable by owner. Allows new proof systems without contract upgrade.
     */
    function registerCircuitVerifier(bytes32 circuitId, ICircuitVerifier verifier) external;
}
