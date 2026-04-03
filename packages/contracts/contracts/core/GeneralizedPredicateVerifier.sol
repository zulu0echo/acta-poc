// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Ownable2Step }     from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { ReentrancyGuard }  from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { Pausable }         from "@openzeppelin/contracts/utils/Pausable.sol";
import { IGeneralizedPredicateVerifier } from "../interfaces/IGeneralizedPredicateVerifier.sol";
import { ICircuitVerifier }              from "../interfaces/ICircuitVerifier.sol";
import { INullifierRegistry }            from "../interfaces/INullifierRegistry.sol";
import { IOpenACCredentialAnchor }       from "../interfaces/IOpenACCredentialAnchor.sol";
import { IPoseidonT4 }                   from "../lib/PoseidonT4.sol";

/**
 * @title GeneralizedPredicateVerifier
 * @notice ACTA central on-chain verifier. Implements the exact 10-step verification
 *         sequence. Any consumer protocol calls verifyAndRegister() and gates its
 *         actions on the PresentationAccepted event or a subsequent isAccepted() check.
 *
 * @dev Public signal ordering (matches OpenACGPPresentation.circom):
 *      pubSignals[0] = nullifier
 *      pubSignals[1] = contextHash  — Poseidon(verifierAddress, policyId, nonce)
 *      pubSignals[2] = predicateProgramHash
 *      pubSignals[3] = issuerPubKeyCommitment
 *      pubSignals[4] = credentialMerkleRoot
 *      pubSignals[5] = expiryBlock
 *
 * Step 7 — Context Hash Verification:
 *   The circuit computes contextHash = Poseidon(verifierAddress, policyId, nonce).
 *   On-chain, this contract recomputes the same Poseidon hash via the `contextHasher`
 *   and compares it to pubSignals[IDX_CONTEXT_HASH].
 *
 *   IMPORTANT: `contextHasher` must be set to a deployed IPoseidonT4 implementation
 *   before production use. If `contextHasher` is address(0), Step 7 is SKIPPED,
 *   which means front-running protection is disabled. This skip mode exists only
 *   for local Hardhat testing where the Poseidon library is not yet deployed.
 *   See contracts/lib/PoseidonT4.sol for deployment instructions.
 *
 * Emergency controls:
 *   The owner can pause() to halt verifyAndRegister() and registerPolicy() in an
 *   incident. Use unpause() to resume after remediation.
 */
contract GeneralizedPredicateVerifier is IGeneralizedPredicateVerifier, Ownable2Step, ReentrancyGuard, Pausable {
    uint256 private constant IDX_NULLIFIER              = 0;
    uint256 private constant IDX_CONTEXT_HASH           = 1;
    uint256 private constant IDX_PREDICATE_HASH         = 2;
    uint256 private constant IDX_ISSUER_COMMITMENT      = 3;
    uint256 private constant IDX_MERKLE_ROOT            = 4;
    uint256 private constant IDX_EXPIRY_BLOCK           = 5;
    uint256 private constant EXPECTED_PUBLIC_SIGNAL_COUNT = 6;

    INullifierRegistry      public immutable nullifierRegistry;
    IOpenACCredentialAnchor public immutable credentialAnchor;

    /// @notice Optional Poseidon-T4 hasher for Step 7 contextHash verification.
    ///         Must be set via setContextHasher() before production deployment.
    ///         If address(0), Step 7 is skipped (local dev / test mode only).
    IPoseidonT4 public contextHasher;

    mapping(bytes32 => PolicyDescriptor)             private _policies;
    mapping(bytes32 => ICircuitVerifier)             private _circuitVerifiers;
    mapping(bytes32 => bool)                         private _acceptedNullifiers;
    mapping(bytes32 => mapping(bytes32 => bool))     private _policyAcceptances;

    event ContextHasherSet(address indexed hasher);

    constructor(
        address initialOwner,
        address _nullifierRegistry,
        address _credentialAnchor
    ) Ownable2Step() {
        _transferOwnership(initialOwner);
        nullifierRegistry = INullifierRegistry(_nullifierRegistry);
        credentialAnchor  = IOpenACCredentialAnchor(_credentialAnchor);
    }

    // ── Admin ──────────────────────────────────────────────────────────────

    /// @notice Set the Poseidon-T4 hasher used in Step 7. Owner only.
    /// @dev Must be called with the deployed IPoseidonT4 address before production.
    ///      Set to address(0) to disable the check (test mode only).
    function setContextHasher(address hasher) external onlyOwner {
        contextHasher = IPoseidonT4(hasher);
        emit ContextHasherSet(hasher);
    }

    /// @notice Pause all state-changing operations. Owner only. Use in emergencies.
    function pause() external onlyOwner { _pause(); }

    /// @notice Resume operations after an incident is resolved. Owner only.
    function unpause() external onlyOwner { _unpause(); }

    // ── Circuit Registry ───────────────────────────────────────────────────

    /// @inheritdoc IGeneralizedPredicateVerifier
    function registerCircuitVerifier(bytes32 circuitId, ICircuitVerifier verifier)
        external
        onlyOwner
    {
        _circuitVerifiers[circuitId] = verifier;
    }

    function getCircuitVerifier(bytes32 circuitId) external view returns (address) {
        return address(_circuitVerifiers[circuitId]);
    }

    // ── Policy Management ─────────────────────────────────────────────────

    /// @inheritdoc IGeneralizedPredicateVerifier
    function registerPolicy(PolicyDescriptor calldata desc)
        external
        whenNotPaused
        returns (bytes32 policyId)
    {
        if (desc.verifier != address(0) && desc.verifier != msg.sender) {
            // Compute policyId with desc.verifier to show what was rejected
            bytes32 rejectedId = keccak256(abi.encode(
                desc.verifier,
                desc.predicateProgramHash,
                desc.credentialType,
                desc.circuitId,
                desc.expiryBlock,
                desc.issuerCommitment
            ));
            revert UnauthorizedPolicyOwner(msg.sender, rejectedId);
        }

        policyId = keccak256(abi.encode(
            msg.sender,
            desc.predicateProgramHash,
            desc.credentialType,
            desc.circuitId,
            desc.expiryBlock,
            desc.issuerCommitment
        ));

        _policies[policyId] = PolicyDescriptor({
            verifier:              msg.sender,
            predicateProgramHash:  desc.predicateProgramHash,
            credentialType:        desc.credentialType,
            circuitId:             desc.circuitId,
            expiryBlock:           desc.expiryBlock,
            issuerCommitment:      desc.issuerCommitment,
            active:                true
        });

        emit PolicyRegistered(policyId, msg.sender, desc.predicateProgramHash, desc.circuitId);
    }

    /// @inheritdoc IGeneralizedPredicateVerifier
    function deactivatePolicy(bytes32 policyId) external {
        PolicyDescriptor storage policy = _policies[policyId];
        if (policy.verifier == address(0)) revert PolicyNotFound(policyId);
        if (policy.verifier != msg.sender)  revert UnauthorizedPolicyOwner(msg.sender, policyId);
        policy.active = false;
        emit PolicyDeactivated(policyId);
    }

    /// @inheritdoc IGeneralizedPredicateVerifier
    function getPolicy(bytes32 policyId) external view returns (PolicyDescriptor memory desc) {
        if (_policies[policyId].verifier == address(0)) revert PolicyNotFound(policyId);
        return _policies[policyId];
    }

    // ── 10-Step Verification ───────────────────────────────────────────────

    /// @inheritdoc IGeneralizedPredicateVerifier
    function verifyAndRegister(
        bytes32 policyId,
        bytes calldata proof,
        uint256[] calldata pubSignals,
        uint256 agentId,
        uint256 nonce
    ) external nonReentrant whenNotPaused {
        // Step 1: Load policy — revert if not found, inactive, or expired
        PolicyDescriptor storage policy = _policies[policyId];
        if (policy.verifier == address(0))      revert PolicyNotFound(policyId);
        if (!policy.active)                     revert PolicyInactive(policyId);
        if (policy.expiryBlock != 0 && block.number > policy.expiryBlock) {
            revert PolicyExpired(policyId, policy.expiryBlock);
        }

        // Step 2: Decode public signals — validate count
        if (pubSignals.length != EXPECTED_PUBLIC_SIGNAL_COUNT) {
            revert InvalidPublicSignalCount(pubSignals.length, EXPECTED_PUBLIC_SIGNAL_COUNT);
        }

        bytes32 nullifier            = bytes32(pubSignals[IDX_NULLIFIER]);
        bytes32 contextHash          = bytes32(pubSignals[IDX_CONTEXT_HASH]);
        bytes32 predicateProgramHash = bytes32(pubSignals[IDX_PREDICATE_HASH]);
        bytes32 issuerCommitment     = bytes32(pubSignals[IDX_ISSUER_COMMITMENT]);
        bytes32 merkleRoot           = bytes32(pubSignals[IDX_MERKLE_ROOT]);
        uint256 expiryBlock          = pubSignals[IDX_EXPIRY_BLOCK];

        // Step 3: Predicate hash must match the registered policy
        if (predicateProgramHash != policy.predicateProgramHash) {
            revert PredicateHashMismatch(predicateProgramHash, policy.predicateProgramHash);
        }

        // Step 4: Expiry block must be in the future
        if (expiryBlock <= block.number) revert ExpiryBlockPassed(expiryBlock, block.number);

        // Step 5: Credential Merkle root must be current in the anchor contract
        if (!credentialAnchor.isMerkleRootCurrent(agentId, policy.credentialType, merkleRoot)) {
            revert MerkleRootNotCurrent(merkleRoot);
        }

        // Step 6: Issuer public key commitment must match policy
        if (issuerCommitment != policy.issuerCommitment) {
            revert IssuerCommitmentMismatch(issuerCommitment, policy.issuerCommitment);
        }

        // Step 7: Context hash binds this proof to (caller, policyId, nonce).
        // The circuit computes contextHash = Poseidon(verifierAddress, policyId, nonce).
        // We must recompute the same Poseidon hash on-chain and compare.
        //
        // If contextHasher is not set (address(0)), this check is skipped.
        // This is acceptable ONLY for local Hardhat testing. Production deployments
        // MUST have contextHasher set to a verified IPoseidonT4 implementation.
        // Without this check, front-running protection is not enforced on-chain.
        if (address(contextHasher) != address(0)) {
            uint256 expectedCtxHash = contextHasher.hash(
                uint256(uint160(msg.sender)),
                uint256(policyId),
                nonce
            );
            if (bytes32(expectedCtxHash) != contextHash) {
                revert ContextHashMismatch(contextHash, bytes32(expectedCtxHash));
            }
        }

        // Step 8: Verify ZK proof via circuit-specific verifier
        ICircuitVerifier circuitVerifier = _circuitVerifiers[policy.circuitId];
        if (address(circuitVerifier) == address(0)) {
            revert CircuitVerifierNotRegistered(policy.circuitId);
        }
        if (!circuitVerifier.verifyProof(proof, pubSignals)) revert ProofInvalid();

        // Step 9: Register nullifier — reverts if already active (replay protection)
        nullifierRegistry.register(nullifier, contextHash, expiryBlock);
        _acceptedNullifiers[nullifier]          = true;
        _policyAcceptances[policyId][nullifier] = true;

        // Step 10: Emit PresentationAccepted
        emit PresentationAccepted(policyId, nullifier, contextHash, msg.sender, block.number);
    }

    /**
     * @notice Returns true if a nullifier has ever been accepted in any verified presentation.
     * @dev Policy-agnostic. Prefer isAcceptedForPolicy in consumer contracts to prevent
     *      cross-policy access (see AgentAccessGate, ZKReputationAccumulator).
     */
    function isAccepted(bytes32 nullifier) external view returns (bool) {
        return _acceptedNullifiers[nullifier];
    }

    /**
     * @notice Returns true if a nullifier was accepted specifically under the given policyId.
     * @dev Use this in all consumer contracts. A nullifier accepted under a weaker policy
     *      MUST NOT grant access under a stricter policy gate.
     */
    function isAcceptedForPolicy(bytes32 nullifier, bytes32 policyId) external view returns (bool) {
        return _policyAcceptances[policyId][nullifier];
    }
}
