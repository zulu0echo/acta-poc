// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IGeneralizedPredicateVerifier } from "../interfaces/IGeneralizedPredicateVerifier.sol";

/**
 * @title AgentAccessGate
 * @notice Example consumer contract that gates protocol access behind a valid
 *         ACTA ZK presentation.
 *
 * @dev Usage pattern:
 *      1. Deploy with the address of GeneralizedPredicateVerifier and the policyId
 *         that represents your compliance requirement.
 *      2. Agents call requestAccess() with their proof (or the verifier calls grantAccess()
 *         after off-chain verification + on-chain submission).
 *      3. Access is keyed by nullifier — one-time and anonymous.
 *      4. Consumer logic calls requireAccess(nullifier) or the onlyVerifiedAgent modifier.
 *
 * Replay attack prevention: the same nullifier cannot grant access twice.
 * The NullifierRegistry in GeneralizedPredicateVerifier enforces this at the proof level.
 * AgentAccessGate additionally tracks granted nullifiers independently.
 */
contract AgentAccessGate is Ownable2Step {
    IGeneralizedPredicateVerifier public immutable gpVerifier;
    bytes32 public immutable policyId;

    mapping(bytes32 => bool)    private _accessGranted;
    mapping(bytes32 => uint256) private _grantedAtBlock;
    /// @dev Permanently revoked nullifiers cannot be re-granted, even if the GPVerifier
    ///      still shows them as accepted. This prevents the revocation bypass where a
    ///      caller re-invokes grantAccess() after the owner calls revokeAccess().
    mapping(bytes32 => bool)    private _permanentlyRevoked;
    uint256 public totalAccessesGranted;

    event AccessGranted(bytes32 indexed nullifier, uint256 blockNumber);
    event AccessRevoked(bytes32 indexed nullifier, address revoker);

    error AccessNotGranted(bytes32 nullifier);
    error AccessAlreadyGranted(bytes32 nullifier);
    error AccessPermanentlyRevoked(bytes32 nullifier);
    error PresentationNotAccepted(bytes32 nullifier);

    constructor(
        address initialOwner,
        address _gpVerifier,
        bytes32 _policyId
    ) Ownable2Step() {
        _transferOwnership(initialOwner);
        gpVerifier = IGeneralizedPredicateVerifier(_gpVerifier);
        policyId   = _policyId;
    }

    // ── Modifiers ──────────────────────────────────────────────────────────

    /**
     * @notice Modifier for downstream protocol functions that require a verified agent.
     * @param nullifier The nullifier from the agent's accepted presentation.
     */
    modifier onlyVerifiedAgent(bytes32 nullifier) {
        if (!_accessGranted[nullifier]) revert AccessNotGranted(nullifier);
        _;
    }

    // ── Core Logic ─────────────────────────────────────────────────────────

    /**
     * @notice Grant access for an agent whose presentation has been accepted under this gate's policyId.
     * @param nullifier The nullifier from the PresentationAccepted event.
     * @dev Anyone can call this function — it only succeeds if GeneralizedPredicateVerifier
     *      has recorded the nullifier as accepted for this specific policyId. Policy-scoped
     *      to prevent a nullifier from a weaker policy granting access on a stricter gate.
     */
    function grantAccess(bytes32 nullifier) external {
        if (_permanentlyRevoked[nullifier]) revert AccessPermanentlyRevoked(nullifier);
        if (_accessGranted[nullifier]) revert AccessAlreadyGranted(nullifier);
        if (!gpVerifier.isAcceptedForPolicy(nullifier, policyId)) revert PresentationNotAccepted(nullifier);

        _accessGranted[nullifier]  = true;
        _grantedAtBlock[nullifier] = block.number;
        totalAccessesGranted++;

        emit AccessGranted(nullifier, block.number);
    }

    /**
     * @notice Permanently revoke access for a nullifier (e.g., after credential revocation).
     * @dev Callable only by the contract owner. Once revoked, the nullifier cannot be
     *      re-granted — even if gpVerifier still shows it as accepted. This is the correct
     *      behaviour: credential revocation is a permanent policy decision.
     */
    function revokeAccess(bytes32 nullifier) external onlyOwner {
        if (!_accessGranted[nullifier]) revert AccessNotGranted(nullifier);
        _accessGranted[nullifier]    = false;
        _permanentlyRevoked[nullifier] = true;
        if (totalAccessesGranted > 0) totalAccessesGranted--;
        emit AccessRevoked(nullifier, msg.sender);
    }

    /**
     * @notice Check whether a nullifier has been granted access.
     */
    function isAccessGranted(bytes32 nullifier) external view returns (bool) {
        return _accessGranted[nullifier];
    }

    /**
     * @notice Returns the block at which access was granted.
     */
    function grantedAtBlock(bytes32 nullifier) external view returns (uint256) {
        return _grantedAtBlock[nullifier];
    }

    /**
     * @notice Example gated function — represents any protocol action.
     * @dev In a real DeFi protocol, this would be replaced with actual business logic.
     */
    function executeProtocolAction(bytes32 nullifier, bytes calldata actionData)
        external
        onlyVerifiedAgent(nullifier)
        returns (bool success)
    {
        // Protocol action logic goes here.
        // actionData is available for downstream processing.
        (success) = actionData.length > 0;
    }
}
