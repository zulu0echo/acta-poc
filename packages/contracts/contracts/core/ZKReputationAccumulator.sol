// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IZKReputationAccumulator } from "../interfaces/IZKReputationAccumulator.sol";
import { IGeneralizedPredicateVerifier } from "../interfaces/IGeneralizedPredicateVerifier.sol";

/**
 * @title ZKReputationAccumulator
 * @notice Anonymously accumulates reputation for agents that have passed ZK verification.
 *
 * @dev Reputation is keyed by (policyId, nullifier) — anonymous by design.
 *      The contract cross-checks GeneralizedPredicateVerifier.isAcceptedForPolicy() to ensure
 *      reputation can only be earned by agents with a valid ZK presentation for this specific
 *      policy. This prevents both sybil inflation via direct calls and cross-policy inflation
 *      where a weak-policy nullifier earns reputation in a high-bar pool.
 *
 *      Pools must be created before increments can occur. Pool creation is permissioned
 *      to prevent protocol spam. Any address authorised by the owner can create pools
 *      (typically, this is the verifier contract address from a registered policy).
 */
contract ZKReputationAccumulator is IZKReputationAccumulator, Ownable2Step {
    error UnauthorizedPoolCreator(address caller);

    struct Pool {
        bool exists;
        uint256 maxDeltaPerOp;
        uint256 totalReputation;
        address creator;
    }

    IGeneralizedPredicateVerifier public immutable gpVerifier;

    mapping(bytes32 => Pool)                        private _pools;
    mapping(bytes32 => mapping(bytes32 => uint256)) private _reputation;
    mapping(address => bool)                        private _poolCreators;

    constructor(address initialOwner, address _gpVerifier) Ownable2Step() {
        _transferOwnership(initialOwner);
        gpVerifier = IGeneralizedPredicateVerifier(_gpVerifier);
    }

    // ── Administration ─────────────────────────────────────────────────────

    function authorizePoolCreator(address creator) external onlyOwner {
        _poolCreators[creator] = true;
    }

    // ── Pool Management ────────────────────────────────────────────────────

    /// @inheritdoc IZKReputationAccumulator
    function createPool(bytes32 policyId, uint256 maxDeltaPerOp) external {
        if (!_poolCreators[msg.sender] && msg.sender != owner()) {
            revert UnauthorizedPoolCreator(msg.sender);
        }
        _pools[policyId] = Pool({
            exists: true,
            maxDeltaPerOp: maxDeltaPerOp,
            totalReputation: 0,
            creator: msg.sender
        });
        emit ReputationPoolCreated(policyId, msg.sender);
    }

    // ── Reputation Increment ───────────────────────────────────────────────

    /// @inheritdoc IZKReputationAccumulator
    function increment(bytes32 policyId, bytes32 nullifier, uint256 delta) external {
        Pool storage pool = _pools[policyId];
        if (!pool.exists) revert PoolNotFound(policyId);
        // Use policy-scoped check: a nullifier accepted under a different policy MUST NOT
        // earn reputation in this pool. Policy-agnostic isAccepted() would allow cross-policy
        // inflation where a low-bar policy nullifier earns reputation in a high-bar pool.
        if (!gpVerifier.isAcceptedForPolicy(nullifier, policyId)) revert PresentationNotVerified(nullifier);
        if (delta > pool.maxDeltaPerOp) revert DeltaExceedsMax(delta, pool.maxDeltaPerOp);

        uint256 current = _reputation[policyId][nullifier];
        unchecked {
            uint256 newScore = current + delta;
            if (newScore < current) revert ReputationOverflow(current, delta);
            _reputation[policyId][nullifier] = newScore;
        }
        // pool.totalReputation uses checked arithmetic to prevent silent overflow
        pool.totalReputation += delta;

        emit ReputationIncremented(policyId, nullifier, delta, _reputation[policyId][nullifier]);
    }

    /// @inheritdoc IZKReputationAccumulator
    function getReputation(bytes32 policyId, bytes32 nullifier)
        external
        view
        returns (uint256 score)
    {
        return _reputation[policyId][nullifier];
    }

    /// @inheritdoc IZKReputationAccumulator
    function getPoolTotal(bytes32 policyId) external view returns (uint256 total) {
        Pool storage pool = _pools[policyId];
        if (!pool.exists) revert PoolNotFound(policyId);
        return pool.totalReputation;
    }
}
