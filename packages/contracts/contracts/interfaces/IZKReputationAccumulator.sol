// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZKReputationAccumulator
 * @notice Anonymously accumulates reputation scores for agents whose ZK presentations
 *         have been accepted. Reputation is tracked per nullifier cohort — agents
 *         with the same policy can accumulate reputation without revealing identity.
 *
 *         Reputation can only be incremented via a verified presentation
 *         (GeneralizedPredicateVerifier must call recordVerification before this contract
 *         accepts an increment). This prevents sybil reputation inflation.
 */
interface IZKReputationAccumulator {
    /// @notice Emitted when reputation is incremented for a nullifier cohort.
    event ReputationIncremented(
        bytes32 indexed policyId,
        bytes32 indexed nullifier,
        uint256 delta,
        uint256 newTotal
    );

    /// @notice Emitted when a reputation pool is created for a policy.
    event ReputationPoolCreated(bytes32 indexed policyId, address creator);

    error PoolNotFound(bytes32 policyId);
    error PresentationNotVerified(bytes32 nullifier);
    error DeltaExceedsMax(uint256 delta, uint256 max);
    error ReputationOverflow(uint256 current, uint256 delta);

    /**
     * @notice Create a reputation pool for a policy.
     * @param policyId       The policy this pool is bound to.
     * @param maxDeltaPerOp  Maximum reputation delta per single increment operation.
     */
    function createPool(bytes32 policyId, uint256 maxDeltaPerOp) external;

    /**
     * @notice Increment reputation for an agent identified by nullifier.
     *         The nullifier must correspond to an accepted presentation in
     *         GeneralizedPredicateVerifier (verified on-chain before call).
     * @param policyId  The pool to increment in.
     * @param nullifier The agent's nullifier from their accepted presentation.
     * @param delta     Reputation points to add. Must be <= maxDeltaPerOp.
     */
    function increment(bytes32 policyId, bytes32 nullifier, uint256 delta) external;

    /**
     * @notice Returns the accumulated reputation for a nullifier in a pool.
     */
    function getReputation(bytes32 policyId, bytes32 nullifier)
        external
        view
        returns (uint256 score);

    /**
     * @notice Returns the total reputation accumulated across all agents in a pool.
     */
    function getPoolTotal(bytes32 policyId) external view returns (uint256 total);
}
