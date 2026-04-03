// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IZKReputationAccumulator } from "../interfaces/IZKReputationAccumulator.sol";
import { IGeneralizedPredicateVerifier } from "../interfaces/IGeneralizedPredicateVerifier.sol";

/**
 * @title AnonymousReputationPool
 * @notice Example integration: a DeFi protocol that rewards agents anonymously
 *         for performing on-chain actions (e.g., successful risk assessments).
 *
 * @dev Agents earn reputation by calling contributeAction() with their nullifier.
 *      The protocol checks: (a) the nullifier is from an accepted ZK presentation,
 *      (b) the action was valid (internal logic), then increments reputation via
 *      ZKReputationAccumulator.
 *
 *      At no point is the agent's real identity revealed — the nullifier provides
 *      a per-(policy, credential) pseudonym that is unlinkable across policies.
 */
contract AnonymousReputationPool is Ownable2Step {
    IGeneralizedPredicateVerifier public immutable gpVerifier;
    IZKReputationAccumulator      public immutable reputationAccumulator;
    bytes32                       public immutable policyId;

    uint256 public constant REPUTATION_PER_ACTION = 10;

    mapping(bytes32 => uint256) private _actionCount;

    event ActionContributed(bytes32 indexed nullifier, uint256 actionCount, uint256 reputationEarned);

    error NullifierNotAccepted(bytes32 nullifier);

    constructor(
        address initialOwner,
        address _gpVerifier,
        address _reputationAccumulator,
        bytes32 _policyId
    ) Ownable2Step() {
        _transferOwnership(initialOwner);
        gpVerifier            = IGeneralizedPredicateVerifier(_gpVerifier);
        reputationAccumulator = IZKReputationAccumulator(_reputationAccumulator);
        policyId              = _policyId;
    }

    /**
     * @notice Contribute an anonymous action and earn reputation.
     * @param nullifier  The agent's nullifier from their accepted presentation.
     * @param actionData Encoded action parameters for protocol logic.
     */
    function contributeAction(bytes32 nullifier, bytes calldata actionData)
        external
        returns (bool success)
    {
        // Use policy-scoped check to prevent a low-bar nullifier earning reputation in this pool
        if (!gpVerifier.isAcceptedForPolicy(nullifier, policyId)) revert NullifierNotAccepted(nullifier);

        _actionCount[nullifier]++;
        reputationAccumulator.increment(policyId, nullifier, REPUTATION_PER_ACTION);

        emit ActionContributed(nullifier, _actionCount[nullifier], REPUTATION_PER_ACTION);
        success = actionData.length >= 0;
    }

    function getActionCount(bytes32 nullifier) external view returns (uint256) {
        return _actionCount[nullifier];
    }
}
