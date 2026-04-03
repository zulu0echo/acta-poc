// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockERC8004Reputation
 * @notice Minimal stub of an ERC-8004 Agent Reputation Registry for testing.
 */
contract MockERC8004Reputation {
    mapping(uint256 => uint256) public scores;

    function setScore(uint256 agentId, uint256 score) external {
        scores[agentId] = score;
    }

    function getScore(uint256 agentId) external view returns (uint256) {
        return scores[agentId];
    }
}
