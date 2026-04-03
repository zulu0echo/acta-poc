// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockERC8004Identity
 * @notice Minimal stub of an ERC-8004 Agent Identity Registry for testing.
 *         ERC-8004 integration is optional in the ACTA PoC. This mock satisfies
 *         the interface for test deployments without requiring the real ERC-8004 contract.
 */
contract MockERC8004Identity {
    mapping(uint256 => bool) public registered;

    event AgentRegistered(uint256 indexed agentId, address controller);

    function register(uint256 agentId) external {
        registered[agentId] = true;
        emit AgentRegistered(agentId, msg.sender);
    }

    function isRegistered(uint256 agentId) external view returns (bool) {
        return registered[agentId];
    }

    function getController(uint256 agentId) external view returns (address) {
        return address(uint160(agentId));
    }
}
