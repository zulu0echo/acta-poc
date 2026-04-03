// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IOpenACCredentialAnchor
 * @notice Interface for anchoring did:ethr-backed credential commitments on-chain.
 *         Links an Ethereum address (the address-component of a did:ethr DID) to
 *         a ZK credential commitment (Poseidon hash of attribute values + randomness).
 *
 *         The agentId is uint256(uint160(ethAddress)) where ethAddress is the address
 *         extracted from did:ethr:0x14f69:0x<ethAddress>.
 */
interface IOpenACCredentialAnchor {
    /// @notice Emitted when a credential commitment is anchored.
    event CredentialAnchored(
        uint256 indexed agentId,
        bytes32 indexed credentialType,
        bytes32 commitment,
        bytes32 merkleRoot,
        uint256 anchoredAt
    );

    /// @notice Emitted when an agent rotates to a new commitment (credential renewal).
    event CredentialRotated(
        uint256 indexed agentId,
        bytes32 indexed credentialType,
        bytes32 oldCommitment,
        bytes32 newCommitment
    );

    /// @notice Emitted when an agent revokes their anchored credential.
    event CredentialRevoked(
        uint256 indexed agentId,
        bytes32 indexed credentialType,
        bytes32 commitment
    );

    error AgentIdMismatch(uint256 agentId, address sender);
    error NoActiveCredential(uint256 agentId, bytes32 credentialType);
    error CommitmentAlreadyAnchored(bytes32 commitment);
    error ActiveAnchorExists(uint256 agentId, bytes32 credentialType);
    error InvalidCommitment();
    error InvalidMerkleRoot();
    error CredentialRevoked(uint256 agentId, bytes32 credentialType);

    /**
     * @notice Anchor a credential commitment for the calling agent.
     * @param agentId        uint256(uint160(msg.sender)). Enforced: msg.sender == address(uint160(agentId)).
     * @param credentialType keccak256 of the credential type string (e.g. "AgentCapabilityCredential").
     * @param commitment     Poseidon hash of (attributeValues[], randomness).
     * @param merkleRoot     Merkle root of the agent's credential tree (used in ZK proofs).
     * @dev Only the did:ethr controller (== msg.sender) can anchor for their agentId.
     */
    function anchorCredential(
        uint256 agentId,
        bytes32 credentialType,
        bytes32 commitment,
        bytes32 merkleRoot
    ) external;

    /**
     * @notice Rotate to a new commitment (e.g., renewed credential after audit).
     * @dev Caller MUST be the same msg.sender as original anchor.
     */
    function rotateCredential(
        uint256 agentId,
        bytes32 credentialType,
        bytes32 newCommitment,
        bytes32 newMerkleRoot
    ) external;

    /**
     * @notice Revoke the active credential for an agent.
     * @dev Can be called by: (a) the agent itself, or (b) an authorised revoker (e.g., issuer).
     */
    function revokeCredential(uint256 agentId, bytes32 credentialType) external;

    /**
     * @notice Returns the active commitment for an agent.
     * @return commitment bytes32(0) if no active credential.
     */
    function getCommitment(uint256 agentId, bytes32 credentialType)
        external
        view
        returns (bytes32 commitment, bytes32 merkleRoot, uint256 anchoredAt);

    /**
     * @notice Checks whether a given Merkle root is the current active root for an agent.
     *         Called by the ZK verifier to ensure the credential tree is current.
     */
    function isMerkleRootCurrent(
        uint256 agentId,
        bytes32 credentialType,
        bytes32 merkleRoot
    ) external view returns (bool current);
}
