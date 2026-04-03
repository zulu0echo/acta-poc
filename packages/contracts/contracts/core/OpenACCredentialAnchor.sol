// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IOpenACCredentialAnchor } from "../interfaces/IOpenACCredentialAnchor.sol";

/**
 * @title OpenACCredentialAnchor
 * @notice Links did:ethr identities to ZK credential commitments on-chain.
 *
 * @dev The agentId equals uint256(uint160(ethAddress)) where ethAddress is the
 *      address component of did:ethr:0x14f69:0x<ethAddress>. The contract enforces
 *      msg.sender == address(uint160(agentId)), so only the DID controller can
 *      anchor credentials for their DID. This is the on-chain enforcement of the
 *      did:ethr self-sovereign property — no separate identity registry needed.
 *
 * A credential commitment is Poseidon(attributeValues[], randomness).
 * The Merkle root covers the agent's full attribute tree and is used in
 * ZK proofs to prove attribute membership without revealing attribute values.
 *
 * Authorised revokers (e.g., the issuer's Ethereum address) may revoke credentials
 * if an agent's certification lapses or is withdrawn.
 */
contract OpenACCredentialAnchor is IOpenACCredentialAnchor, Ownable2Step {
    struct AnchorRecord {
        bytes32 commitment;
        bytes32 merkleRoot;
        uint256 anchoredAt;
        bool revoked;
        address revokedBy;
    }

    // agentId => credentialType => AnchorRecord
    mapping(uint256 => mapping(bytes32 => AnchorRecord)) private _anchors;

    // Addresses authorised to revoke credentials (e.g., issuer contracts)
    mapping(address => bool) private _authorizedRevokers;

    // Track all commitments to prevent duplicate anchoring
    mapping(bytes32 => bool) private _usedCommitments;

    constructor(address initialOwner) Ownable2Step() {
        _transferOwnership(initialOwner);
    }

    // ── Administration ─────────────────────────────────────────────────────

    function authorizeRevoker(address revoker) external onlyOwner {
        _authorizedRevokers[revoker] = true;
    }

    // ── Core Logic ─────────────────────────────────────────────────────────

    /// @inheritdoc IOpenACCredentialAnchor
    function anchorCredential(
        uint256 agentId,
        bytes32 credentialType,
        bytes32 commitment,
        bytes32 merkleRoot
    ) external {
        if (msg.sender != address(uint160(agentId))) revert AgentIdMismatch(agentId, msg.sender);
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (_usedCommitments[commitment]) revert CommitmentAlreadyAnchored(commitment);

        AnchorRecord storage existing = _anchors[agentId][credentialType];
        if (existing.anchoredAt != 0 && !existing.revoked) {
            // The _usedCommitments check above already handles the idempotent same-commitment
            // case (it would revert with CommitmentAlreadyAnchored). If we reach here with a
            // live anchor and a different commitment, force the caller to use rotateCredential()
            // to ensure the CredentialRotated event is emitted for audit trail integrity.
            revert ActiveAnchorExists(agentId, credentialType);
        }

        _anchors[agentId][credentialType] = AnchorRecord({
            commitment: commitment,
            merkleRoot: merkleRoot,
            anchoredAt: block.number,
            revoked: false,
            revokedBy: address(0)
        });
        _usedCommitments[commitment] = true;

        emit CredentialAnchored(agentId, credentialType, commitment, merkleRoot, block.number);
    }

    /// @inheritdoc IOpenACCredentialAnchor
    function rotateCredential(
        uint256 agentId,
        bytes32 credentialType,
        bytes32 newCommitment,
        bytes32 newMerkleRoot
    ) external {
        if (msg.sender != address(uint160(agentId))) revert AgentIdMismatch(agentId, msg.sender);
        if (newCommitment == bytes32(0)) revert InvalidCommitment();
        if (newMerkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (_usedCommitments[newCommitment]) revert CommitmentAlreadyAnchored(newCommitment);

        AnchorRecord storage rec = _anchors[agentId][credentialType];
        if (rec.anchoredAt == 0) revert NoActiveCredential(agentId, credentialType);
        if (rec.revoked) revert CredentialRevoked(agentId, credentialType);

        bytes32 oldCommitment = rec.commitment;
        rec.commitment = newCommitment;
        rec.merkleRoot = newMerkleRoot;
        rec.anchoredAt = block.number;

        _usedCommitments[newCommitment] = true;

        emit CredentialRotated(agentId, credentialType, oldCommitment, newCommitment);
    }

    /// @inheritdoc IOpenACCredentialAnchor
    function revokeCredential(uint256 agentId, bytes32 credentialType) external {
        bool isSelf = msg.sender == address(uint160(agentId));
        bool isRevoker = _authorizedRevokers[msg.sender];
        bool isOwner_ = msg.sender == owner();
        if (!isSelf && !isRevoker && !isOwner_) revert AgentIdMismatch(agentId, msg.sender);

        AnchorRecord storage rec = _anchors[agentId][credentialType];
        if (rec.anchoredAt == 0) revert NoActiveCredential(agentId, credentialType);
        if (rec.revoked) revert CredentialRevoked(agentId, credentialType);

        bytes32 commitment = rec.commitment;
        rec.revoked = true;
        rec.revokedBy = msg.sender;

        emit CredentialRevoked(agentId, credentialType, commitment);
    }

    /// @inheritdoc IOpenACCredentialAnchor
    function getCommitment(uint256 agentId, bytes32 credentialType)
        external
        view
        returns (bytes32 commitment, bytes32 merkleRoot, uint256 anchoredAt)
    {
        AnchorRecord storage rec = _anchors[agentId][credentialType];
        return (rec.commitment, rec.merkleRoot, rec.anchoredAt);
    }

    /// @inheritdoc IOpenACCredentialAnchor
    function isMerkleRootCurrent(
        uint256 agentId,
        bytes32 credentialType,
        bytes32 merkleRoot
    ) external view returns (bool current) {
        AnchorRecord storage rec = _anchors[agentId][credentialType];
        return rec.anchoredAt != 0 && !rec.revoked && rec.merkleRoot == merkleRoot;
    }
}
