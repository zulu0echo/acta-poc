// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { INullifierRegistry } from "../interfaces/INullifierRegistry.sol";

/**
 * @title NullifierRegistry
 * @notice Context-scoped nullifier registry for ACTA presentations.
 *
 * @dev Nullifiers are scoped to a contextHash = keccak256(verifierAddress || policyId || nonce),
 *      so the same underlying credential may be used in different policies without
 *      cross-protocol linkability.
 *
 *      The lockAuthorization() pattern prevents governance from silently revoking
 *      a verifier's ability to register nullifiers after credentials are issued.
 *
 * Security properties:
 * - Replay prevention: once a nullifier is active, a second register() reverts.
 * - Expiry: nullifiers have a block-number expiry after which isActive() returns false.
 * - Context isolation: two presentations with the same credential but different
 *   (verifier, policy, nonce) tuples produce distinct nullifiers — the circuit
 *   enforces this. On-chain we only store the nullifier; we do not reconstruct context.
 * - Revocation: authorized revokers can cancel a nullifier (e.g., after issuer revocation).
 */
contract NullifierRegistry is INullifierRegistry, Ownable2Step {
    struct NullifierRecord {
        bytes32 contextHash;
        uint256 expiryBlock;
        address registeredBy;
        uint256 registeredAt;
        bool revoked;
    }

    mapping(bytes32 => NullifierRecord) private _records;
    mapping(address => bool) private _authorizedCallers;

    constructor(address initialOwner) Ownable2Step() {
        _transferOwnership(initialOwner);
    }

    // ── Authorisation ──────────────────────────────────────────────────────

    modifier onlyAuthorized() {
        if (!_authorizedCallers[msg.sender]) {
            revert UnauthorizedCaller(msg.sender);
        }
        _;
    }

    /// @inheritdoc INullifierRegistry
    function lockAuthorization(address caller) external onlyOwner {
        _authorizedCallers[caller] = true;
        emit AuthorizationLocked(caller);
    }

    function isAuthorized(address caller) external view returns (bool) {
        return _authorizedCallers[caller];
    }

    // ── Core Logic ─────────────────────────────────────────────────────────

    /// @inheritdoc INullifierRegistry
    function register(
        bytes32 nullifier,
        bytes32 contextHash,
        uint256 expiryBlock
    ) external onlyAuthorized {
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (expiryBlock <= block.number) revert InvalidExpiryBlock(expiryBlock);

        NullifierRecord storage rec = _records[nullifier];

        // A nullifier MUST NOT be re-registered once it has been seen, regardless of
        // whether it has expired or been revoked. The security argument is:
        //
        //   A nullifier is deterministic for (credential, verifier, policy, nonce).
        //   A legitimate re-presentation always uses a fresh nonce → different nullifier.
        //   Therefore a second registration of the same nullifier is never legitimate.
        //
        // Previously, revoked or expired nullifiers could be re-registered with a
        // different contextHash and expiryBlock. This would let an attacker who can
        // trigger a revocation change the on-chain record for a nullifier, potentially
        // confusing consumers that store and compare contextHashes directly.
        if (rec.registeredAt != 0) {
            revert NullifierAlreadyActive(nullifier);
        }

        _records[nullifier] = NullifierRecord({
            contextHash:   contextHash,
            expiryBlock:   expiryBlock,
            registeredBy:  msg.sender,
            registeredAt:  block.number,
            revoked:       false
        });

        emit NullifierRegistered(nullifier, contextHash, expiryBlock);
    }

    /// @inheritdoc INullifierRegistry
    function isActive(bytes32 nullifier) external view returns (bool active) {
        NullifierRecord storage rec = _records[nullifier];
        return rec.registeredAt != 0
            && !rec.revoked
            && block.number <= rec.expiryBlock;
    }

    /// @inheritdoc INullifierRegistry
    function getRecord(bytes32 nullifier)
        external
        view
        returns (
            bytes32 contextHash,
            uint256 expiryBlock,
            address registeredBy,
            uint256 registeredAt,
            bool revoked
        )
    {
        NullifierRecord storage rec = _records[nullifier];
        return (rec.contextHash, rec.expiryBlock, rec.registeredBy, rec.registeredAt, rec.revoked);
    }

    /// @inheritdoc INullifierRegistry
    function revoke(bytes32 nullifier) external {
        NullifierRecord storage rec = _records[nullifier];
        if (rec.registeredAt == 0) revert NullifierNotFound(nullifier);
        if (msg.sender != rec.registeredBy && msg.sender != owner()) {
            revert UnauthorizedCaller(msg.sender);
        }
        rec.revoked = true;
        emit NullifierRevoked(nullifier, msg.sender);
    }
}
