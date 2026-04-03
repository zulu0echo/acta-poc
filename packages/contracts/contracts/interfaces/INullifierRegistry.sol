// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title INullifierRegistry
 * @notice Interface for context-scoped nullifier registration.
 *         Nullifiers prevent double-spend / replay attacks on ZK presentations.
 *         A nullifier is scoped to a (policyId, verifierAddress) context so the
 *         same underlying credential can be used in different protocols without
 *         cross-protocol linkability.
 */
interface INullifierRegistry {
    /// @notice Emitted when a nullifier is successfully registered.
    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed contextHash,
        uint256 indexed expiryBlock
    );

    /// @notice Emitted when a nullifier is explicitly revoked (e.g., credential revocation).
    event NullifierRevoked(bytes32 indexed nullifier, address indexed revoker);

    /// @notice Emitted when lockAuthorization is granted to a new caller.
    event AuthorizationLocked(address indexed authorizedCaller);

    error NullifierAlreadyActive(bytes32 nullifier);
    error NullifierExpired(bytes32 nullifier, uint256 expiryBlock);
    error NullifierNotFound(bytes32 nullifier);
    error UnauthorizedCaller(address caller);
    error InvalidNullifier();
    error InvalidExpiryBlock(uint256 expiryBlock);

    /**
     * @notice Register a nullifier for a given context.
     * @param nullifier    bytes32 nullifier derived from the ZK circuit.
     * @param contextHash  keccak256(verifierAddress || policyId || nonce).
     * @param expiryBlock  Block number after which this nullifier is no longer valid.
     *                     MUST be greater than block.number.
     * @dev Caller MUST be an authorised verifier contract.
     *      Reverts with NullifierAlreadyActive if nullifier is live.
     */
    function register(
        bytes32 nullifier,
        bytes32 contextHash,
        uint256 expiryBlock
    ) external;

    /**
     * @notice Check whether a nullifier is currently active (registered and not expired).
     * @return active True if the nullifier exists, is not expired, and has not been revoked.
     */
    function isActive(bytes32 nullifier) external view returns (bool active);

    /**
     * @notice Returns the full NullifierRecord for inspection.
     * @dev Returns zeroed struct if nullifier was never registered.
     */
    function getRecord(bytes32 nullifier)
        external
        view
        returns (
            bytes32 contextHash,
            uint256 expiryBlock,
            address registeredBy,
            uint256 registeredAt,
            bool revoked
        );

    /**
     * @notice Authorise an address to call register(). Can only add, never remove.
     *         Callable only by the contract owner.
     * @dev The lock pattern prevents governance from silently removing a verifier's
     *      ability to register nullifiers after credentials are issued.
     */
    function lockAuthorization(address caller) external;

    /**
     * @notice Revoke a nullifier before its expiry (e.g., if the credential was revoked).
     * @dev Callable only by the original registering contract or the owner.
     */
    function revoke(bytes32 nullifier) external;
}
