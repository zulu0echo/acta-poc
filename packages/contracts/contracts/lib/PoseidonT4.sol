// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPoseidonT4
 * @notice Interface for on-chain Poseidon hash with 3 inputs (t = 4).
 *
 * The ACTA OpenACGPPresentation circuit outputs:
 *   contextHash = Poseidon(verifierAddress, policyId, nonce)   [field elements]
 *
 * GeneralizedPredicateVerifier.verifyAndRegister() must recompute this same value
 * on-chain (Step 7) to confirm the proof binds to the correct (caller, policy, nonce).
 * Since keccak256 ≠ Poseidon, a Solidity Poseidon implementation is required.
 *
 * Production deployment: deploy a concrete implementation whose hash(a,b,c) output
 * matches circomlib's Poseidon(3) template over BN254. The authoritative Solidity
 * reference implementation is iden3/poseidon-solidity:
 *   https://github.com/iden3/poseidon-solidity/blob/master/contracts/PoseidonT4.sol
 *
 * Steps:
 *   1. Clone iden3/poseidon-solidity at the commit matching your circomlib version.
 *   2. Copy PoseidonT4.sol into this directory and implement this interface.
 *   3. Deploy and call GeneralizedPredicateVerifier.setContextHasher(poseidonT4Address).
 *   4. Run PoseidonConsistency.test.ts to verify on-chain output matches snarkjs witness.
 */
interface IPoseidonT4 {
    /**
     * @notice Compute Poseidon(a, b, c) over BN254.
     * @param a First input — must be in [0, BN254_SCALAR_FIELD)
     * @param b Second input
     * @param c Third input
     * @return digest Poseidon output in [0, BN254_SCALAR_FIELD)
     */
    function hash(uint256 a, uint256 b, uint256 c) external pure returns (uint256 digest);
}
