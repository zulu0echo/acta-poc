pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

/**
 * NullifierDerive
 * Derives a context-scoped nullifier from a credential identifier and context inputs.
 *
 * Nullifier = Poseidon(credentialSecret, Poseidon(verifierAddress, policyId, nonce))
 *
 * This construction ensures:
 *  1. Cross-context unlinkability: the same credential produces different nullifiers
 *     for different (verifier, policy, nonce) contexts.
 *  2. Single-use per context: the nullifier is deterministic for a given
 *     (credential, verifier, policy, nonce) tuple, so double-spending is detectable.
 *  3. Privacy: the credentialSecret is never revealed; only the nullifier is public.
 *
 * Parameters:
 *   none (fixed structure)
 *
 * Inputs:
 *   credentialSecret  — Poseidon(credentialCommitment, randomness), where
 *                       credentialCommitment = Poseidon(attributeValues[], randomness).
 *                       This double-hashing binds the nullifier to the exact commitment
 *                       while keeping the credential attributes private.
 *   verifierAddress   — Ethereum address of the verifier (as field element)
 *   policyId          — bytes32 policyId (as field element)
 *   nonce             — uint64 session nonce from OID4VP request
 *
 * Outputs:
 *   nullifier         — bytes32 nullifier for this presentation context
 */
template NullifierDerive() {
    signal input credentialSecret;
    signal input verifierAddress;
    signal input policyId;
    signal input nonce;

    signal output nullifier;

    component contextHasher = Poseidon(3);
    contextHasher.inputs[0] <== verifierAddress;
    contextHasher.inputs[1] <== policyId;
    contextHasher.inputs[2] <== nonce;

    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== credentialSecret;
    nullifierHasher.inputs[1] <== contextHasher.out;

    nullifier <== nullifierHasher.out;
}
