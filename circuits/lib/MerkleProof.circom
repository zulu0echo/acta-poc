pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";

/**
 * MerkleProof
 * Verifies a Merkle inclusion proof for a leaf in a Poseidon Merkle tree.
 *
 * Used in OpenACCredentialAnchor: proves that a specific attribute value is
 * in the credential's attribute Merkle tree (whose root is anchored on-chain).
 *
 * Parameters:
 *   levels  — tree depth (e.g. 4 for 16 attributes)
 *
 * Inputs:
 *   leaf          — the attribute value being proved
 *   pathElements  — sibling hashes along the Merkle path
 *   pathIndices   — 0 or 1 for left/right at each level
 *
 * Outputs:
 *   root          — computed Merkle root (must match on-chain root)
 */
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal output root;

    component hashers[levels];
    component muxes[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        muxes[i] = MultiMux1(2);

        muxes[i].c[0][0] <== levelHashes[i];
        muxes[i].c[0][1] <== pathElements[i];
        muxes[i].c[1][0] <== pathElements[i];
        muxes[i].c[1][1] <== levelHashes[i];

        muxes[i].s <== pathIndices[i];

        hashers[i].inputs[0] <== muxes[i].out[0];
        hashers[i].inputs[1] <== muxes[i].out[1];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[levels];
}

/**
 * Convenience wrapper that verifies a leaf's membership and checks against a
 * known root. Emits a constraint root === knownRoot.
 */
template MerkleProofVerify(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input knownRoot;

    component proof = MerkleProof(levels);
    proof.leaf         <== leaf;
    for (var i = 0; i < levels; i++) {
        proof.pathElements[i] <== pathElements[i];
        proof.pathIndices[i]  <== pathIndices[i];
    }

    // Enforce membership
    knownRoot === proof.root;
}
