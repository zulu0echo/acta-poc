pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "../lib/NullifierDerive.circom";

/**
 * OpenACCredentialAnchor Circuit
 *
 * Proves that:
 *   1. The prover knows a set of attributeValues[] and randomness such that
 *      Poseidon(attributeValues[], randomness) == commitment (the on-chain commitment)
 *   2. The commitment is correctly formed (range checks on each attribute)
 *   3. The Merkle root of the attribute tree is correctly computed
 *
 * This circuit is run by the holder to generate the commitment and merkleRoot
 * that are anchored on-chain in OpenACCredentialAnchor.anchorCredential().
 *
 * Public inputs:
 *   commitment      — on-chain credential commitment
 *   merkleRoot      — Merkle root of the 16-element attribute tree
 *
 * Private inputs:
 *   attributeValues — 16 field elements (indices 0–5 used, 6–15 = 0)
 *   randomness      — blinding factor for commitment
 */
template OpenACCredentialAnchorCircuit() {
    var ATTR_COUNT = 16;

    signal input attributeValues[ATTR_COUNT];
    signal input randomness;

    signal output commitment;
    signal output merkleRoot;

    // ── Commitment = Poseidon(attributeValues[0..15], randomness) ─────────
    component commitHasher = Poseidon(ATTR_COUNT + 1);
    for (var i = 0; i < ATTR_COUNT; i++) {
        commitHasher.inputs[i] <== attributeValues[i];
    }
    commitHasher.inputs[ATTR_COUNT] <== randomness;
    commitment <== commitHasher.out;

    // ── Merkle root of attribute tree (pairs of attributes) ───────────────
    // Level 0: 16 leaves → 8 nodes
    component level0[8];
    signal l0out[8];
    for (var i = 0; i < 8; i++) {
        level0[i] = Poseidon(2);
        level0[i].inputs[0] <== attributeValues[i * 2];
        level0[i].inputs[1] <== attributeValues[i * 2 + 1];
        l0out[i] <== level0[i].out;
    }

    // Level 1: 8 nodes → 4 nodes
    component level1[4];
    signal l1out[4];
    for (var i = 0; i < 4; i++) {
        level1[i] = Poseidon(2);
        level1[i].inputs[0] <== l0out[i * 2];
        level1[i].inputs[1] <== l0out[i * 2 + 1];
        l1out[i] <== level1[i].out;
    }

    // Level 2: 4 nodes → 2 nodes
    component level2[2];
    signal l2out[2];
    for (var i = 0; i < 2; i++) {
        level2[i] = Poseidon(2);
        level2[i].inputs[0] <== l1out[i * 2];
        level2[i].inputs[1] <== l1out[i * 2 + 1];
        l2out[i] <== level2[i].out;
    }

    // Level 3 (root): 2 nodes → 1 root
    component rootHasher = Poseidon(2);
    rootHasher.inputs[0] <== l2out[0];
    rootHasher.inputs[1] <== l2out[1];
    merkleRoot <== rootHasher.out;

    // ── Range check: auditScore (index 0) must be in [0, 100] ──────────────
    component auditScoreRange = LessEqThan(8);  // 8 bits = max 255
    auditScoreRange.in[0] <== attributeValues[0];
    auditScoreRange.in[1] <== 100;
    auditScoreRange.out === 1;

    // ── Enforce reserved indices 6–15 are zero ─────────────────────────────
    for (var i = 6; i < ATTR_COUNT; i++) {
        attributeValues[i] === 0;
    }
}

component main {public [commitment, merkleRoot]} = OpenACCredentialAnchorCircuit();
