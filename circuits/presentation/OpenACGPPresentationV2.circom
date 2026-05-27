pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "../lib/NullifierDerive.circom";
include "../lib/PredicateEval.circom";
include "../lib/PostfixEval.circom";

/**
 * OpenACGPPresentationV2 — zkID generalized-predicate presentation circuit
 * for ACTA v0.4+.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  STATUS: v0.3 DRAFT — pending ZK-engineer review and trusted setup.
 *  This file is the **specification** of the V2 constraints. It is not yet
 *  expected to compile cleanly against snarkjs/circom 2.1.6 without
 *  optimisation passes. See docs/ROADMAP.md Phase 1 for the path to v0.4.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * Replaces v0.2's three hard-coded predicate families with the zkID
 * generalised-predicate model:
 *
 *   • Predicates: list of (claimIndex, op ∈ {≤, ≥, ==}, operand, isClaimRef)
 *   • Expression: postfix tokens over {AND, OR, NOT, PRED(i)} with PAD slots
 *
 * The TypeScript encoder in @acta/shared/gp/encoder.ts MUST produce the
 * same witness layout as this circuit consumes; parity is enforced by
 * vector tests in packages/shared/test/gp.test.ts (off-chain) and
 * circuits/test/openacGPPresentationV2.test.ts (in-circuit, future).
 *
 * Public signals (order matches the on-chain GP verifier's pubSignals[]):
 *   0: nullifier
 *   1: contextHash
 *   2: predicateProgramHash
 *   3: issuerPubKeyCommitment
 *   4: credentialMerkleRoot
 *   5: credentialCommitmentOut
 *   6: expiryBlock
 */
template OpenACGPPresentationV2() {
    // ── Circuit bounds (MUST match encoder.ts DEFAULT_GP_BOUNDS) ──────────
    var N_CLAIMS    = 16; // claim slots (credential attributeValues)
    var M_PREDS     = 8;  // max predicates per program
    var T_TOKENS    = 16; // max postfix expression length
    var COMPARE_BITS = 64; // bit-width for ≤/≥ comparators

    // ── Private inputs ────────────────────────────────────────────────────
    signal input attributeValues[N_CLAIMS];
    signal input randomness;
    signal input credentialCommitment;
    signal input issuerPubKeyCommitmentPrivate;
    signal input verifierAddress;
    signal input policyId;
    signal input nonce;
    signal input expiryBlockPrivate;

    // ── GP program (private witness, but bound to predicateProgramHash) ───
    signal input predClaimIdx[M_PREDS];
    signal input predOpCode[M_PREDS];
    signal input predOperand[M_PREDS];
    signal input predIsClaimRef[M_PREDS];
    signal input predIsActive[M_PREDS];
    signal input exprTokenType[T_TOKENS];
    signal input exprTokenValue[T_TOKENS];

    // Prover-supplied postfix stack trace
    signal input stackTrace[T_TOKENS + 1][T_TOKENS + 1];
    signal input dpTrace[T_TOKENS + 1];

    // ── Public outputs ────────────────────────────────────────────────────
    signal output nullifier;
    signal output contextHash;
    signal output predicateProgramHash;
    signal output issuerPubKeyCommitment;
    signal output credentialMerkleRoot;
    signal output credentialCommitmentOut;
    signal output expiryBlock;

    issuerPubKeyCommitment <== issuerPubKeyCommitmentPrivate;
    expiryBlock <== expiryBlockPrivate;
    credentialCommitmentOut <== credentialCommitment;

    // ── 1. Credential commitment ──────────────────────────────────────────
    component commitHasher = Poseidon(N_CLAIMS + 1);
    for (var i = 0; i < N_CLAIMS; i++) {
        commitHasher.inputs[i] <== attributeValues[i];
    }
    commitHasher.inputs[N_CLAIMS] <== randomness;
    commitHasher.out === credentialCommitment;

    // ── 2. Merkle root (same construction as V1) ──────────────────────────
    component l0[8]; signal l0out[8];
    for (var i = 0; i < 8; i++) {
        l0[i] = Poseidon(2);
        l0[i].inputs[0] <== attributeValues[i * 2];
        l0[i].inputs[1] <== attributeValues[i * 2 + 1];
        l0out[i] <== l0[i].out;
    }
    component l1[4]; signal l1out[4];
    for (var i = 0; i < 4; i++) {
        l1[i] = Poseidon(2);
        l1[i].inputs[0] <== l0out[i * 2];
        l1[i].inputs[1] <== l0out[i * 2 + 1];
        l1out[i] <== l1[i].out;
    }
    component l2[2]; signal l2out[2];
    for (var i = 0; i < 2; i++) {
        l2[i] = Poseidon(2);
        l2[i].inputs[0] <== l1out[i * 2];
        l2[i].inputs[1] <== l1out[i * 2 + 1];
        l2out[i] <== l2[i].out;
    }
    component rootHasher = Poseidon(2);
    rootHasher.inputs[0] <== l2out[0];
    rootHasher.inputs[1] <== l2out[1];
    credentialMerkleRoot <== rootHasher.out;

    // ── 3a. Predicate evaluation (M parallel evaluators) ──────────────────
    component predEval[M_PREDS];
    signal predResult[M_PREDS];
    for (var p = 0; p < M_PREDS; p++) {
        predEval[p] = PredicateEval(N_CLAIMS, COMPARE_BITS);
        for (var i = 0; i < N_CLAIMS; i++) {
            predEval[p].claims[i] <== attributeValues[i];
        }
        predEval[p].claimIdx   <== predClaimIdx[p];
        predEval[p].opCode     <== predOpCode[p];
        predEval[p].operand    <== predOperand[p];
        predEval[p].isClaimRef <== predIsClaimRef[p];
        predEval[p].isActive   <== predIsActive[p];
        predResult[p] <== predEval[p].result;
    }

    // ── 3b. Postfix expression evaluation ─────────────────────────────────
    component postfix = PostfixEval(T_TOKENS, M_PREDS);
    for (var p = 0; p < M_PREDS; p++) {
        postfix.predResult[p] <== predResult[p];
    }
    for (var k = 0; k < T_TOKENS; k++) {
        postfix.exprTokenType[k]  <== exprTokenType[k];
        postfix.exprTokenValue[k] <== exprTokenValue[k];
    }
    for (var k = 0; k <= T_TOKENS; k++) {
        postfix.dpTrace[k] <== dpTrace[k];
        for (var d = 0; d <= T_TOKENS; d++) {
            postfix.stackTrace[k][d] <== stackTrace[k][d];
        }
    }
    // The program is satisfied iff finalValue == 1.
    postfix.finalValue === 1;

    // ── 3c. Bind predicateProgramHash to witness program inputs ───────────
    //
    // The hash is computed by a Merkle-style binary fold of Poseidon(2)
    // over a 75-element flat vector matching `canonicalProgramHash()` in
    // packages/shared/src/gp/encoder.ts:
    //
    //   fields = [
    //     version=1,
    //     M_PREDS,
    //     T_TOKENS,
    //     // per predicate (5 fields × M_PREDS = 40):
    //     predClaimIdx[0..M], predOpCode[0..M], predOperand[0..M],
    //     predIsClaimRef[0..M], predIsActive[0..M],
    //     // per token (2 fields × T_TOKENS = 32):
    //     exprTokenType[0..T], exprTokenValue[0..T],
    //   ]
    //
    // Total = 1 + 2 + 5·M + 2·T = 1 + 2 + 40 + 32 = 75 fields.
    // We hash with a balanced binary tree of Poseidon(2) hashes; the
    // fold mirrors `foldPoseidonHash()` in encoder.ts.
    //
    // For brevity (and to keep this draft readable), we materialise a
    // 128-leaf tree by zero-padding the 75-element vector to 128 leaves,
    // then fold log₂(128) = 7 levels using Poseidon(2) at each step.

    var HASH_LEAVES = 128;
    signal hashLeaves[HASH_LEAVES];
    hashLeaves[0] <== 1;                              // version
    hashLeaves[1] <== M_PREDS;
    hashLeaves[2] <== T_TOKENS;
    var idx = 3;
    for (var p = 0; p < M_PREDS; p++) {
        hashLeaves[idx]     <== predClaimIdx[p];
        hashLeaves[idx + 1] <== predOpCode[p];
        hashLeaves[idx + 2] <== predOperand[p];
        hashLeaves[idx + 3] <== predIsClaimRef[p];
        hashLeaves[idx + 4] <== predIsActive[p];
        idx = idx + 5;
    }
    for (var k = 0; k < T_TOKENS; k++) {
        hashLeaves[idx]     <== exprTokenType[k];
        hashLeaves[idx + 1] <== exprTokenValue[k];
        idx = idx + 2;
    }
    // idx == 75; pad the remaining leaves with 0.
    for (var i = idx; i < HASH_LEAVES; i++) {
        hashLeaves[i] <== 0;
    }

    // Binary fold: 128 → 64 → 32 → 16 → 8 → 4 → 2 → 1
    var LEVEL0 = 64;
    component fold0[LEVEL0];
    signal level0[LEVEL0];
    for (var i = 0; i < LEVEL0; i++) {
        fold0[i] = Poseidon(2);
        fold0[i].inputs[0] <== hashLeaves[i * 2];
        fold0[i].inputs[1] <== hashLeaves[i * 2 + 1];
        level0[i] <== fold0[i].out;
    }
    var LEVEL1 = 32;
    component fold1[LEVEL1];
    signal level1[LEVEL1];
    for (var i = 0; i < LEVEL1; i++) {
        fold1[i] = Poseidon(2);
        fold1[i].inputs[0] <== level0[i * 2];
        fold1[i].inputs[1] <== level0[i * 2 + 1];
        level1[i] <== fold1[i].out;
    }
    var LEVEL2 = 16;
    component fold2[LEVEL2];
    signal level2[LEVEL2];
    for (var i = 0; i < LEVEL2; i++) {
        fold2[i] = Poseidon(2);
        fold2[i].inputs[0] <== level1[i * 2];
        fold2[i].inputs[1] <== level1[i * 2 + 1];
        level2[i] <== fold2[i].out;
    }
    var LEVEL3 = 8;
    component fold3[LEVEL3];
    signal level3[LEVEL3];
    for (var i = 0; i < LEVEL3; i++) {
        fold3[i] = Poseidon(2);
        fold3[i].inputs[0] <== level2[i * 2];
        fold3[i].inputs[1] <== level2[i * 2 + 1];
        level3[i] <== fold3[i].out;
    }
    var LEVEL4 = 4;
    component fold4[LEVEL4];
    signal level4[LEVEL4];
    for (var i = 0; i < LEVEL4; i++) {
        fold4[i] = Poseidon(2);
        fold4[i].inputs[0] <== level3[i * 2];
        fold4[i].inputs[1] <== level3[i * 2 + 1];
        level4[i] <== fold4[i].out;
    }
    var LEVEL5 = 2;
    component fold5[LEVEL5];
    signal level5[LEVEL5];
    for (var i = 0; i < LEVEL5; i++) {
        fold5[i] = Poseidon(2);
        fold5[i].inputs[0] <== level4[i * 2];
        fold5[i].inputs[1] <== level4[i * 2 + 1];
        level5[i] <== fold5[i].out;
    }
    component fold6 = Poseidon(2);
    fold6.inputs[0] <== level5[0];
    fold6.inputs[1] <== level5[1];
    predicateProgramHash <== fold6.out;

    // ── 4. Nullifier ──────────────────────────────────────────────────────
    component credSecret = Poseidon(2);
    credSecret.inputs[0] <== credentialCommitment;
    credSecret.inputs[1] <== randomness;

    component nullifierDeriver = NullifierDerive();
    nullifierDeriver.credentialSecret <== credSecret.out;
    nullifierDeriver.verifierAddress  <== verifierAddress;
    nullifierDeriver.policyId         <== policyId;
    nullifierDeriver.nonce            <== nonce;
    nullifier <== nullifierDeriver.nullifier;

    // ── 5. contextHash (Poseidon, on-chain verifier checks keccak too) ────
    component ctxHasher = Poseidon(3);
    ctxHasher.inputs[0] <== verifierAddress;
    ctxHasher.inputs[1] <== policyId;
    ctxHasher.inputs[2] <== nonce;
    contextHash <== ctxHasher.out;

    // ── 6. Reserved attribute indices must be zero ────────────────────────
    // V2 keeps the same reserved-slot convention as V1 for compatibility
    // with @acta/shared/constants ATTRIBUTE_INDEX.
    for (var i = 6; i < N_CLAIMS; i++) {
        attributeValues[i] === 0;
    }
}

component main {public [
    nullifier, contextHash, predicateProgramHash,
    issuerPubKeyCommitment, credentialMerkleRoot, credentialCommitmentOut, expiryBlock
]} = OpenACGPPresentationV2();
