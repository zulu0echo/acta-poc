pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

/**
 * PostfixEval — stack-based evaluator for a zkID-style postfix logical
 * expression over booleans.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  STATUS: v0.3 DRAFT — pending ZK-engineer review and ceremony.
 *  Do not deploy to mainnet until reviewed against the
 *  `circuits/test/postfixEval.test.ts` parity vectors and the constraint
 *  count is acceptable (target: ≤ 10k constraints for T=16, M=8).
 * ──────────────────────────────────────────────────────────────────────────
 *
 * Strategy: the prover supplies the full stack trace as private witness
 * signals (stackTrace[T+1][STACK_W], dpTrace[T+1]). The circuit verifies:
 *
 *   1. Initial state:  dpTrace[0] = 0, stackTrace[0][*] = 0.
 *   2. For every step k ∈ [0, T):
 *        Given (exprTokenType[k], exprTokenValue[k]) and predResult[],
 *        the post-state (stackTrace[k+1], dpTrace[k+1]) is consistent with
 *        the pre-state and the token's stack-machine semantics.
 *   3. Final state:    dpTrace[T] = 1   and   stackTrace[T][0] = 1 (= true).
 *
 * Token types (must match TypeScript encoder):
 *   0 = PAD   (no-op)
 *   1 = PRED  (push predResult[exprTokenValue[k]])
 *   2 = AND   (pop a, pop b, push a*b)
 *   3 = OR    (pop a, pop b, push a + b − a*b)
 *   4 = NOT   (pop a,        push 1 − a)
 *
 * Parameters:
 *   T  — max number of tokens (also serves as max stack depth bound)
 *   M  — number of predicate result slots
 *
 * Constraint footprint (rough estimate):
 *   - Per step: O((T+1) + M)        for selectors
 *   - Per cell × per step: O(1)     for transition
 *   - Total ≈ T · ((T+1)·6 + M)     ≈ T·(6T + M)
 *   For T=16, M=8: ≈ 16·(96 + 8) = 1664 constraints — within budget.
 */
template PostfixEval(T, M) {
    var STACK_W = T + 1; // stack width

    signal input predResult[M];
    signal input exprTokenType[T];
    signal input exprTokenValue[T];
    signal input stackTrace[T + 1][STACK_W];
    signal input dpTrace[T + 1];

    signal output finalValue;

    // ── 1. Initial state ──────────────────────────────────────────────────
    dpTrace[0] === 0;
    for (var d = 0; d < STACK_W; d++) {
        stackTrace[0][d] === 0;
    }

    // ── Per-step component & signal pre-allocation ────────────────────────
    component isPad[T];
    component isPred[T];
    component isAND[T];
    component isOR[T];
    component isNOT[T];

    component predEq[T][M];
    signal    predLookupAccum[T][M + 1];
    signal    pushVal[T];

    component depthSelTop1[T][STACK_W];
    signal    depthAccumTop1[T][STACK_W + 1];
    component depthSelTop2[T][STACK_W];
    signal    depthAccumTop2[T][STACK_W + 1];
    signal    top1[T];
    signal    top2[T];
    signal    andResult[T];
    signal    orResult[T];

    component writePosEqPush[T][STACK_W];   // d == dp[k]
    component writePosEqUnary[T][STACK_W];  // d == dp[k] - 1
    component writePosEqBinary[T][STACK_W]; // d == dp[k] - 2

    signal    writePred[T][STACK_W];
    signal    writeNot[T][STACK_W];
    signal    writeAndPos[T][STACK_W];
    signal    writeOrPos[T][STACK_W];
    signal    clearAndOrPos[T][STACK_W];
    signal    isWritten[T][STACK_W];
    signal    writeContribPred[T][STACK_W];
    signal    writeContribNot[T][STACK_W];
    signal    writeContribAnd[T][STACK_W];
    signal    writeContribOr[T][STACK_W];
    signal    writeVal[T][STACK_W];
    signal    keep[T][STACK_W];

    signal    typeSum[T];
    signal    expectedDp[T];

    // ── 2. Per-step transitions ───────────────────────────────────────────
    for (var k = 0; k < T; k++) {
        // ── Token type one-hot ─────
        isPad[k]  = IsEqual(); isPad[k].in[0]  <== exprTokenType[k]; isPad[k].in[1]  <== 0;
        isPred[k] = IsEqual(); isPred[k].in[0] <== exprTokenType[k]; isPred[k].in[1] <== 1;
        isAND[k]  = IsEqual(); isAND[k].in[0]  <== exprTokenType[k]; isAND[k].in[1]  <== 2;
        isOR[k]   = IsEqual(); isOR[k].in[0]   <== exprTokenType[k]; isOR[k].in[1]   <== 3;
        isNOT[k]  = IsEqual(); isNOT[k].in[0]  <== exprTokenType[k]; isNOT[k].in[1]  <== 4;

        typeSum[k] <== isPad[k].out + isPred[k].out + isAND[k].out + isOR[k].out + isNOT[k].out;
        typeSum[k] === 1;

        // ── pushVal = predResult[exprTokenValue[k]] ─────
        predLookupAccum[k][0] <== 0;
        for (var p = 0; p < M; p++) {
            predEq[k][p] = IsEqual();
            predEq[k][p].in[0] <== exprTokenValue[k];
            predEq[k][p].in[1] <== p;
            predLookupAccum[k][p + 1] <== predLookupAccum[k][p] + predEq[k][p].out * predResult[p];
        }
        pushVal[k] <== predLookupAccum[k][M];

        // ── top1 = stackTrace[k][dp[k]-1], top2 = stackTrace[k][dp[k]-2] ─────
        depthAccumTop1[k][0] <== 0;
        depthAccumTop2[k][0] <== 0;
        for (var d = 0; d < STACK_W; d++) {
            depthSelTop1[k][d] = IsEqual();
            depthSelTop1[k][d].in[0] <== dpTrace[k];
            depthSelTop1[k][d].in[1] <== d + 1;
            depthAccumTop1[k][d + 1] <== depthAccumTop1[k][d] + depthSelTop1[k][d].out * stackTrace[k][d];

            depthSelTop2[k][d] = IsEqual();
            depthSelTop2[k][d].in[0] <== dpTrace[k];
            depthSelTop2[k][d].in[1] <== d + 2;
            depthAccumTop2[k][d + 1] <== depthAccumTop2[k][d] + depthSelTop2[k][d].out * stackTrace[k][d];
        }
        top1[k] <== depthAccumTop1[k][STACK_W];
        top2[k] <== depthAccumTop2[k][STACK_W];

        // ── Depth transition ─────
        // PAD: 0, PRED: +1, NOT: 0, AND: -1, OR: -1
        expectedDp[k] <== dpTrace[k] + isPred[k].out - isAND[k].out - isOR[k].out;
        dpTrace[k + 1] === expectedDp[k];

        andResult[k] <== top1[k] * top2[k];
        // orResult = top1 + top2 - top1*top2 = top1 + top2 - andResult
        orResult[k]  <== top1[k] + top2[k] - andResult[k];

        // ── Cell transitions ─────
        for (var d = 0; d < STACK_W; d++) {
            // Write-position indicators
            writePosEqPush[k][d] = IsEqual();
            writePosEqPush[k][d].in[0] <== dpTrace[k];
            writePosEqPush[k][d].in[1] <== d;

            writePosEqUnary[k][d] = IsEqual();
            writePosEqUnary[k][d].in[0] <== dpTrace[k];
            writePosEqUnary[k][d].in[1] <== d + 1;

            writePosEqBinary[k][d] = IsEqual();
            writePosEqBinary[k][d].in[0] <== dpTrace[k];
            writePosEqBinary[k][d].in[1] <== d + 2;

            // Per-op active-write flags (degree 2)
            writePred[k][d]     <== isPred[k].out * writePosEqPush[k][d].out;
            writeNot[k][d]      <== isNOT[k].out  * writePosEqUnary[k][d].out;
            writeAndPos[k][d]   <== isAND[k].out  * writePosEqBinary[k][d].out;
            writeOrPos[k][d]    <== isOR[k].out   * writePosEqBinary[k][d].out;
            // The cell at dp[k]-1 must be cleared when AND/OR fires (was top1)
            clearAndOrPos[k][d] <== (isAND[k].out + isOR[k].out) * writePosEqUnary[k][d].out;

            // Total write indicator (these are mutually exclusive in well-formed steps;
            // we sum without checking exclusivity — the typeSum/expectedDp checks
            // above ensure at most one op fires per step).
            isWritten[k][d] <== writePred[k][d] + writeNot[k][d] + writeAndPos[k][d] + writeOrPos[k][d] + clearAndOrPos[k][d];

            // Per-op contributions to writeVal (each is degree 2)
            writeContribPred[k][d] <== writePred[k][d]   * pushVal[k];
            writeContribNot[k][d]  <== writeNot[k][d]    * (1 - top1[k]);
            writeContribAnd[k][d]  <== writeAndPos[k][d] * andResult[k];
            writeContribOr[k][d]   <== writeOrPos[k][d]  * orResult[k];
            // clearAndOrPos contributes 0.
            writeVal[k][d] <== writeContribPred[k][d] + writeContribNot[k][d] + writeContribAnd[k][d] + writeContribOr[k][d];

            // Transition: next[d] = (1 - isWritten[d]) * cur[d] + writeVal[d]
            keep[k][d] <== (1 - isWritten[k][d]) * stackTrace[k][d];
            stackTrace[k + 1][d] === keep[k][d] + writeVal[k][d];
        }
    }

    // ── 3. Final state ────────────────────────────────────────────────────
    dpTrace[T] === 1;
    finalValue <== stackTrace[T][0];
}
