pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

/**
 * PredicateEval — evaluate a zkID generalised predicate against a claim
 * vector. Selects LHS/RHS via N-way selectors, dispatches the operator
 * (le=0, ge=1, eq=2), and outputs a boolean result.
 *
 * The `isActive` input is multiplied into the result so that inactive
 * (padding) predicates always yield 0 (they should not be referenced by
 * the postfix expression in any case).
 *
 * Parameters:
 *   N            — number of claim slots
 *   COMPARE_BITS — bit-width for ≤/≥ comparators (operands must fit)
 *
 * Inputs:
 *   claims[N]      — claim values (private)
 *   claimIdx       — LHS claim index ∈ [0, N)
 *   opCode         — 0 ⇒ ≤  | 1 ⇒ ≥  | 2 ⇒ ==
 *   operand        — RHS value (constant) OR claim index (if isClaimRef=1)
 *   isClaimRef     — 0/1 (0 ⇒ operand is constant, 1 ⇒ operand is claim idx)
 *   isActive       — 0/1 (0 ⇒ padding slot, output forced to 0)
 *
 * Outputs:
 *   result         — 0/1
 */
template PredicateEval(N, COMPARE_BITS) {
    signal input claims[N];
    signal input claimIdx;
    signal input opCode;
    signal input operand;
    signal input isClaimRef;
    signal input isActive;

    signal output result;

    // Booleanity
    isClaimRef * (1 - isClaimRef) === 0;
    isActive   * (1 - isActive)   === 0;

    // ── LHS: claims[claimIdx] via N-way selector ──────────────────────────
    component lhsEq[N];
    signal lhsAccum[N + 1];
    lhsAccum[0] <== 0;
    for (var i = 0; i < N; i++) {
        lhsEq[i] = IsEqual();
        lhsEq[i].in[0] <== claimIdx;
        lhsEq[i].in[1] <== i;
        lhsAccum[i + 1] <== lhsAccum[i] + lhsEq[i].out * claims[i];
    }
    signal lhs;
    lhs <== lhsAccum[N];

    // ── RHS: either `operand` (constant) or claims[operand] (claim ref) ───
    component rhsEq[N];
    signal rhsAccum[N + 1];
    rhsAccum[0] <== 0;
    for (var i = 0; i < N; i++) {
        rhsEq[i] = IsEqual();
        rhsEq[i].in[0] <== operand;
        rhsEq[i].in[1] <== i;
        rhsAccum[i + 1] <== rhsAccum[i] + rhsEq[i].out * claims[i];
    }
    signal rhsByClaim;
    rhsByClaim <== rhsAccum[N];

    // rhs = isClaimRef * rhsByClaim + (1 - isClaimRef) * operand
    //     = operand + isClaimRef * (rhsByClaim - operand)
    signal rhs;
    rhs <== operand + isClaimRef * (rhsByClaim - operand);

    // ── Operator dispatch ─────────────────────────────────────────────────
    component leCmp = LessEqThan(COMPARE_BITS);
    leCmp.in[0] <== lhs;
    leCmp.in[1] <== rhs;

    component geCmp = GreaterEqThan(COMPARE_BITS);
    geCmp.in[0] <== lhs;
    geCmp.in[1] <== rhs;

    component eqCmp = IsEqual();
    eqCmp.in[0] <== lhs;
    eqCmp.in[1] <== rhs;

    component opIsLE = IsEqual(); opIsLE.in[0] <== opCode; opIsLE.in[1] <== 0;
    component opIsGE = IsEqual(); opIsGE.in[0] <== opCode; opIsGE.in[1] <== 1;
    component opIsEQ = IsEqual(); opIsEQ.in[0] <== opCode; opIsEQ.in[1] <== 2;

    // Exactly one op must be selected when active. For padding slots we
    // still want a sound circuit; assert ≤ 1 is selected (so an inactive
    // slot can have opCode = anything but isActive will zero the output).
    signal opSum;
    opSum <== opIsLE.out + opIsGE.out + opIsEQ.out;
    // active ⇒ opSum == 1 ; inactive ⇒ opSum can be 0 or 1 (don't care)
    // Constraint: isActive * (1 - opSum) === 0
    signal opSelectGate;
    opSelectGate <== isActive * (1 - opSum);
    opSelectGate === 0;

    signal cmpResult;
    cmpResult <== opIsLE.out * leCmp.out
               + opIsGE.out * geCmp.out
               + opIsEQ.out * eqCmp.out;

    result <== isActive * cmpResult;
}
