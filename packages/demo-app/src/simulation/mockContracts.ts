export function generateVerifyAndRegisterCall(
  policyId: string,
  nullifier: string,
  verifierAddress: string
) {
  return {
    contract:  'GeneralizedPredicateVerifier',
    function:  'verifyAndRegister',
    args: {
      policyId,
      proof:     '0x[256-byte-proof-bytes]',
      pubSignals: '[nullifier, contextHash, predicateHash, issuerCommitment, merkleRoot, expiryBlock]',
      agentId:   '0x[holder-eth-address-as-uint256]',
      nonce:     '0x[session-nonce]',
    },
    estimatedGas: '~195,000 gas',
    estimatedCost: '~$0.001 at current Base gas prices',
    emits: 'PresentationAccepted(policyId, nullifier, contextHash, verifier, blockNumber)',
  }
}

export function generateNullifierRegistration(nullifier: string, contextHash: string) {
  return {
    contract: 'NullifierRegistry',
    internal: true,
    call:    `register(${nullifier.slice(0, 18)}…, ${contextHash.slice(0, 18)}…, expiryBlock)`,
    effect:  'Nullifier permanently marked active. Any replay attempt reverts with NullifierAlreadyActive.',
  }
}

export function generateReplayAttempt(nullifier: string) {
  return {
    attempt: 'verifyAndRegister with same proof/nullifier',
    step:    'Step 9 — NullifierRegistry.register() called',
    revert:  `NullifierAlreadyActive("${nullifier.slice(0, 18)}…")`,
    gasUsed: '~21,000 gas (reverted, refunded)',
    message: 'The same proof cannot be reused. Each verification is one-time.',
  }
}
