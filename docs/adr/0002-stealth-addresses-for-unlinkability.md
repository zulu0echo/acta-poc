# ADR-0002 — Stealth addresses per (verifier, policyId, sessionIndex) for unlinkability

* **Status**: Accepted
* **Date**: 2026-05-27
* **Supersedes**: The v0.2 model where `agentId = uint160(holderEthrAddress)` is reused across all presentations.
* **Related**: ADR-0003 (anchor by holder-commitment), `docs/SECURITY_AUDIT.md` finding ACTA-014.

## Context

In ACTA v0.2 the holder uses a single `did:ethr` (a single Ethereum address) for:

1. Signing VP JWTs (the `iss` claim).
2. Submitting `verifyAndRegister` transactions (`msg.sender`).
3. Being looked up in `OpenACCredentialAnchor` (`agentId = uint160(address)`).

This makes every presentation **publicly correlatable**: any observer can group all presentations by `msg.sender`/`agentId`, defeating the protocol's anonymity goal.

The user explicitly required **unlinkability between verifiers and across sessions** (2026-05-27 scope confirmation).

## Decision

The holder derives a fresh **stealth keypair** per presentation context, scoped by `(verifierAddress, policyId, sessionIndex)`. The stealth key:

- Signs the VP JWT (becomes the new `iss` DID).
- Pays gas and is `msg.sender` for `verifyAndRegister`.

The holder's **master secret** is never exposed on-chain or to the verifier.

### Derivation

```
stealthSeed = HKDF-SHA256(
  ikm  = holderMasterSecret,
  salt = "acta-stealth/v1",
  info = "verifier:" || verifierAddress || "|policy:" || policyId || "|session:" || sessionIndex
)

stealthPriv = SHA256(stealthSeed) mod (n − 1) + 1     // secp256k1 group order
stealthPub  = stealthPriv · G
stealthAddr = keccak256(stealthPub.x || stealthPub.y)[12:]
```

Properties:

| Property | Justification |
|----------|---------------|
| **Determinism**: same `(master, verifier, policyId, sessionIndex)` → same stealth address. | HKDF is a deterministic function. Re-derivation lets the holder recover from local state loss. |
| **Indistinguishability**: stealth address is computationally indistinguishable from a uniformly-random Ethereum address. | HKDF output is computationally pseudo-random; reduction modulo `n` is statistically uniform over `[1, n-1]`. |
| **Domain separation**: master is bound to ACTA's stealth purpose. | The `"acta-stealth/v1"` salt prevents cross-protocol address reuse. |
| **Forward secrecy**: leaking one stealth private key does not reveal the master or any other stealth key. | HKDF is one-way; each output is independent across `info` strings. |

### Funding (out-of-band)

The user explicitly preferred this model **over a relayer** (no off-chain dependency).

The holder is responsible for funding each stealth address with the gas needed for one `verifyAndRegister` call (~205k gas). This is the UX cost we accept for "no relayer".

Funding strategies (documented in `docs/PM_GUIDE.md` for v0.5):

1. **Pre-funded pool**: the holder pre-funds N stealth addresses from a faucet drip (suitable for L2s with cheap gas).
2. **Just-in-time funding**: the holder transfers gas from its master address immediately before each presentation, accepting that the funding transaction is correlatable. To mitigate correlation, route via a privacy-preserving service (e.g., mixers, atomic swaps) — out of scope for ACTA itself.
3. **Per-verifier deposit**: the verifier pre-funds the holder's stealth address from a deposit. This re-introduces a verifier dependency but is the simplest model for one-shot integrations.

### Why not a relayer?

A relayer (the alternative considered) would be simpler from a UX perspective:
- Holder signs a meta-transaction → relayer submits → `msg.sender = relayer`.
- The relayer absorbs the gas-funding correlation problem.

The user chose **stealth addresses** because relayers re-introduce an off-chain service dependency (and an availability target). Stealth addresses keep ACTA's trust model fully decentralised at the cost of UX.

If practical experience shows the funding-correlation problem dominates, this ADR should be revisited with a relayer model (see "Open questions").

## Consequences

### Positive

- Two presentations to the same verifier under different `policyId` values are unlinkable on-chain.
- Two presentations to different verifiers under any `policyId` are unlinkable on-chain.
- The holder's master DID is never used on-chain post-anchoring.

### Negative

- The holder must fund each stealth address before it can submit (~$0.002 of gas on Base Sepolia per presentation, much less in production L2 conditions).
- A naive funding pattern (`master → stealth` in one tx, then `stealth → verifier` in the next) is itself correlatable. Mitigation is documented but not enforced.
- The holder's wallet UX grows: keypair derivation, address funding, address tracking.

### Neutral

- The off-chain VP JWT verification at the verifier changes from "VP `iss` must match anchored agentId" to "VP `iss` must be derivable from the anchored holder commitment" — this is part of ADR-0003.

## Implementation status (v0.3 snapshot)

| Component | Shipped | Path |
|-----------|---------|------|
| Derivation function | yes | `packages/holder/src/stealth.ts` |
| Determinism + uniqueness tests | yes | `packages/holder/test/stealth.test.ts` |
| Holder presentation flow uses stealth | open (v0.5) | `packages/holder/src/openacAdapter.ts` |
| Funding helper | open (v0.5) | `packages/holder/src/stealthFunding.ts` |
| Docs (`docs/PM_GUIDE.md`, `docs/FLOW.md`) updated | open (v0.5) | `docs/` |

## Open questions

1. Should the holder rotate stealth addresses per session even for the same `(verifier, policyId)`? **Recommended**: yes, include a `sessionIndex` (already in the derivation function).
2. Should the verifier accept the master DID as a fallback (for non-anonymous flows)? **Recommended**: no — the holder explicitly opts into stealth or non-stealth via a flag.
3. Should ACTA standardise a stealth-funding interface? **Recommended**: defer to v0.6 once observed funding patterns settle.

## References

- secp256k1 group order: <https://www.secg.org/sec2-v2.pdf>
- HKDF: RFC 5869
- BIP-32 (HD derivation) — informative comparison.
- `docs/SECURITY_AUDIT.md` finding ACTA-014.
