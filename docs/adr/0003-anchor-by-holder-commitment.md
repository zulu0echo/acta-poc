# ADR-0003 — Anchor credentials by holder-commitment, not by raw agentId

* **Status**: Accepted
* **Date**: 2026-05-27
* **Related**: ADR-0002 (stealth addresses), `docs/SECURITY_AUDIT.md` finding ACTA-014.
* **Supersedes**: The v0.2 `OpenACCredentialAnchor` layout that keys anchors by `agentId = uint160(holderEthrAddress)`.

## Context

Even with stealth addresses (ADR-0002), if the on-chain anchor still keys credentials by the holder's master address, a verifier can:

1. Read the anchor commitment for a holder's master address from the public anchor map.
2. Observe a stealth-address presentation that proves knowledge of the same commitment.
3. Correlate the stealth presentation back to the holder's master identity by matching commitments.

For genuine unlinkability we must remove the master address from on-chain lookups entirely.

## Decision

`OpenACCredentialAnchor` v2 will anchor credentials by a **holder-binding commitment**:

```
holderCommitment = Poseidon(holderMasterSecret, salt)
```

where `salt` is a high-entropy value committed during anchoring.

Anchoring writes:

```
anchorRoot = Poseidon(holderCommitment, credentialCommitment, credentialMerkleRoot)
```

into a Merkle accumulator (`anchorSet`). The on-chain state exposes only the **accumulator root** and an append-only event log of anchor leaves. There is **no public map from address to commitment**.

At presentation time, the holder proves in zero-knowledge:

```
∃ holderMasterSecret, salt, credentialCommitment, randomness, merkleRoot, anchorPath:
   holderCommitment      = Poseidon(holderMasterSecret, salt)
   credentialCommitment  = Poseidon(attributeValues, randomness)
   credentialMerkleRoot  = MerkleRoot(attributeValues)
   anchorLeaf            = Poseidon(holderCommitment, credentialCommitment, credentialMerkleRoot)
   anchorRoot            = MerkleVerify(anchorLeaf, anchorPath)
```

`anchorRoot` becomes a new public signal, replacing the v0.2 `credentialCommitment` + Merkle root surface for on-chain lookup. The anchor contract no longer needs the holder's address.

## Why this works

| Property | Justification |
|----------|---------------|
| **No address ↔ commitment binding on-chain** | Anchor leaves are committed to a Merkle accumulator; the public state is one root. Leaves emitted as events are pseudorandom (Poseidon outputs). |
| **Holder cannot double-anchor** | Optional: enforce `holderCommitment` uniqueness via a separate `usedCommitments` map, gated by a ZK proof of knowledge of `holderMasterSecret` (similar to nullifier scheme). |
| **Stealth-address presenter is unlinkable to anchorer** | Anchoring tx caller and presentation tx callers are independent stealth addresses (or, at anchor time, can also be a one-shot stealth address). |
| **Revocation** | A revocation list is maintained off-chain or as a separate Merkle accumulator. Inclusion in the revocation set defeats the proof. |

## Consequences

### Positive

- Closes finding ACTA-014 fully (not just operational mitigation).
- Removes the public correlation surface entirely.
- Enables ACTA to compose with other anchor-set systems (Semaphore-like).

### Negative

- The circuit grows: Merkle accumulator inclusion proof adds ~log₂(N) Poseidon hashes (~20 hashes for N=2²⁰).
- The off-chain anchor index (verifier-side or holder-side) must track leaves to construct inclusion proofs.
- The anchor contract becomes append-only — credential rotation requires anchoring a new leaf (the old leaf is not removed, but its `holderCommitment` is marked revoked).

### Neutral

- The credential structure (`Poseidon(attrs, randomness)`) does not change.

## Implementation status

| Component | Status | Path |
|-----------|--------|------|
| Anchor V2 Solidity contract | open (v0.5) | `packages/contracts/contracts/core/OpenACCredentialAnchorV2.sol` |
| Anchor-set off-chain index | open (v0.5) | `packages/issuer/src/anchorIndex.ts` |
| Merkle inclusion proof in circuit V2 | open (v0.5) | `circuits/presentation/OpenACGPPresentationV2.circom` (extends Phase 1) |
| Holder-commitment derivation helper | open (v0.5) | `packages/holder/src/holderCommitment.ts` |
| Verifier accepts anchor-by-commitment proofs | open (v0.5) | `GeneralizedPredicateVerifier.sol` |

## Open questions

1. Should the anchor set be sparse (per-holder Merkle tree) or dense (one global accumulator)? **Recommended**: dense global Merkle tree (1024-leaf or larger); sparse adds complexity without privacy benefit.
2. Should `holderCommitment` uniqueness be enforced on-chain? **Recommended**: yes via a `usedHolderCommitments` set, but only when a credential is *first* anchored.
3. How does revocation interact with stealth addresses? **Recommended**: the issuer publishes a `revokedLeavesRoot`; the circuit asserts `holderCommitment` is **not** in the revocation set.

## References

- Semaphore Merkle accumulator: <https://semaphore.appliedzkp.org>
- ADR-0002 (stealth addresses).
- `docs/SECURITY_AUDIT.md` finding ACTA-014.
