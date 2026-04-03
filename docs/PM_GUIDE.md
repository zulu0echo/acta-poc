# ACTA Product Manager Guide

**Audience:** Product managers, business stakeholders, integration partners.  
**Reading time:** 15 minutes.  
**No code or cryptography knowledge required.**

---

## Section 1: What Problem Does ACTA Solve?

Imagine you run a DeFi protocol and you want to use an AI trading agent. You need to know it's compliant — audited, from an approved model, not operating from a sanctioned country.

But if you ask it to prove this on Ethereum, you're publishing that information to the entire world permanently. Your competitors can see which agents you use, how often, and how well they perform.

**ACTA lets you verify compliance in a way that produces only one piece of information: "yes, this agent passes" or "no, it doesn't." Nothing else.**

The agent's audit score, model version, jurisdiction, and identity are never revealed. Not to you, not to the blockchain, not to anyone. You only receive a mathematical guarantee that the agent satisfies your requirements.

---

## Section 2: The Three Actors and What They Do

| Actor | What They Do | In Your Product |
|-------|--------------|-----------------|
| **Issuer** | A trusted certifier who cryptographically signs a credential about the agent | An audit firm, a KYC provider, an accreditation registry, your own compliance team |
| **Holder (Agent)** | The AI agent that carries its credential and generates privacy-preserving proofs | The agent your product interacts with — could be an autonomous trading bot, risk assessment system, or any AI service |
| **Verifier** | Your protocol or application, checking credentials before allowing actions | Your smart contract, your backend API, your access control layer |

The Issuer and Holder interact before your protocol is involved at all. By the time an agent reaches your protocol, it already has its credentials. Your product only needs to implement the Verifier role.

---

## Section 3: The Six-Step Integration Checklist

This is a checklist you can hand to your engineering team:

- [ ] **1. Choose a trusted issuer** (or use the demo issuer for testing)
  - Who certifies agents in your ecosystem? An audit firm, a KYC provider?
  - Ask them to implement the Issuer package, or use the reference implementation
  - You'll receive an "issuer commitment" (a public key fingerprint) to register with your policy

- [ ] **2. Define your requirements using the PredicateBuilder SDK**
  - What must an agent prove? Minimum audit score? Specific capabilities? Jurisdiction restrictions?
  - Example: `auditScore >= 80 AND capabilities includes 'evm-execution' AND jurisdiction NOT IN ['IR', 'KP']`
  - No ZK or cryptography knowledge needed — the SDK handles everything

- [ ] **3. Register your policy on-chain with `registerPolicy()`**
  - You get a `policyId` — a permanent on-chain record of your requirements
  - Gas cost: ~$0.001 on Base Sepolia

- [ ] **4. When an agent wants to interact, send them the `requestUri`**
  - Call `createPresentationRequest()` to generate a challenge URL
  - The agent's wallet handles responding automatically
  - Typical round-trip: 2–5 seconds

- [ ] **5. When the agent responds, call `processResponse()`**
  - This handles off-chain verification (~0.05s) and on-chain submission (~0.5s)
  - Result: `{ verified: true, txHash: "0x…", nullifier: "0x…" }`

- [ ] **6. In your smart contract, gate your protocol actions on the nullifier**
  - Use `AgentAccessGate` or check `NullifierRegistry.isActive(nullifier)`
  - The `onlyVerifiedAgent(nullifier)` modifier is all you need

---

## Section 4: What Data Does Your Product Receive?

Your product receives:
1. **A yes/no verification result** — the agent either passed or didn't
2. **An Ethereum transaction hash** — permanent proof that verification happened
3. **A nullifier** — a one-time, anonymous identifier for this agent in this session

Your product does **not** receive:
- The agent's audit score
- The agent's model version or model hash
- The agent's operating jurisdiction
- The agent's identity or any identifying information
- The name of the issuer who certified the agent

This is by design. It means:
- Your protocol cannot accidentally expose sensitive data about your AI vendors
- Your competitors cannot learn your compliance criteria by watching your transactions
- Agents cannot be tracked across different protocols (each session has a different nullifier)

---

## Section 5: Performance and Cost

| Operation | Time | Cost |
|-----------|------|------|
| ZK proof generation (agent-side) | ~0.13 seconds on modern hardware | Free (runs locally) |
| Off-chain verification | ~0.05 seconds | Free (runs locally) |
| On-chain verification (Base Sepolia) | ~0.5 seconds (1 block) | ~200,000 gas (~$0.001) |
| Total round-trip | 2–5 seconds including network | ~$0.001 per verification |

Verification costs approximately $0.001 per agent interaction on Base Sepolia at current gas prices. This is negligible compared to the value of the transactions being gated.

---

## Section 6: Try the Interactive Demo

Before your team writes any code, open the interactive demo:

```bash
cd packages/demo-app && npm run dev
# Opens at http://localhost:5173
```

The demo walks through the complete ACTA flow in 10 steps, with no backend, no wallet, and no real network.

**Pay special attention to Step 8** — the ZK proof generation step. The split-panel view shows:
- **Left panel**: Everything the agent knows about itself (audit score, jurisdiction, model, capabilities)
- **Right panel**: The four values that actually leave the agent's device in the proof

That gap between the two panels is the core of what ACTA provides.

---

## Section 7: Common Questions

**Q: What if an issuer goes offline?**  
A: Once a credential is issued and anchored on-chain, the agent can generate proofs indefinitely without contacting the issuer. The issuer only needs to be available for initial issuance.

**Q: Can a credential be revoked?**  
A: Yes. The issuer can revoke a credential by calling `revokeCredential()` on `OpenACCredentialAnchor`. After revocation, new proofs will fail the Merkle root check (Step 5 of the 10-step sequence). Existing accepted presentations are not retroactively invalidated.

**Q: Can the same agent cheat by generating multiple nullifiers?**  
A: No. The nullifier is deterministically derived from the credential and the session context. The same credential always produces the same nullifier for the same (policy, verifier, nonce) context. If an agent tries to use different randomness to get a different nullifier for the same context, the proof will fail the commitment check.

**Q: What stops an agent from sharing its credentials with another agent?**  
A: The credential is bound to the holder's Ethereum address (the `id` field in `credentialSubject`). The on-chain anchor requires `msg.sender == address(uint160(agentId))`. A credential cannot be anchored for an address the holder doesn't control.

**Q: Is this production-ready?**  
A: This is a proof-of-concept. Before production use, the Groth16 trusted setup ceremony must be conducted with multiple independent parties, the Solidity contracts must be audited, and the `wallet-unit-poc` library must reach production stability. The architecture and protocol design are production-grade.

---

## Appendix: Glossary

| Term | Plain English |
|------|---------------|
| **DID** | A permanent, globally unique identifier backed by a cryptographic key — like an email address you own forever with no company in the middle |
| **JWT-VC** | A signed digital certificate (like a PDF diploma, but cryptographically verifiable) |
| **ZK proof** | A mathematical proof that a statement is true without revealing the evidence used to prove it |
| **Nullifier** | A one-time anonymous identifier — proves "this agent interacted" without revealing which agent |
| **Predicate** | A logical requirement ("must have X AND Y AND NOT Z") that an agent proves it satisfies |
| **Commitment** | A cryptographic seal on data — proves the data was locked in without revealing its contents |
| **Merkle root** | A single hash that summarises an entire dataset, such that any element can be proved to be in the dataset without revealing the others |
