export default function SpecPage() {
  return (
    <div className="h-full overflow-y-auto bg-dark-900">
      <div className="max-w-4xl mx-auto px-8 py-10 prose-spec">

        {/* Header */}
        <div className="mb-10 pb-6 border-b border-gray-700/60">
          <div className="flex items-center gap-3 mb-3">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-900/50 text-amber-300 border border-amber-700/50">raw</span>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-900/50 text-blue-300 border border-blue-700/50">Standards Track</span>
            <span className="text-xs text-gray-500 font-mono">slug: 8080</span>
          </div>
          <h1 className="text-2xl font-bold text-white mb-1">ACTA/ANONYMOUS-AGENT-CREDENTIALS</h1>
          <p className="text-gray-400 text-sm">Anonymous Credential Verification for Trustless AI Agents on EVM Chains</p>
          <p className="text-xs text-gray-600 mt-2">
            Tags: zero-knowledge · anonymous-credentials · ai-agents · evm · nullifiers · did-ethr · groth16 · poseidon · privacy
          </p>
        </div>

        <Section title="Abstract">
          <p>
            This specification defines a four-layer protocol that allows an AI agent to prove compliance with a
            verifier-defined predicate policy — without disclosing the underlying credential attributes — and
            receive on-chain access rights whose scope is permanently bounded to a single (verifier, policy, nonce) context.
          </p>
          <p className="mt-3">
            The agent holds a W3C Verifiable Credential issued by a trusted <Code>did:ethr</Code> issuer.
            A Groth16 SNARK (<Code>OpenACGPPresentation</Code>) proves that the credential satisfies the verifier's
            predicate (e.g., <Code>auditScore ≥ 80 AND jurisdiction NOT IN [IR, KP]</Code>) while exposing only
            six public signals: a context-scoped nullifier, a context hash, a predicate program hash, an issuer
            public key commitment, a credential Merkle root, and an expiry block.
          </p>
          <p className="mt-3">
            On-chain verification (<Code>GeneralizedPredicateVerifier.verifyAndRegister</Code>) executes a
            10-step atomic sequence that validates all six signals, verifies the Groth16 proof, registers the
            nullifier, and emits <Code>PresentationAccepted</Code>. Replay attacks are cryptographically
            prevented: the nullifier is deterministic for a given <Code>(credentialSecret, verifierAddress, policyId, nonce)</Code> tuple
            and is stored permanently on registration.
          </p>
        </Section>

        <Section title="Motivation">
          <p>
            AI agents operating in DeFi, on-chain governance, and regulated protocol contexts require compliance
            verification before accessing sensitive operations. Classical approaches — KYC databases, allow-lists,
            on-chain identity registries — either break agent privacy or create centralised chokepoints.
          </p>
          <p className="mt-3">
            ACTA separates <em>eligibility proof</em> from <em>identity disclosure</em>. A protocol can
            enforce "only audit-certified agents with no sanctioned-jurisdiction exposure may execute trades"
            without learning which specific agent passed, what their exact audit score is, or linking two
            distinct protocol interactions to the same agent.
          </p>
          <p className="mt-3">
            The core primitive is a <strong className="text-white">context-scoped nullifier</strong>: a single
            credential produces a different nullifier for every (verifier, policy, nonce) context, so
            cross-protocol identity linkage is computationally infeasible even if an adversary observes every
            nullifier on every chain.
          </p>
        </Section>

        <Section title="System Architecture">
          <p className="mb-3">Four layers are strictly separated. A compromise at one layer MUST NOT propagate to adjacent layers.</p>
          <CodeBlock>{`Layer 4: On-Chain Execution     — smart contracts enforce verification and gate access
Layer 3: ZK Privacy             — Groth16 SNARK proves predicate satisfaction in private
Layer 2: W3C Credential         — JWT-VC signed by a did:ethr issuer
Layer 1: DID Identity           — did:ethr backed by ERC-1056 (EthereumDIDRegistry)`}</CodeBlock>
          <Table
            headers={['Role', 'Description', 'Key Material']}
            rows={[
              ['Issuer', 'Certifies agent attributes; issues AgentCapabilityCredential', 'did:ethr secp256k1 key'],
              ['Holder (Agent)', 'Carries credential; generates ZK proof on request', 'did:ethr secp256k1 key'],
              ['Verifier (Protocol)', 'Defines predicate policy; submits proof on-chain', 'did:ethr secp256k1 key'],
            ]}
          />
        </Section>

        <Section title="Cryptographic Primitives">
          <Table
            headers={['Primitive', 'Usage', 'Parameters']}
            rows={[
              ['Poseidon', 'Commitment, nullifier, Merkle tree, context hash', 'BN254 scalar field; circomlib parameters'],
              ['Groth16', 'SNARK proving and on-chain verification', 'BN254 curve; trusted setup required'],
              ['secp256k1 / ES256K', 'DID keys, JWT signing, Ethereum transactions', 'Standard Ethereum parameters'],
              ['keccak256', 'On-chain context hash, issuer commitment, policyId', 'EVM native'],
            ]}
          />
          <p className="mt-3 text-sm">
            Implementations MUST use the <a href="https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom" className="text-brand-400 hover:text-brand-300">circomlib Poseidon</a> implementation
            with BN254 scalar field parameters. Different Poseidon configurations across prover and verifier WILL produce proof failures.
          </p>
        </Section>

        <Section title="Circuit: OpenACGPPresentation">
          <p className="mb-4 text-sm">Groth16 on BN254. File: <Code>circuits/presentation/OpenACGPPresentation.circom</Code></p>

          <SubSection title="Private Inputs">
            <Table
              headers={['Signal', 'Description']}
              rows={[
                ['attributeValues[16]', 'Credential subject fields at fixed indices'],
                ['randomness', 'Blinding factor for the credential commitment'],
                ['credentialCommitment', 'On-chain commitment = Poseidon(attributeValues[], randomness)'],
                ['issuerPubKeyCommitmentPrivate', 'keccak256(compressedPubKey) & ((1 << 248) − 1)'],
                ['verifierAddress', 'Ethereum address of the verifier (field element)'],
                ['policyId', 'bytes32 policy identifier (field element)'],
                ['nonce', 'uint64 session nonce from OID4VP request'],
                ['expiryBlockPrivate', 'Block number after which the presentation is invalid'],
                ['predicateAuditScoreMin', 'Minimum audit score (0 = disabled)'],
                ['predicateCapabilityMask', 'Required capability bitmask (0 = disabled)'],
                ['predicateJurisdictionSanctions[8]', 'Banned jurisdiction numerics (0 = unused slot)'],
                ['predicateProgramHashPrivate', 'Hash of the predicate program'],
              ]}
            />
          </SubSection>

          <SubSection title="Public Outputs">
            <Table
              headers={['Index', 'Signal', 'Description']}
              rows={[
                ['0', 'nullifier', 'Context-scoped anonymous agent identifier'],
                ['1', 'contextHash', 'Poseidon(verifierAddress, policyId, nonce) — in-circuit commitment'],
                ['2', 'predicateProgramHash', 'Binds proof to specific policy'],
                ['3', 'issuerPubKeyCommitment', 'Binds proof to specific trusted issuer'],
                ['4', 'credentialMerkleRoot', 'Proves credential is current on-chain'],
                ['5', 'expiryBlock', 'Enforces proof time-bounding'],
              ]}
            />
          </SubSection>

          <SubSection title="Nullifier Derivation">
            <CodeBlock>{`credentialSecret = Poseidon(credentialCommitment, randomness)
contextHashInner  = Poseidon(verifierAddress, policyId, nonce)
nullifier         = Poseidon(credentialSecret, contextHashInner)`}</CodeBlock>
            <p className="mt-2 text-sm">
              The nullifier is deterministic for a given (credential, verifier, policy, nonce) tuple.
              It is computationally unlinkable across contexts because <Code>contextHashInner</Code> varies by (verifierAddress, policyId, nonce).
            </p>
          </SubSection>
        </Section>

        <Section title="10-Step Verification Sequence">
          <p className="mb-3 text-sm">
            <Code>verifyAndRegister(policyId, proof, pubSignals, agentId, nonce)</Code> executes all steps atomically.
            Any step failure reverts the entire transaction.
          </p>
          <Table
            headers={['Step', 'Check', 'Reverts With']}
            rows={[
              ['1', 'Policy exists, is active, not expired', 'PolicyNotFound / PolicyInactive / PolicyExpired'],
              ['2', 'pubSignals.length == 6', 'InvalidPublicSignalCount'],
              ['3', 'pubSignals[2] == policy.predicateProgramHash', 'PredicateHashMismatch'],
              ['4', 'pubSignals[5] > block.number', 'ExpiryBlockPassed'],
              ['5', 'credentialAnchor.isMerkleRootCurrent(agentId, credentialType, pubSignals[4])', 'MerkleRootNotCurrent'],
              ['6', 'pubSignals[3] == policy.issuerCommitment', 'IssuerCommitmentMismatch'],
              ['7', 'keccak256(msg.sender ‖ policyId ‖ nonce) == pubSignals[1]', 'ContextHashMismatch'],
              ['8', 'circuitVerifier.verifyProof(proof, pubSignals) == true', 'ProofInvalid'],
              ['9', 'nullifierRegistry.register(nullifier, contextHash, expiryBlock)', 'NullifierAlreadyActive'],
              ['10', 'Emit PresentationAccepted(policyId, nullifier, contextHash, caller, block.number)', '—'],
            ]}
          />
        </Section>

        <Section title="Trust Model">
          <div className="space-y-4">
            <TrustAssumption id="T1" title="Issuer Honesty">
              <p>
                The Issuer issues <Code>AgentCapabilityCredential</Code> only to agents it has independently
                verified. ACTA does NOT enforce that the issuer's certification process is sound.
                The <Code>issuerCommitment</Code> field binds each policy to a specific issuer key.
              </p>
              <p className="mt-2 text-amber-400/80 text-xs">
                Residual risk: a compromised issuer key allows fraudulent credential issuance until the verifier
                updates <Code>issuerCommitment</Code> via a new policy registration.
              </p>
            </TrustAssumption>

            <TrustAssumption id="T2" title="ZK Proof Soundness">
              <p>
                Groth16 over BN254 is computationally sound under the algebraic group model and the
                hardness of the discrete logarithm on BN254. A forged proof without a valid credential
                would break Groth16 soundness.
              </p>
            </TrustAssumption>

            <TrustAssumption id="T3" title="Poseidon Collision Resistance">
              <p>
                The Poseidon hash function (circomlib, BN254) is collision-resistant and second-preimage-resistant
                for commitment and nullifier derivation. Poseidon is newer than SHA-256 and has received less
                cryptanalytic scrutiny. Production deployments SHOULD monitor the literature.
              </p>
            </TrustAssumption>

            <TrustAssumption id="T4" title="Trusted Setup Integrity">
              <p>
                The Groth16 proving key was generated by a Powers of Tau ceremony with at least one honest
                participant. A ceremony participant who retains toxic waste can construct fake proofs for any
                statement. The ceremony transcript MUST be published for public verification.
              </p>
              <p className="mt-2 text-red-400/80 text-xs">
                A single-party setup is equivalent to a trusted oracle and MUST NOT be used in production.
              </p>
            </TrustAssumption>

            <TrustAssumption id="T5" title="ERC-1056 Registry Integrity">
              <p>
                The <Code>EthereumDIDRegistry</Code> contract correctly records DID controller changes.
                A compromised registry could allow an attacker to rotate a DID's verification method
                to a key they control, enabling VP JWT forgery.
              </p>
            </TrustAssumption>
          </div>
        </Section>

        <Section title="Security Properties">
          <div className="space-y-5">
            <SecurityProperty title="Replay Prevention">
              The nullifier is deterministic per (credential, context). Once registered in <Code>NullifierRegistry</Code>,
              any second <Code>register</Code> call reverts with <Code>NullifierAlreadyActive</Code> (Step 9, atomic).
              Verifiers MUST use a fresh unpredictable <Code>nonce</Code> per session.
            </SecurityProperty>

            <SecurityProperty title="Cross-Context Unlinkability">
              Two presentations to different verifiers, or under different policies or nonces, produce
              computationally unlinkable nullifiers. Given <Code>nullifier_1 = Poseidon(s, ctx_1)</Code> and{' '}
              <Code>nullifier_2 = Poseidon(s, ctx_2)</Code> where <Code>ctx_1 ≠ ctx_2</Code>, linking them
              requires a Poseidon preimage — infeasible under T3.
            </SecurityProperty>

            <SecurityProperty title="Front-Running Protection">
              The context hash binds the proof to <Code>msg.sender</Code> (Step 7):
              <CodeBlock className="mt-2">{`expectedContextHash = keccak256(abi.encodePacked(msg.sender, policyId, nonce))`}</CodeBlock>
              A front-runner copying a pending transaction cannot substitute their address — the
              on-chain context hash would diverge from the in-proof value.
            </SecurityProperty>

            <SecurityProperty title="Credential Binding">
              Step 5 calls <Code>credentialAnchor.isMerkleRootCurrent(agentId, credentialType, merkleRoot)</Code>.
              A credential re-anchored with a new Merkle root (e.g., after attribute update) invalidates all
              proofs based on the old root, providing a revocation mechanism.
            </SecurityProperty>

            <SecurityProperty title="Issuer Binding">
              Step 6 checks <Code>pubSignals[3] == policy.issuerCommitment</Code>. This prevents accepting
              proofs generated from credentials issued by a different (potentially attacker-controlled) issuer.
            </SecurityProperty>

            <SecurityProperty title="Policy-Scoped Access Gating">
              Consumer contracts MUST call <Code>isAcceptedForPolicy(nullifier, policyId)</Code>, not the
              policy-agnostic <Code>isAccepted(nullifier)</Code>. A nullifier accepted under a weaker policy
              (e.g., <Code>auditScore ≥ 50</Code>) MUST NOT grant access on a gate configured for a stronger
              policy (e.g., <Code>auditScore ≥ 90</Code>). <Code>GeneralizedPredicateVerifier</Code> tracks
              per-policy acceptances in a separate mapping to enforce this.
            </SecurityProperty>
          </div>
        </Section>

        <Section title="Linkability Analysis">
          <SubSection title="On-Chain Metadata (publicly observable)">
            <ul className="list-disc list-inside space-y-1 text-sm text-gray-400">
              <li><Code>msg.sender</Code> — the verifier's address</li>
              <li><Code>policyId</Code> — reveals which policy was verified</li>
              <li><Code>nullifier</Code> — anonymous but permanent; one per verification context</li>
              <li>Block number, timestamp, gas fee, transaction sender</li>
            </ul>
          </SubSection>
          <SubSection title="Off-Chain Metadata (visible to verifier)">
            <ul className="list-disc list-inside space-y-1 text-sm text-gray-400">
              <li>The holder's <Code>did:ethr</Code> (from VP JWT <Code>iss</Code>)</li>
              <li>VP timing and IP address (if not relayed)</li>
              <li>The six public signals (non-attributable to a real-world identity)</li>
            </ul>
            <p className="mt-2 text-sm">
              Implementations SHOULD route VP submissions through a privacy-preserving relay to prevent
              IP address linkage between the holder and the on-chain transaction.
            </p>
          </SubSection>
        </Section>

        <Section title="Known Limitations">
          <Table
            headers={['ID', 'Limitation', 'Version']}
            rows={[
              ['L1', 'Circuit supports only three predicate types: audit score, capability bitmask, jurisdiction exclusion. No arbitrary boolean logic.', 'v0.1'],
              ['L2', 'AgentCapabilityCredential schema is fixed at 16 attribute slots. New attributes require circuit upgrade and re-anchoring.', 'v0.1'],
              ['L3', 'No device binding. Credential theft allows an attacker to generate valid proofs until issuer revocation.', 'v0.1'],
              ['L4', 'Revocation requires on-chain re-anchoring. No push-revocation mechanism; revoked agent can prove until old Merkle root is superseded.', 'v0.1'],
              ['L5', 'Groth16 requires trusted setup. Unlike transparent proof systems, a compromised ceremony cannot be detected post-hoc.', 'v0.1'],
            ]}
          />
        </Section>

        <Section title="References">
          <ul className="space-y-1.5 text-sm">
            {[
              ['RFC 2119', 'https://www.ietf.org/rfc/rfc2119.txt'],
              ['W3C Verifiable Credentials Data Model 1.1', 'https://www.w3.org/TR/vc-data-model/'],
              ['OpenID for Verifiable Credential Issuance (OID4VCI)', 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html'],
              ['OpenID for Verifiable Presentations (OID4VP)', 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html'],
              ['EIP-1056 — Ethereum DID Registry', 'https://eips.ethereum.org/EIPS/eip-1056'],
              ['Groth16 paper', 'https://eprint.iacr.org/2016/260'],
              ['Poseidon Hash Function', 'https://eprint.iacr.org/2019/458'],
              ['OpenAC (paper)', 'https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf'],
              ['5/ZK-HUMAN-VERIFICATION (related prior art)', 'https://github.com/privacy-ethereum/zkspecs/tree/main/specs/5'],
            ].map(([label, url]) => (
              <li key={label}>
                <a href={url} target="_blank" rel="noreferrer" className="text-brand-400 hover:text-brand-300 hover:underline">
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </Section>

        <div className="mt-12 pt-6 border-t border-gray-700/60 text-center">
          <p className="text-xs text-gray-600">
            Copyright and related rights waived via{' '}
            <a href="https://creativecommons.org/publicdomain/zero/1.0/" className="text-gray-500 hover:text-gray-400">CC0</a>.
          </p>
        </div>
      </div>
    </div>
  )
}

// ── Internal layout primitives ────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="text-lg font-bold text-white mb-4 pb-2 border-b border-gray-700/50">{title}</h2>
      <div className="text-gray-300 text-sm leading-relaxed">{children}</div>
    </section>
  )
}

function SubSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <h3 className="text-sm font-semibold text-gray-200 mb-2">{title}</h3>
      <div className="text-gray-400 text-sm leading-relaxed">{children}</div>
    </div>
  )
}

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="px-1.5 py-0.5 rounded bg-gray-800 text-blue-300 text-xs font-mono border border-gray-700/50">
      {children}
    </code>
  )
}

function CodeBlock({ children, className = '' }: { children: string; className?: string }) {
  return (
    <pre className={`bg-gray-900 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-x-auto border border-gray-700/40 ${className}`}>
      {children}
    </pre>
  )
}

function Table({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="overflow-x-auto mt-3">
      <table className="w-full text-xs border-collapse">
        <thead>
          <tr>
            {headers.map(h => (
              <th key={h} className="text-left px-3 py-2 bg-gray-800/60 text-gray-300 font-semibold border border-gray-700/50 first:rounded-tl last:rounded-tr">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2 text-gray-400 border-x border-gray-700/30 align-top font-mono">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TrustAssumption({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <div className="p-4 rounded-lg border border-gray-700/50 bg-gray-900/40">
      <div className="flex items-center gap-2 mb-2">
        <span className="px-2 py-0.5 rounded bg-amber-900/40 text-amber-400 text-xs font-mono font-bold border border-amber-700/40">
          {id}
        </span>
        <span className="text-sm font-semibold text-gray-200">{title}</span>
      </div>
      <div className="text-xs text-gray-400 leading-relaxed">{children}</div>
    </div>
  )
}

function SecurityProperty({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="p-4 rounded-lg border border-teal-700/30 bg-teal-950/20">
      <h4 className="text-sm font-semibold text-teal-300 mb-1.5">✓ {title}</h4>
      <div className="text-xs text-gray-400 leading-relaxed">{children}</div>
    </div>
  )
}
