import { useSimulation } from '../../simulation/SimulationEngine'

export default function Step6Policy() {
  const { state } = useSimulation()

  const policyDescriptor = {
    verifier:             state.actors.verifier.address,
    predicateProgramHash: state.predicateProgramHash,
    credentialType:       '0x' + Array.from(new TextEncoder().encode('AgentCapabilityCredential')).map(b => b.toString(16).padStart(2, '0')).join('').padEnd(64, '0').slice(0, 64),
    circuitId:            '0x' + Array.from(new TextEncoder().encode('OpenACGPPresentation.v1')).map(b => b.toString(16).padStart(2, '0')).join('').padEnd(64, '0').slice(0, 64),
    expiryBlock:          0,
    issuerCommitment:     state.publicSignals.issuerPubKeyCommitment,
    active:               true,
  }

  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 6 — Verifier Registers Policy On-Chain</h2>
        <p className="text-sm text-gray-400">The predicate is permanently recorded in GeneralizedPredicateVerifier. Any agent that wants to interact must satisfy this policy.</p>
      </div>

      <div className="p-3 rounded-lg bg-teal-900/20 border border-teal-700/40 text-xs text-teal-300">
        <strong>Plain language:</strong> The protocol locks its requirements on-chain. These can't be changed retroactively — agents can trust that the rules won't shift after they generate a proof.
      </div>

      <div className="card p-4">
        <h3 className="text-xs font-semibold text-gray-300 mb-2">PolicyDescriptor</h3>
        <div className="code-block">
          <pre className="text-[11px] text-gray-300">{JSON.stringify(policyDescriptor, null, 2)}</pre>
        </div>
      </div>

      <div className="card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-gray-300">Generated policyId</span>
          <span className="badge-green">PolicyRegistered event</span>
        </div>
        <div className="bg-gray-900/60 rounded-lg p-3">
          <p className="font-mono text-[11px] text-amber-300 break-all">{state.policyId}</p>
          <p className="text-[10px] text-gray-500 mt-1.5">
            = keccak256(verifier || predicateProgramHash || credentialType || circuitId || expiryBlock || issuerCommitment)
          </p>
        </div>
        <div className="text-xs text-gray-500">
          Simulated tx: <span className="font-mono text-gray-400">{state.policyTxHash.slice(0, 26)}…</span>
        </div>
      </div>

      <div className="card p-4">
        <h4 className="text-xs font-semibold text-gray-300 mb-2">Security properties</h4>
        <ul className="text-xs text-gray-400 space-y-1.5">
          <li>• <code className="text-blue-400">deactivatePolicy()</code> can be called to turn off a policy — but existing verified nullifiers remain valid</li>
          <li>• <code className="text-blue-400">issuerCommitment</code> binds the policy to a specific trusted issuer — prevents accepting proofs from unauthorised issuers</li>
          <li>• <code className="text-blue-400">circuitId</code> binds the policy to a specific ZK circuit — prevents accepting proofs from different circuits</li>
        </ul>
      </div>
    </div>
  )
}
