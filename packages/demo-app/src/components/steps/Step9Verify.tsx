import { motion, AnimatePresence } from 'framer-motion'
import { Check, Circle, Loader2 } from 'lucide-react'
import { useSimulation } from '../../simulation/SimulationEngine'

const STEP_ICONS: Record<string, JSX.Element> = {
  pending: <Circle size={14} className="text-gray-600" />,
  running: <Loader2 size={14} className="text-brand-400 animate-spin" />,
  done:    <Check size={14} className="text-green-400" />,
}

export default function Step9Verify() {
  const { state, runVerificationSteps } = useSimulation()
  const allDone = state.verificationSteps.every(s => s.status === 'done')
  const anyDone = state.verificationSteps.some(s => s.status === 'done')

  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 9 — Verifier Verifies (Off-chain + On-chain)</h2>
        <p className="text-sm text-gray-400">Two-phase verification: fast off-chain pre-flight, then atomic on-chain commitment with the 10-step sequence.</p>
      </div>

      <div className="p-3 rounded-lg bg-teal-900/20 border border-teal-700/40 text-xs text-teal-300">
        <strong>Plain language:</strong> The protocol verified the proof both privately and publicly. The on-chain result is permanent — anyone can verify it happened.
      </div>

      {/* Phase 1: Off-chain */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-semibold text-gray-300">Phase 1: Off-chain Verification</h3>
          {anyDone && <span className="badge-green text-[10px]">✓ Passed (~0.05s)</span>}
        </div>
        <div className="text-xs text-gray-400 space-y-1">
          <p>→ OpenAC SDK verifies ZK proof locally</p>
          <p>→ issuerPubKeyCommitment checked against resolved did:ethr document</p>
          <p>→ VP JWT iss claim verified against holderDid</p>
          <p>→ expiryBlock checked against current block number</p>
        </div>
      </div>

      {/* Phase 2: On-chain */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-semibold text-gray-300">Phase 2: On-chain — 10-Step Sequence</h3>
          {!anyDone && (
            <button onClick={runVerificationSteps} className="btn-primary text-xs px-3 py-1.5">
              Run Verification
            </button>
          )}
          {allDone && <span className="badge-green text-[10px]">All 10 steps ✓</span>}
        </div>

        <div className="space-y-1.5">
          {state.verificationSteps.map((step, i) => (
            <motion.div
              key={i}
              className={`flex items-start gap-3 p-2 rounded-lg transition-colors ${
                step.status === 'done'
                  ? 'bg-green-950/30 border border-green-800/40'
                  : 'bg-gray-900/40 border border-gray-800/30'
              }`}
              animate={step.status === 'done' ? { opacity: 1 } : { opacity: step.status === 'pending' ? 0.5 : 1 }}
            >
              <div className="flex-shrink-0 mt-0.5">
                {STEP_ICONS[step.status]}
              </div>
              <div>
                <p className={`text-xs font-medium ${step.status === 'done' ? 'text-green-300' : 'text-gray-400'}`}>
                  {i + 1}. {step.label}
                </p>
                <p className="text-[10px] text-gray-600">{step.detail}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* PresentationAccepted event */}
      <AnimatePresence>
        {allDone && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="card p-4 border-green-500/30 bg-green-950/20"
          >
            <div className="flex items-center gap-2 mb-2">
              <span className="text-green-400 text-sm">✓</span>
              <span className="text-sm font-semibold text-green-300">PresentationAccepted</span>
              <span className="ml-auto font-mono text-[10px] text-gray-500">
                tx: {state.verificationTxHash.slice(0, 22)}…
              </span>
            </div>
            <div className="code-block">
              <pre className="text-[10px] text-gray-300">{`event PresentationAccepted(
  policyId:    ${state.policyId.slice(0, 18)}…,
  nullifier:   ${state.nullifier.slice(0, 18)}…,
  contextHash: ${state.publicSignals.contextHash.slice(0, 18)}…,
  verifier:    ${state.actors.verifier.address},
  blockNumber: 12456789
)`}</pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
