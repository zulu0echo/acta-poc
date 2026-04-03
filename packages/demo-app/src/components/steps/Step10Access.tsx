import { motion, AnimatePresence } from 'framer-motion'
import { Lock, Unlock, AlertTriangle } from 'lucide-react'
import { useSimulation } from '../../simulation/SimulationEngine'
import { generateReplayAttempt } from '../../simulation/mockContracts'

export default function Step10Access() {
  const { state, grantAccess, attemptReplay } = useSimulation()
  const replayData = generateReplayAttempt(state.nullifier)

  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 10 — Smart Contract Acts on Verified Proof</h2>
        <p className="text-sm text-gray-400">The AgentAccessGate contract reads from GeneralizedPredicateVerifier to grant access. Access is one-time and anonymous.</p>
      </div>

      <div className="p-3 rounded-lg bg-green-900/20 border border-green-700/40 text-xs text-green-300">
        <strong>Plain language:</strong> The agent now has access. The same proof cannot be reused — each access is one-time and the agent's real identity is never revealed.
      </div>

      {/* Access grant */}
      <div className="card p-4 space-y-3">
        <h3 className="text-xs font-semibold text-gray-300">AgentAccessGate.grantAccess()</h3>

        {!state.accessGranted ? (
          <button onClick={grantAccess} className="btn-primary gap-2">
            <Unlock size={14} />
            Grant Access
          </button>
        ) : (
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="flex flex-col items-center p-6 bg-green-950/30 border border-green-600/40 rounded-xl"
          >
            <motion.div
              initial={{ rotate: -10 }}
              animate={{ rotate: 0 }}
              transition={{ type: 'spring', stiffness: 200 }}
              className="text-5xl mb-3"
            >
              🔓
            </motion.div>
            <p className="text-lg font-bold text-green-300">Access Granted</p>
            <p className="text-xs text-gray-400 mt-1">isAccessGranted({state.nullifier.slice(0, 18)}…) = true</p>
          </motion.div>
        )}

        {state.accessGranted && (
          <div className="code-block">
            <pre className="text-[10px] text-gray-300">{`// grantAccess(nullifier) called
// gpVerifier.isAccepted(nullifier) == true ✓
// AccessGranted event emitted

emit AccessGranted(
  nullifier: ${state.nullifier.slice(0, 18)}…,
  blockNumber: 12456790
)`}</pre>
          </div>
        )}
      </div>

      {/* isAccessGranted query */}
      {state.accessGranted && (
        <div className="card p-4">
          <h3 className="text-xs font-semibold text-gray-300 mb-2">isAccessGranted(nullifier)</h3>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs text-gray-400">{state.nullifier.slice(0, 30)}…</span>
            <span className="font-mono text-green-400 font-bold">→ true</span>
          </div>
        </div>
      )}

      {/* Replay attack demo */}
      {state.accessGranted && (
        <div className="card p-4 border-amber-500/30">
          <h3 className="text-xs font-semibold text-amber-300 mb-2 flex items-center gap-2">
            <AlertTriangle size={13} />
            Replay Attack Demo
          </h3>
          <p className="text-xs text-gray-400 mb-3">What happens when the same proof is submitted again?</p>

          {!state.replayAttempted ? (
            <button onClick={attemptReplay} className="btn-secondary text-xs gap-2">
              <AlertTriangle size={12} />
              Attempt Replay Attack
            </button>
          ) : (
            <AnimatePresence>
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="space-y-2"
              >
                <div className="code-block border border-red-800/50">
                  <pre className="text-[10px] text-red-400">{JSON.stringify(replayData, null, 2)}</pre>
                </div>
                <div className="flex items-center gap-2">
                  <span className="badge-red">Transaction Reverted</span>
                  <span className="text-xs text-gray-400">NullifierAlreadyActive({state.nullifier.slice(0, 18)}…)</span>
                </div>
                <p className="text-xs text-green-400">✓ Replay attack blocked. The nullifier is registered on-chain — it cannot be reused under any circumstances.</p>
              </motion.div>
            </AnimatePresence>
          )}
        </div>
      )}

      {/* Summary */}
      {state.accessGranted && (
        <div className="card p-4 border-brand-500/30 bg-brand-950/20">
          <h4 className="text-sm font-bold text-white mb-3">🎉 ACTA Flow Complete</h4>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-gray-900/60 p-2 rounded">
              <p className="text-gray-500 mb-0.5">What your protocol received</p>
              <p className="text-green-300">✓ Verified proof</p>
              <p className="text-green-300">✓ On-chain tx hash</p>
              <p className="text-green-300">✓ Anonymous nullifier</p>
            </div>
            <div className="bg-gray-900/60 p-2 rounded">
              <p className="text-gray-500 mb-0.5">What your protocol did NOT receive</p>
              <p className="text-red-400 line-through text-gray-600">Audit score value</p>
              <p className="text-red-400 line-through text-gray-600">Agent identity</p>
              <p className="text-red-400 line-through text-gray-600">Model hash</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
