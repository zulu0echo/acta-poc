import { motion, AnimatePresence } from 'framer-motion'
import { useSimulation } from '../../simulation/SimulationEngine'
import ProofViewer from '../ProofViewer'
import { Zap } from 'lucide-react'

export default function Step8Proof() {
  const { state, runProofGeneration } = useSimulation()

  return (
    <div className="space-y-5 max-w-3xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 8 — Holder Generates ZK Proof</h2>
        <p className="text-sm text-gray-400">The Agent proves it satisfies the predicate — without revealing its actual credential values. This is the core privacy guarantee of ACTA.</p>
      </div>

      <div className="p-3 rounded-lg bg-purple-900/20 border border-purple-700/40 text-xs text-purple-300">
        <strong>Plain language:</strong> The agent generates a mathematical proof that says "I satisfy your requirements" without revealing HOW it satisfies them — like proving you're old enough to enter a venue without showing your ID.
      </div>

      {/* Proof generation button */}
      {!state.proofGenerating && state.proofProgress === 0 && (
        <button onClick={runProofGeneration} className="btn-primary gap-2">
          <Zap size={14} />
          Generate ZK Proof (simulated ~0.13s)
        </button>
      )}

      {/* Progress bar */}
      <AnimatePresence>
        {(state.proofGenerating || state.proofProgress > 0) && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-gray-300">
                {state.proofGenerating ? 'Generating Groth16 proof…' : `Proof generated in ${state.proofTimeMs}ms ✓`}
              </span>
              <span className="text-xs font-mono text-amber-300">{state.proofProgress}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <motion.div
                className="h-2 bg-gradient-to-r from-purple-600 to-brand-500 rounded-full"
                animate={{ width: `${state.proofProgress}%` }}
                transition={{ duration: 0.1 }}
              />
            </div>
            {state.proofGenerating && (
              <p className="text-[10px] text-gray-500 mt-2">
                Computing Poseidon hashes → witness generation → Groth16 proving…
              </p>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Privacy split panel */}
      {state.proofProgress === 100 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <ProofViewer />
        </motion.div>
      )}

      {state.proofProgress === 0 && (
        <div className="card p-4 border-dashed">
          <h4 className="text-xs font-semibold text-gray-500 mb-2">What will be computed:</h4>
          <div className="grid grid-cols-2 gap-4 text-xs text-gray-500">
            <div>
              <p className="font-medium text-gray-400 mb-1">Private inputs (stay on device)</p>
              <ul className="space-y-0.5">
                <li>• auditScore = {state.credentialValues.auditScore}</li>
                <li>• modelHash = {state.credentialValues.modelHash.slice(0, 18)}…</li>
                <li>• jurisdiction = {state.credentialValues.operatorJurisdiction}</li>
                <li>• capabilities bitmask</li>
                <li>• issuer private key</li>
                <li>• Merkle path proof</li>
              </ul>
            </div>
            <div>
              <p className="font-medium text-gray-400 mb-1">Public outputs (in the proof)</p>
              <ul className="space-y-0.5">
                <li>• nullifier (anonymous ID)</li>
                <li>• contextHash</li>
                <li>• predicateProgramHash</li>
                <li>• issuerPubKeyCommitment</li>
                <li>• credentialMerkleRoot</li>
                <li>• expiryBlock</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
