import { useState } from 'react'
import { motion } from 'framer-motion'
import { useSimulation } from '../../simulation/SimulationEngine'

export default function Step7Request() {
  const { state } = useSimulation()
  const [showFull, setShowFull] = useState(false)

  const request = {
    ...state.presentationRequest,
    nonce: state.policyId.slice(0, 16),
    response_uri: `http://localhost:3003/verify-callback/${state.policyId.slice(0, 16)}`,
    'x-openac-predicate': JSON.stringify({
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'logical',
        connective: 'AND',
        children: state.predicateConditions.map(c => ({ type: 'condition', condition: c })),
      },
      hash: state.predicateProgramHash,
    }),
    'x-openac-policy-id': state.policyId,
    'x-onchain-verifier': '0x' + 'ae'.repeat(20),
  }

  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 7 — Verifier Sends Presentation Request (OID4VP)</h2>
        <p className="text-sm text-gray-400">The Protocol challenges the Agent: "Prove you satisfy this policy." The request is signed with the verifier's did:ethr key.</p>
      </div>

      <div className="p-3 rounded-lg bg-teal-900/20 border border-teal-700/40 text-xs text-teal-300">
        <strong>Plain language:</strong> The protocol sends a challenge to the agent. Like a customs officer saying "prove you have the right paperwork" — but in this case the agent proves it privately.
      </div>

      {/* Animated request flow */}
      <div className="flex items-center justify-between p-4 card">
        <div className="text-center">
          <div className="text-2xl mb-1">🔍</div>
          <div className="text-xs text-teal-300">Protocol</div>
        </div>
        <div className="flex-1 flex flex-col items-center mx-4">
          <motion.div
            initial={{ x: 40, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.8, type: 'spring' }}
            className="text-sm mb-1"
          >
            📋
          </motion.div>
          <div className="h-px w-full bg-gradient-to-r from-teal-500 to-purple-500" />
          <div className="text-[10px] text-gray-500 mt-1">OID4VP Authorization Request</div>
        </div>
        <div className="text-center">
          <div className="text-2xl mb-1">🤖</div>
          <div className="text-xs text-purple-300">Agent</div>
        </div>
      </div>

      <div className="card p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-semibold text-gray-300">Authorization Request</h3>
          <button onClick={() => setShowFull(!showFull)} className="btn-ghost text-xs">
            {showFull ? 'Collapse' : 'Expand all'}
          </button>
        </div>
        <div className="code-block">
          <pre className="text-[10px] text-gray-300 whitespace-pre-wrap">
            {showFull ? JSON.stringify(request, null, 2) : JSON.stringify({
              response_type:    request.response_type,
              client_id:        request['client_id'],
              nonce:            request.nonce,
              'x-openac-policy-id': request['x-openac-policy-id'],
              'x-openac-predicate': '[see expanded view]',
              response_uri:     request.response_uri,
            }, null, 2)}
          </pre>
        </div>
      </div>

      <div className="p-3 bg-amber-900/20 border border-amber-700/30 rounded-lg">
        <h4 className="text-xs font-semibold text-amber-300 mb-1.5">Key security properties of this request</h4>
        <ul className="text-xs text-gray-400 space-y-1">
          <li>• <code className="text-blue-400">client_id</code> = verifier's did:ethr — proves the request is from a known protocol</li>
          <li>• <code className="text-blue-400">nonce</code> — session-specific, prevents request replay</li>
          <li>• <code className="text-blue-400">x-openac-predicate</code> — the exact policy hash the proof must satisfy</li>
        </ul>
      </div>
    </div>
  )
}
