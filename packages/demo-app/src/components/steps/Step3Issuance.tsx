import { useState } from 'react'
import { motion } from 'framer-motion'
import { useSimulation } from '../../simulation/SimulationEngine'
import CredentialViewer from '../CredentialViewer'
import { generateOID4VCITrace } from '../../simulation/mockIssuer'

export default function Step3Issuance() {
  const { state } = useSimulation()
  const [showTrace, setShowTrace] = useState(false)
  const trace = generateOID4VCITrace(
    state.actors.issuer.did,
    state.actors.holder.did,
    state.credentialValues
  )

  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 3 — Credential Issued (OID4VCI)</h2>
        <p className="text-sm text-gray-400">The Issuer signed a JWT-VC and delivered it to the Agent via the OpenID for Verifiable Credential Issuance protocol.</p>
      </div>

      <div className="p-3 rounded-lg bg-blue-900/20 border border-blue-700/40 text-xs text-blue-300">
        <strong>Plain language:</strong> The certifier has signed a digital certificate for the agent. Like a PDF diploma, but cryptographically verifiable and signed by an on-chain identity.
      </div>

      {/* Animated issuance flow */}
      <div className="flex items-center justify-between p-4 card">
        <div className="text-center">
          <div className="text-2xl mb-1">🏛️</div>
          <div className="text-xs text-blue-300">Issuer</div>
          <div className="text-[10px] text-gray-500">{state.actors.issuer.did.slice(0, 24)}…</div>
        </div>
        <div className="flex-1 flex flex-col items-center mx-4">
          <motion.div
            initial={{ x: -40, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.8, type: 'spring' }}
            className="w-8 h-8 bg-brand-600 rounded-full flex items-center justify-center text-white text-sm mb-1"
          >
            📜
          </motion.div>
          <div className="h-px w-full bg-gradient-to-r from-blue-500 to-purple-500" />
          <div className="text-[10px] text-gray-500 mt-1">JWT-VC (ES256K signed)</div>
        </div>
        <div className="text-center">
          <div className="text-2xl mb-1">🤖</div>
          <div className="text-xs text-purple-300">Agent</div>
          <div className="text-[10px] text-gray-500">{state.actors.holder.did.slice(0, 24)}…</div>
        </div>
      </div>

      <CredentialViewer />

      {/* OID4VCI Protocol Trace */}
      <div>
        <button onClick={() => setShowTrace(!showTrace)} className="btn-ghost text-xs mb-2">
          {showTrace ? '▼' : '▶'} OID4VCI Protocol Messages
        </button>
        {showTrace && (
          <div className="code-block space-y-3">
            {Object.entries(trace).map(([key, value]) => (
              <div key={key}>
                <div className="text-gray-500 text-[10px] mb-1">// {key}</div>
                <pre className="text-[10px] text-gray-300 whitespace-pre-wrap">
                  {JSON.stringify(value, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
