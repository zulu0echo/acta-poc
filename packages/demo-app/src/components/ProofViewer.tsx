import { motion } from 'framer-motion'
import { Shield, Eye, EyeOff } from 'lucide-react'
import { useSimulation } from '../simulation/SimulationEngine'

export default function ProofViewer() {
  const { state } = useSimulation()
  const { credentialValues, publicSignals } = state

  const knownToHolder = [
    { label: 'Audit Score',    value: String(credentialValues.auditScore),           color: 'text-blue-400',   reveal: false },
    { label: 'Model Hash',     value: credentialValues.modelHash.slice(0, 22) + '…', color: 'text-purple-400', reveal: false },
    { label: 'Jurisdiction',   value: credentialValues.operatorJurisdiction,          color: 'text-teal-400',   reveal: false },
    { label: 'Capabilities',   value: credentialValues.capabilities.join(', '),       color: 'text-green-400',  reveal: false },
    { label: 'Audited By',     value: credentialValues.auditedBy.slice(0, 24) + '…', color: 'text-amber-400',  reveal: false },
    { label: 'Audit Date',     value: credentialValues.auditDate,                     color: 'text-rose-400',   reveal: false },
  ]

  const revealedToVerifier = [
    { label: 'Nullifier',        value: publicSignals.nullifier.slice(0, 22) + '…',        color: 'text-gray-300' },
    { label: 'Predicate Hash',   value: publicSignals.predicateProgramHash.slice(0, 22) + '…', color: 'text-gray-300' },
    { label: 'Expiry Block',     value: String(publicSignals.expiryBlock),                 color: 'text-gray-300' },
    { label: 'Context Hash',     value: publicSignals.contextHash.slice(0, 22) + '…',      color: 'text-gray-300' },
  ]

  return (
    <div className="grid grid-cols-2 gap-4">
      {/* Left: What the agent knows */}
      <div className="card p-4 border-purple-500/30">
        <div className="flex items-center gap-2 mb-3">
          <Eye size={14} className="text-purple-400" />
          <h3 className="text-xs font-semibold text-purple-300">What the Agent Knows</h3>
        </div>
        <p className="text-[10px] text-gray-500 mb-3">Full credential values — private to the holder</p>
        <div className="space-y-2">
          {knownToHolder.map(item => (
            <div key={item.label} className="flex items-center justify-between gap-2 py-1 border-b border-gray-800/60">
              <span className="text-[11px] text-gray-400">{item.label}</span>
              <span className={`text-[11px] font-mono ${item.color}`}>{item.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Privacy shield arrow */}
      <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-10 hidden">
        {/* Positioning handled by flex layout */}
      </div>

      {/* Right: What the proof reveals */}
      <div className="card p-4 border-green-500/30 relative">
        <div className="flex items-center gap-2 mb-3">
          <Shield size={14} className="text-green-400" />
          <h3 className="text-xs font-semibold text-green-300">What the Proof Reveals</h3>
        </div>
        <p className="text-[10px] text-gray-500 mb-3">Only these values leave the holder's device</p>
        <div className="space-y-2">
          {revealedToVerifier.map(item => (
            <div key={item.label} className="flex items-center justify-between gap-2 py-1 border-b border-gray-800/60">
              <span className="text-[11px] text-gray-400">{item.label}</span>
              <span className={`text-[11px] font-mono ${item.color}`}>{item.value}</span>
            </div>
          ))}
        </div>

        {/* "Hidden" fields overlay */}
        <div className="mt-3 p-2 bg-gray-900/80 rounded-lg border border-gray-700/50">
          <div className="flex items-center gap-1.5 mb-1">
            <EyeOff size={11} className="text-gray-500" />
            <span className="text-[10px] text-gray-500">Hidden from verifier:</span>
          </div>
          <p className="text-[10px] text-gray-600">Audit score value · Model hash · Jurisdiction · Capabilities bitmask · Audited-by DID</p>
        </div>
      </div>

      {/* ZK proof bytes */}
      <div className="col-span-2 card p-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-gray-300">Groth16 Proof Bytes (256 bytes)</span>
          <span className="badge-purple text-[10px]">~0.13s generation</span>
        </div>
        <div className="code-block">
          <span className="text-[10px] text-gray-500 break-all">
            {state.zkProof}
          </span>
        </div>
      </div>
    </div>
  )
}
