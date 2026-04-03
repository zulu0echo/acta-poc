import { motion } from 'framer-motion'
import { useSimulation } from '../../simulation/SimulationEngine'

const ROLE_COLORS = {
  issuer:   { border: 'border-blue-500/50',   bg: 'bg-blue-950/30',   badge: 'badge-blue',   icon: '🏛️', tagline: 'Signs credentials' },
  holder:   { border: 'border-purple-500/50', bg: 'bg-purple-950/30', badge: 'badge-purple', icon: '🤖', tagline: 'Carries credentials' },
  verifier: { border: 'border-teal-500/50',   bg: 'bg-teal-950/30',   badge: 'badge-green',  icon: '🔍', tagline: 'Checks compliance' },
}

export default function Step1Actors() {
  const { state } = useSimulation()
  const { actors } = state

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 1 — Actors are Created</h2>
        <p className="text-sm text-gray-400">Three independent parties, each with a unique did:ethr identity on Base Sepolia.</p>
      </div>

      <div className="p-3 rounded-lg bg-brand-900/20 border border-brand-700/40 text-xs text-blue-300">
        <strong>Plain language:</strong> Think of these like three parties in a business deal: the certifier (Issuer), the AI agent (Holder), and the protocol checking compliance (Verifier). Each has a permanent, cryptographically-verifiable identity.
      </div>

      <div className="grid gap-4">
        {Object.entries(actors).map(([key, actor], i) => {
          const colors = ROLE_COLORS[key as keyof typeof ROLE_COLORS]
          return (
            <motion.div
              key={key}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.15 }}
              className={`card p-4 ${colors.border} ${colors.bg}`}
            >
              <div className="flex items-start gap-4">
                <div className="text-2xl flex-shrink-0">{colors.icon}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-sm font-semibold text-white">{actor.label}</h3>
                    <span className={colors.badge}>{actor.role}</span>
                    <span className="text-[10px] text-gray-500 ml-auto">{colors.tagline}</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">{actor.description}</p>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-gray-900/60 rounded p-2">
                      <p className="text-[10px] text-gray-500 mb-0.5">DID</p>
                      <p className="font-mono text-[11px] text-gray-300 break-all">{actor.did}</p>
                    </div>
                    <div className="bg-gray-900/60 rounded p-2">
                      <p className="text-[10px] text-gray-500 mb-0.5">Ethereum Address</p>
                      <p className="font-mono text-[11px] text-gray-300 break-all">{actor.address}</p>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )
        })}
      </div>

      <div className="card p-4">
        <h4 className="text-xs font-semibold text-gray-300 mb-2">DID Format Explained</h4>
        <div className="font-mono text-xs">
          <span className="text-gray-500">did:</span>
          <span className="text-blue-400">ethr</span>
          <span className="text-gray-500">:</span>
          <span className="text-amber-400">0x14f69</span>
          <span className="text-gray-500">:</span>
          <span className="text-green-400">0x{actors.issuer.address.slice(2)}</span>
        </div>
        <div className="grid grid-cols-3 gap-2 mt-2 text-[10px] text-gray-500">
          <div><span className="text-blue-400">ethr</span> = DID method (Ethereum)</div>
          <div><span className="text-amber-400">0x14f69</span> = Base Sepolia chainId</div>
          <div><span className="text-green-400">0x…</span> = Ethereum address</div>
        </div>
      </div>
    </div>
  )
}
