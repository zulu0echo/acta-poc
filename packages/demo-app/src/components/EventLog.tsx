import { useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Terminal } from 'lucide-react'
import { useSimulation } from '../simulation/SimulationEngine'

const SEVERITY_STYLES: Record<string, string> = {
  info:    'text-blue-400',
  success: 'text-green-400',
  warning: 'text-amber-400',
  error:   'text-red-400',
}

const SEVERITY_PREFIX: Record<string, string> = {
  info:    '●',
  success: '✓',
  warning: '⚠',
  error:   '✗',
}

const ACTOR_BADGE: Record<string, string> = {
  issuer:   'badge-blue',
  holder:   'badge-purple',
  verifier: 'badge-green',
  contract: 'badge-amber',
  system:   'text-gray-500',
}

function formatTime(ts: number): string {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
    '.' + d.getMilliseconds().toString().padStart(3, '0')
}

export default function EventLog() {
  const { state } = useSimulation()
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [state.eventLog])

  return (
    <div className="h-full flex flex-col bg-dark-900">
      <div className="flex items-center gap-2 px-4 py-1.5 border-b border-gray-700/60 flex-shrink-0">
        <Terminal size={13} className="text-gray-400" />
        <span className="text-xs font-medium text-gray-300">Live Event Log</span>
        <span className="ml-auto text-[10px] text-gray-500">{state.eventLog.length} events</span>
      </div>
      <div className="flex-1 overflow-y-auto px-4 py-2 space-y-0.5 font-mono">
        <AnimatePresence initial={false}>
          {state.eventLog.map(entry => (
            <motion.div
              key={entry.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.15 }}
              className="flex items-start gap-3 text-[11px] py-0.5"
            >
              <span className="text-gray-600 flex-shrink-0">{formatTime(entry.timestamp)}</span>
              <span className={`flex-shrink-0 ${SEVERITY_STYLES[entry.severity]}`}>
                {SEVERITY_PREFIX[entry.severity]}
              </span>
              <span className={`flex-shrink-0 ${ACTOR_BADGE[entry.actor] ?? 'text-gray-400'}`}>
                [{entry.actor}]
              </span>
              <span className={SEVERITY_STYLES[entry.severity]}>{entry.message}</span>
              {entry.detail && (
                <span className="text-gray-500 truncate">{entry.detail}</span>
              )}
              {entry.txHash && (
                <span className="text-gray-600 font-mono">
                  tx: {entry.txHash.slice(0, 12)}…
                </span>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
