import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import { useSimulation } from '../simulation/SimulationEngine'

function JsonHighlight({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const indent = '  '.repeat(depth)

  if (value === null) return <span className="json-null">null</span>
  if (typeof value === 'boolean') return <span className="json-bool">{String(value)}</span>
  if (typeof value === 'number') return <span className="json-number">{value}</span>
  if (typeof value === 'string') return <span className="json-string">"{value}"</span>
  if (Array.isArray(value)) {
    return (
      <>
        {'['}
        {value.map((v, i) => (
          <span key={i}>
            {'\n' + indent + '  '}
            <JsonHighlight value={v} depth={depth + 1} />
            {i < value.length - 1 ? ',' : ''}
          </span>
        ))}
        {'\n' + indent + ']'}
      </>
    )
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
    return (
      <>
        {'{'}
        {entries.map(([k, v], i) => (
          <span key={k}>
            {'\n' + indent + '  '}
            <span className="json-key">"{k}"</span>
            {': '}
            <JsonHighlight value={v} depth={depth + 1} />
            {i < entries.length - 1 ? ',' : ''}
          </span>
        ))}
        {'\n' + indent + '}'}
      </>
    )
  }
  return <span>{String(value)}</span>
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="btn-ghost p-1"
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
    >
      {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
    </button>
  )
}

export default function CredentialViewer() {
  const { state } = useSimulation()
  const [activeTab, setActiveTab] = useState<'header' | 'payload' | 'signature' | 'raw'>('payload')
  const [expandedField, setExpandedField] = useState<string | null>(null)

  const tabs = [
    { id: 'header',    label: 'Header' },
    { id: 'payload',   label: 'Payload' },
    { id: 'signature', label: 'Signature' },
    { id: 'raw',       label: 'Raw JWT' },
  ] as const

  return (
    <div className="card overflow-hidden">
      <div className="flex border-b border-gray-700/60">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex-1 px-3 py-2 text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? 'text-brand-400 border-b-2 border-brand-500 bg-brand-950/20'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.1 }}
          className="p-4"
        >
          {activeTab === 'header' && (
            <div className="code-block">
              <pre className="text-xs leading-relaxed">
                <JsonHighlight value={state.jwtHeader} />
              </pre>
            </div>
          )}

          {activeTab === 'payload' && (
            <div className="space-y-2">
              {/* Credential subject fields — highlighted */}
              {Object.entries(state.jwtPayload.vc
                ? (state.jwtPayload.vc as Record<string, unknown>).credentialSubject as Record<string, unknown>
                : {}
              ).map(([key, value]) => (
                <div
                  key={key}
                  className="flex items-start gap-3 p-2 bg-gray-900/50 rounded-lg cursor-pointer hover:bg-gray-800/50 transition-colors"
                  onClick={() => setExpandedField(expandedField === key ? null : key)}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-blue-400 text-xs font-mono">{key}</span>
                      <span className="text-gray-500 text-xs">·</span>
                      <span className="text-yellow-400 text-xs font-mono">
                        {Array.isArray(value) ? `[${(value as string[]).join(', ')}]` : String(value)}
                      </span>
                    </div>
                    {expandedField === key && (
                      <div className="mt-1 text-[10px] text-gray-500">
                        {getFieldExplanation(key)}
                      </div>
                    )}
                  </div>
                  {expandedField === key ? <ChevronDown size={12} className="text-gray-500 flex-shrink-0 mt-0.5" /> : <ChevronRight size={12} className="text-gray-500 flex-shrink-0 mt-0.5" />}
                </div>
              ))}
            </div>
          )}

          {activeTab === 'signature' && (
            <div className="space-y-3">
              <div className="code-block">
                <div className="text-green-400 text-xs mb-1">// ES256K signature (secp256k1)</div>
                <div className="text-gray-300 break-all text-[11px]">{state.jwtVc.split('.')[2]}</div>
              </div>
              <div className="text-xs text-gray-400 space-y-1">
                <p><span className="text-gray-300">Algorithm:</span> ES256K (secp256k1, Ethereum native)</p>
                <p><span className="text-gray-300">Signing key:</span> Issuer's did:ethr private key</p>
                <p><span className="text-gray-300">Verifiable via:</span> ethr-did-resolver (resolves public key from ERC-1056)</p>
              </div>
            </div>
          )}

          {activeTab === 'raw' && (
            <div className="relative">
              <div className="absolute top-2 right-2">
                <CopyButton text={state.jwtVc} />
              </div>
              <div className="code-block">
                <div className="break-all text-[10px] leading-relaxed">
                  <span className="text-red-400">{state.jwtVc.split('.')[0]}</span>
                  <span className="text-gray-400">.</span>
                  <span className="text-blue-400">{state.jwtVc.split('.')[1]}</span>
                  <span className="text-gray-400">.</span>
                  <span className="text-green-400">{state.jwtVc.split('.')[2]}</span>
                </div>
              </div>
              <p className="text-[10px] text-gray-500 mt-2">
                Red = header · Blue = payload · Green = signature
              </p>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

function getFieldExplanation(field: string): string {
  const explanations: Record<string, string> = {
    id:                   'The holder\'s did:ethr DID — their verifiable Ethereum identity',
    auditScore:           'Audit compliance score from 0–100. ZK proof can prove this is ≥ a threshold without revealing the exact value.',
    modelHash:            'keccak256 of the AI model binary. Proves the exact model version without revealing the model.',
    operatorJurisdiction: 'ISO 3166-1 alpha-2 jurisdiction code. ZK proof can prove this is not in a sanctions list.',
    capabilities:         'Bitmask of permitted operations. ZK proof can prove specific bits are set without revealing the full mask.',
    auditedBy:            'DID of the auditing entity. Kept private in ZK — only issuerPubKeyCommitment is revealed.',
    auditDate:            'Date of the audit. Can be used to prove recency without revealing the exact date.',
  }
  return explanations[field] ?? 'Credential subject field'
}
