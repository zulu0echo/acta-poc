import { useSimulation } from '../../simulation/SimulationEngine'

export default function Step2Schema() {
  const { state, updateCredentialValues } = useSimulation()
  const { credentialValues } = state

  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 2 — Issuer Configures Credential Schema</h2>
        <p className="text-sm text-gray-400">These values will be signed into the AgentCapabilityCredential. You can edit them — they flow through the rest of the simulation.</p>
      </div>

      <div className="p-3 rounded-lg bg-blue-900/20 border border-blue-700/40 text-xs text-blue-300">
        <strong>Plain language:</strong> This is the "form" the certifier fills out about the AI agent — like an audit report. The field values will be kept private, but ZK proofs can answer yes/no questions about them.
      </div>

      <div className="card p-4 space-y-3">
        <h3 className="text-sm font-semibold text-gray-200">AgentCapabilityCredential Fields</h3>

        <div className="grid gap-3">
          <div className="flex items-center gap-3">
            <label className="text-xs text-gray-400 w-36 flex-shrink-0">Audit Score (0–100)</label>
            <div className="flex-1 flex items-center gap-3">
              <input
                type="range" min={0} max={100}
                value={credentialValues.auditScore}
                onChange={e => updateCredentialValues({ auditScore: Number(e.target.value) })}
                className="flex-1 accent-brand-500"
              />
              <span className="font-mono text-sm font-bold text-yellow-400 w-8 text-right">
                {credentialValues.auditScore}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs text-gray-400 w-36 flex-shrink-0">Jurisdiction</label>
            <select
              value={credentialValues.operatorJurisdiction}
              onChange={e => updateCredentialValues({ operatorJurisdiction: e.target.value })}
              className="bg-gray-800 border border-gray-600 text-gray-200 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-brand-500"
            >
              {['US', 'GB', 'DE', 'FR', 'JP', 'SG', 'AU', 'CA'].map(j =>
                <option key={j} value={j}>{j}</option>
              )}
            </select>
          </div>

          <div className="flex items-start gap-3">
            <label className="text-xs text-gray-400 w-36 flex-shrink-0 pt-1">Capabilities</label>
            <div className="flex flex-wrap gap-2">
              {['evm-execution', 'risk-assessment', 'medical-analysis', 'kyc-verification', 'data-oracle'].map(cap => {
                const selected = credentialValues.capabilities.includes(cap)
                return (
                  <button
                    key={cap}
                    onClick={() => updateCredentialValues({
                      capabilities: selected
                        ? credentialValues.capabilities.filter(c => c !== cap)
                        : [...credentialValues.capabilities, cap]
                    })}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                      selected ? 'bg-purple-800 border-purple-600 text-purple-200' : 'bg-gray-800 border-gray-600 text-gray-400'
                    }`}
                  >
                    {cap}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs text-gray-400 w-36 flex-shrink-0">Model Hash</label>
            <span className="font-mono text-xs text-gray-500 truncate">{credentialValues.modelHash}</span>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs text-gray-400 w-36 flex-shrink-0">Audit Date</label>
            <span className="font-mono text-xs text-gray-300">{credentialValues.auditDate}</span>
          </div>
        </div>
      </div>

      <div className="card p-4">
        <h4 className="text-xs font-semibold text-gray-300 mb-2">JSON-LD Context (published at issuer)</h4>
        <div className="code-block">
          <pre className="text-[10px] text-gray-400">{`{
  "@context": {
    "acta": "https://acta.ethereum.org/vocab#",
    "AgentCapabilityCredential": "acta:AgentCapabilityCredential",
    "auditScore": { "@id": "acta:auditScore", "@type": "xsd:integer" },
    "modelHash": { "@id": "acta:modelHash" },
    "operatorJurisdiction": { "@id": "acta:operatorJurisdiction" },
    "capabilities": { "@id": "acta:capabilities", "@container": "@set" }
  }
}`}</pre>
        </div>
      </div>
    </div>
  )
}
