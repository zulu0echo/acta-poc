import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Trash2, ChevronDown } from 'lucide-react'
import { useSimulation, type SimulatedPredicateCondition } from '../simulation/SimulationEngine'

const ATTRIBUTES = [
  { id: 'auditScore',           label: 'Audit Score',       type: 'number',   operators: ['≥', '≤', '='] },
  { id: 'capabilities',         label: 'Capabilities',      type: 'array',    operators: ['includes', 'not includes'] },
  { id: 'operatorJurisdiction', label: 'Jurisdiction',      type: 'string',   operators: ['=', '≠', 'NOT IN'] },
  { id: 'modelHash',            label: 'Model Hash',        type: 'string',   operators: ['=', '≠'] },
  { id: 'delegationDepth',      label: 'Delegation Depth',  type: 'number',   operators: ['≤', '='] },
]

const CAPABILITY_OPTIONS = ['evm-execution', 'risk-assessment', 'medical-analysis', 'kyc-verification', 'data-oracle']
const JURISDICTION_OPTIONS = ['US', 'GB', 'DE', 'FR', 'JP', 'SG', 'IR', 'KP', 'RU', 'BY']

function hashPredicate(conditions: SimulatedPredicateCondition[]): string {
  const str = JSON.stringify(conditions)
  let h = 5381
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) + h + str.charCodeAt(i)) & 0xffffffff
  }
  return '0x' + Math.abs(h).toString(16).padStart(8, '0') + 'deadbeef'.repeat(7).slice(0, 56)
}

function describeConditions(conditions: SimulatedPredicateCondition[]): string {
  return conditions.map(c => {
    if (Array.isArray(c.value)) return `${c.attribute} ${c.operator} [${(c.value as string[]).join(', ')}]`
    return `${c.attribute} ${c.operator} "${c.value}"`
  }).join(' AND ')
}

export default function PredicateEditor() {
  const { state, updatePredicateConditions, addEvent } = useSimulation()
  const [conditions, setConditions] = useState<SimulatedPredicateCondition[]>(state.predicateConditions)
  const [showJSON, setShowJSON] = useState(false)

  const predicateHash = hashPredicate(conditions)
  const description = describeConditions(conditions)

  function updateCondition(index: number, updates: Partial<SimulatedPredicateCondition>) {
    const next = conditions.map((c, i) => i === index ? { ...c, ...updates } : c)
    setConditions(next)
    updatePredicateConditions(next)
  }

  function addCondition() {
    const next = [...conditions, { attribute: 'auditScore', operator: '≥', value: 80 }]
    setConditions(next)
    updatePredicateConditions(next)
  }

  function removeCondition(index: number) {
    const next = conditions.filter((_, i) => i !== index)
    setConditions(next)
    updatePredicateConditions(next)
  }

  const attr = (id: string) => ATTRIBUTES.find(a => a.id === id)

  return (
    <div className="space-y-4">
      {/* Condition list */}
      <div className="space-y-2">
        <AnimatePresence>
          {conditions.map((cond, idx) => {
            const attrDef = attr(cond.attribute)
            return (
              <motion.div
                key={idx}
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-2 p-2.5 bg-gray-900/60 rounded-lg border border-gray-700/50"
              >
                {idx > 0 && (
                  <span className="text-xs font-bold text-brand-400 w-8 flex-shrink-0">AND</span>
                )}
                {idx === 0 && <span className="w-8 flex-shrink-0" />}

                {/* Attribute selector */}
                <div className="relative flex-shrink-0">
                  <select
                    value={cond.attribute}
                    onChange={e => updateCondition(idx, { attribute: e.target.value, value: '' })}
                    className="appearance-none bg-gray-800 border border-gray-600 text-gray-200 text-xs rounded px-2 py-1.5 pr-6 focus:outline-none focus:border-brand-500"
                  >
                    {ATTRIBUTES.map(a => (
                      <option key={a.id} value={a.id}>{a.label}</option>
                    ))}
                  </select>
                  <ChevronDown size={10} className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
                </div>

                {/* Operator selector */}
                <div className="relative flex-shrink-0">
                  <select
                    value={cond.operator}
                    onChange={e => updateCondition(idx, { operator: e.target.value })}
                    className="appearance-none bg-gray-800 border border-gray-600 text-blue-300 text-xs rounded px-2 py-1.5 pr-6 focus:outline-none focus:border-brand-500 font-mono"
                  >
                    {(attrDef?.operators ?? ['=', '≥', '≤']).map(op => (
                      <option key={op} value={op}>{op}</option>
                    ))}
                  </select>
                  <ChevronDown size={10} className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
                </div>

                {/* Value input — type-adaptive */}
                {attrDef?.type === 'number' && (
                  <input
                    type="number"
                    value={cond.value as number}
                    onChange={e => updateCondition(idx, { value: Number(e.target.value) })}
                    className="w-20 bg-gray-800 border border-gray-600 text-yellow-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-brand-500 font-mono"
                    min={0} max={100}
                  />
                )}
                {attrDef?.type === 'array' && (
                  <select
                    value={cond.value as string}
                    onChange={e => updateCondition(idx, { value: e.target.value })}
                    className="appearance-none bg-gray-800 border border-gray-600 text-green-300 text-xs rounded px-2 py-1.5 pr-6 focus:outline-none focus:border-brand-500"
                  >
                    {CAPABILITY_OPTIONS.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                  </select>
                )}
                {attrDef?.type === 'string' && cond.operator !== 'NOT IN' && (
                  <input
                    type="text"
                    value={cond.value as string}
                    onChange={e => updateCondition(idx, { value: e.target.value })}
                    className="w-24 bg-gray-800 border border-gray-600 text-green-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-brand-500 font-mono"
                  />
                )}
                {attrDef?.type === 'string' && cond.operator === 'NOT IN' && (
                  <div className="flex flex-wrap gap-1">
                    {JURISDICTION_OPTIONS.filter(j => ['IR','KP','RU','BY'].includes(j)).map(j => {
                      const selected = Array.isArray(cond.value) ? (cond.value as string[]).includes(j) : false
                      return (
                        <button
                          key={j}
                          onClick={() => {
                            const curr = Array.isArray(cond.value) ? cond.value as string[] : []
                            const next = selected ? curr.filter(x => x !== j) : [...curr, j]
                            updateCondition(idx, { value: next })
                          }}
                          className={`text-[10px] px-1.5 py-0.5 rounded font-mono transition-colors ${selected ? 'bg-red-800 text-red-200 border border-red-600' : 'bg-gray-700 text-gray-400 border border-gray-600'}`}
                        >
                          {j}
                        </button>
                      )
                    })}
                  </div>
                )}

                <button
                  onClick={() => removeCondition(idx)}
                  className="ml-auto text-gray-600 hover:text-red-400 transition-colors flex-shrink-0"
                  disabled={conditions.length <= 1}
                >
                  <Trash2 size={13} />
                </button>
              </motion.div>
            )
          })}
        </AnimatePresence>
      </div>

      <button onClick={addCondition} className="btn-ghost text-xs w-full justify-center border border-dashed border-gray-700 py-2">
        <Plus size={13} />
        Add condition
      </button>

      {/* Live preview */}
      <div className="space-y-2 p-3 bg-gray-900/40 rounded-lg border border-gray-700/50">
        <div className="flex justify-between items-start gap-2">
          <div>
            <p className="text-[10px] text-gray-500 mb-0.5">Human-readable</p>
            <p className="text-xs text-gray-300">{description}</p>
          </div>
        </div>
        <div>
          <p className="text-[10px] text-gray-500 mb-0.5">predicateProgramHash</p>
          <p className="font-mono text-[11px] text-amber-300 break-all">{predicateHash}</p>
        </div>
      </div>

      <div>
        <button onClick={() => setShowJSON(!showJSON)} className="btn-ghost text-xs">
          {showJSON ? 'Hide' : 'Show'} generated JSON
        </button>
        {showJSON && (
          <div className="code-block mt-2">
            <pre className="text-[10px] text-gray-300">
              {JSON.stringify({
                schemaId: 'AgentCapabilityCredential',
                version: 1,
                root: conditions.length === 1
                  ? { type: 'condition', condition: conditions[0] }
                  : { type: 'logical', connective: 'AND', children: conditions.map(c => ({ type: 'condition', condition: c })) }
              }, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}
