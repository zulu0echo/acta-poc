import PredicateEditor from '../PredicateEditor'

export default function Step5Predicate() {
  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 5 — Verifier Builds a Predicate</h2>
        <p className="text-sm text-gray-400">The Protocol defines what it requires from agents — without learning anything about agents that don't qualify.</p>
      </div>

      <div className="p-3 rounded-lg bg-teal-900/20 border border-teal-700/40 text-xs text-teal-300">
        <strong>Plain language:</strong> This is like setting hiring criteria — you're not asking for a résumé, you're asking for a yes/no answer. "Does this agent have audit score ≥ 80, evm-execution capability, and operate outside sanctioned countries?"
      </div>

      <div className="card p-4">
        <h3 className="text-xs font-semibold text-gray-300 mb-3">Predicate Editor</h3>
        <PredicateEditor />
      </div>
    </div>
  )
}
