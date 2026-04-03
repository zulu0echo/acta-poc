import { motion } from 'framer-motion'
import { useSimulation } from '../../simulation/SimulationEngine'
import { generateAnchorTx } from '../../simulation/mockHolder'

export default function Step4Anchor() {
  const { state } = useSimulation()
  const tx = generateAnchorTx(state.actors.holder.address, state.credentialCommitment, state.publicSignals.credentialMerkleRoot)

  return (
    <div className="space-y-5 max-w-2xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Step 4 — Holder Anchors Credential On-Chain</h2>
        <p className="text-sm text-gray-400">The Agent publishes a cryptographic commitment to their credential in the OpenACCredentialAnchor contract, without revealing any credential values.</p>
      </div>

      <div className="p-3 rounded-lg bg-purple-900/20 border border-purple-700/40 text-xs text-purple-300">
        <strong>Plain language:</strong> The agent registers a sealed envelope on-chain. The contents are invisible — only the envelope's fingerprint is public. But its existence is permanently proven.
      </div>

      {/* Commitment display */}
      <div className="card p-4 space-y-3">
        <h3 className="text-xs font-semibold text-gray-300">Credential Commitment</h3>
        <div className="bg-gray-900/60 rounded-lg p-3 border border-amber-700/30">
          <p className="text-[10px] text-amber-400 mb-1">commitment (bytes32)</p>
          <p className="font-mono text-xs text-amber-300 break-all">{state.credentialCommitment}</p>
          <p className="text-[10px] text-gray-500 mt-2">
            = Poseidon(attributeValues[0..15], randomness) — reveals NOTHING about actual values
          </p>
        </div>
        <div className="bg-gray-900/60 rounded-lg p-3 border border-teal-700/30">
          <p className="text-[10px] text-teal-400 mb-1">merkleRoot (bytes32)</p>
          <p className="font-mono text-xs text-teal-300 break-all">{state.publicSignals.credentialMerkleRoot}</p>
          <p className="text-[10px] text-gray-500 mt-2">
            Used in ZK proofs to prove attribute membership without revealing the attribute tree
          </p>
        </div>
      </div>

      {/* Simulated transaction */}
      <div className="card p-4">
        <h3 className="text-xs font-semibold text-gray-300 mb-3">Simulated Transaction</h3>
        <div className="code-block">
          <pre className="text-[11px] text-gray-300 whitespace-pre-wrap">{JSON.stringify(tx, null, 2)}</pre>
        </div>
        <div className="flex items-center gap-3 mt-3">
          <span className="badge-green">CredentialAnchored</span>
          <span className="text-xs text-gray-400">tx: {state.anchorTxHash.slice(0, 22)}…</span>
        </div>
      </div>

      <div className="card p-4">
        <h4 className="text-xs font-semibold text-gray-300 mb-2">Why anchor on-chain?</h4>
        <ul className="text-xs text-gray-400 space-y-1.5">
          <li>• The verifier contract can check the credential is current (not expired/revoked) by calling <code className="text-blue-400">isMerkleRootCurrent()</code></li>
          <li>• The <code className="text-blue-400">agentId = uint256(uint160(holderAddress))</code> links the did:ethr DID to the on-chain commitment</li>
          <li>• <code className="text-blue-400">msg.sender == address(uint160(agentId))</code> is enforced — only the DID controller can anchor</li>
        </ul>
      </div>
    </div>
  )
}
