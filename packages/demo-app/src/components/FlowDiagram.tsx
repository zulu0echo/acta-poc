import { useMemo } from 'react'
import ReactFlow, {
  Background,
  type Node,
  type Edge,
  type NodeProps,
  Handle,
  Position,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { useSimulation } from '../simulation/SimulationEngine'

const NODE_ICONS: Record<string, string> = {
  issuer:    '🏛️',
  holder:    '🤖',
  verifier:  '🔍',
  anchor:    '⚓',
  gpv:       '✅',
  nullifier: '🔒',
  gate:      '🚪',
}

// Named handles so bidirectional Agent↔Protocol edges use opposite sides
// and never overlap each other.
function ActorNode({ data }: NodeProps) {
  const hStyle = { background: '#374151', width: 6, height: 6 }
  return (
    <div className={`px-3 py-2 rounded-lg border text-xs font-medium min-w-[88px] text-center transition-all duration-300 ${
      data.active
        ? 'border-brand-500 bg-brand-900/50 shadow-lg shadow-brand-500/30'
        : 'border-gray-600 bg-dark-700'
    }`}>
      <Handle id="top"    type="target" position={Position.Top}    style={hStyle} />
      <Handle id="left"   type="target" position={Position.Left}   style={hStyle} />
      <Handle id="right"  type="source" position={Position.Right}  style={hStyle} />
      <Handle id="bottom" type="source" position={Position.Bottom} style={hStyle} />
      <div className="text-base mb-0.5">{NODE_ICONS[data.icon]}</div>
      <div className={data.active ? 'text-white' : 'text-gray-300'}>{data.label}</div>
      {data.sublabel && <div className="text-gray-500 text-[10px]">{data.sublabel}</div>}
    </div>
  )
}

const nodeTypes = { actor: ActorNode }

/**
 * Two-column layout — zero edge crossings:
 *
 *  Left col (off-chain/agent):   Issuer → Agent → Anchor
 *  Right col (on-chain/verifier):         Protocol → GPVerifier
 *  Bottom row (contracts):       Nullifiers   AccessGate
 *
 * Agent ↔ Protocol use opposite handles (right↔left) so their
 * bidirectional edges appear as distinct parallel paths.
 */
export default function FlowDiagram() {
  const { state } = useSimulation()
  const { currentStep, activeEdges } = state

  const activeNodes = useMemo(() => {
    const map: Record<number, string[]> = {
      1:  ['issuer', 'holder', 'verifier'],
      2:  ['issuer'],
      3:  ['issuer', 'holder'],
      4:  ['holder', 'anchor'],
      5:  ['verifier'],
      6:  ['verifier', 'gpv'],
      7:  ['verifier', 'holder'],
      8:  ['holder'],
      9:  ['holder', 'verifier', 'gpv', 'nullifier'],
      10: ['gpv', 'gate'],
    }
    return new Set(map[currentStep] ?? [])
  }, [currentStep])

  const nodes: Node[] = useMemo(() => [
    // Left column
    { id: 'issuer',    type: 'actor', position: { x: 20,  y: 0   }, data: { label: 'Issuer',      sublabel: 'did:ethr', icon: 'issuer',    active: activeNodes.has('issuer')    } },
    { id: 'holder',    type: 'actor', position: { x: 20,  y: 150 }, data: { label: 'Agent',       sublabel: 'did:ethr', icon: 'holder',    active: activeNodes.has('holder')    } },
    { id: 'anchor',    type: 'actor', position: { x: 20,  y: 310 }, data: { label: 'Anchor',      sublabel: 'contract', icon: 'anchor',    active: activeNodes.has('anchor')    } },
    // Right column
    { id: 'verifier',  type: 'actor', position: { x: 195, y: 150 }, data: { label: 'Protocol',    sublabel: 'did:ethr', icon: 'verifier',  active: activeNodes.has('verifier')  } },
    { id: 'gpv',       type: 'actor', position: { x: 195, y: 310 }, data: { label: 'GP Verifier', sublabel: 'contract', icon: 'gpv',       active: activeNodes.has('gpv')       } },
    // Bottom row
    { id: 'nullifier', type: 'actor', position: { x: 20,  y: 460 }, data: { label: 'Nullifiers',  sublabel: 'contract', icon: 'nullifier', active: activeNodes.has('nullifier') } },
    { id: 'gate',      type: 'actor', position: { x: 140, y: 460 }, data: { label: 'AccessGate',  sublabel: 'contract', icon: 'gate',      active: activeNodes.has('gate')      } },
  ], [activeNodes])

  const edges: Edge[] = useMemo(() => {
    const a = (id: string) => activeEdges.includes(id)
    const s = (id: string, color: string) => ({
      stroke: a(id) ? color : '#4b5563',
      strokeWidth: a(id) ? 2.5 : 1.5,
    })
    return [
      // Left column — all straight vertical, no crossings
      { id: 'issuer-holder',        type: 'smoothstep', source: 'issuer',   sourceHandle: 'bottom', target: 'holder',   targetHandle: 'top',    animated: a('issuer-holder'),        style: s('issuer-holder',        '#3b82f6'), label: a('issuer-holder') ? 'JWT-VC' : '' },
      { id: 'holder-anchor',        type: 'smoothstep', source: 'holder',   sourceHandle: 'bottom', target: 'anchor',   targetHandle: 'top',    animated: a('holder-anchor'),        style: s('holder-anchor',        '#7c3aed') },

      // Agent → Protocol: exits Agent's RIGHT, enters Protocol's LEFT (top lane)
      { id: 'holder-verifier',      type: 'smoothstep', source: 'holder',   sourceHandle: 'right',  target: 'verifier', targetHandle: 'left',   animated: a('holder-verifier'),      style: s('holder-verifier',      '#7c3aed'), label: a('holder-verifier') ? 'VP' : '' },
      // Protocol → Agent: exits Protocol's BOTTOM, enters Agent's RIGHT (separate path)
      { id: 'verifier-holder',      type: 'smoothstep', source: 'verifier', sourceHandle: 'bottom', target: 'holder',   targetHandle: 'right',  animated: a('verifier-holder'),      style: s('verifier-holder',      '#0d9488'), label: a('verifier-holder') ? 'OID4VP' : '' },

      // Right column — straight vertical
      { id: 'verifier-gpverifier',  type: 'smoothstep', source: 'verifier', sourceHandle: 'bottom', target: 'gpv',      targetHandle: 'top',    animated: a('verifier-gpverifier'),  style: s('verifier-gpverifier',  '#0d9488') },

      // GPVerifier → Nullifiers: diagonal left-down, clear of all nodes
      { id: 'gpverifier-nullifier', type: 'smoothstep', source: 'gpv',      sourceHandle: 'bottom', target: 'nullifier',targetHandle: 'top',    animated: a('gpverifier-nullifier'), style: s('gpverifier-nullifier', '#d97706') },

      // GPVerifier → AccessGate: slight right-down, step 10
      { id: 'gpv-gate',             type: 'smoothstep', source: 'gpv',      sourceHandle: 'bottom', target: 'gate',     targetHandle: 'top',    animated: a('gpv-gate'),             style: s('gpv-gate',             '#10b981') },
    ]
  }, [activeEdges])

  return (
    <div className="h-full bg-dark-900 flex flex-col">
      <div className="px-3 py-2 border-b border-gray-700/60">
        <p className="text-xs font-medium text-gray-300">Architecture</p>
        <p className="text-[10px] text-gray-500">Step {currentStep}: active nodes highlighted</p>
      </div>
      <div className="flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.15, minZoom: 0.4, maxZoom: 1 }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          zoomOnScroll={false}
          panOnScroll={false}
          panOnDrag={false}
          attributionPosition="bottom-left"
        >
          <Background color="#1f2937" gap={20} size={1} />
        </ReactFlow>
      </div>

      {/* Step legend */}
      <div className="px-3 py-2 border-t border-gray-700/60 space-y-1">
        {[
          { step: 3, label: 'Credential issued',  color: 'bg-blue-500'   },
          { step: 4, label: 'On-chain anchor',     color: 'bg-purple-500' },
          { step: 8, label: 'ZK proof generated',  color: 'bg-amber-500'  },
          { step: 9, label: 'On-chain verified',   color: 'bg-teal-500'   },
        ].map(({ step, label, color }) => (
          <div key={step} className={`flex items-center gap-2 text-[10px] ${currentStep === step ? 'text-gray-200' : 'text-gray-500'}`}>
            <div className={`w-1.5 h-1.5 rounded-full ${currentStep === step ? color : 'bg-gray-600'}`} />
            {label}
          </div>
        ))}
      </div>
    </div>
  )
}
