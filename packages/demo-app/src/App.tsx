import { useState, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RotateCcw, ChevronLeft, ChevronRight, Shield, FileText, BookOpen } from 'lucide-react'
import {
  SimulationContext,
  createInitialState,
  type SimulationState,
  type SimulatedCredentialValues,
  type SimulatedPredicateCondition,
  type EventLogEntry,
} from './simulation/SimulationEngine'
import FlowDiagram from './components/FlowDiagram'
import StepPanel from './components/StepPanel'
import DocPanel from './components/DocPanel'
import EventLog from './components/EventLog'
import SpecPage from './components/SpecPage'
import DocsPage from './components/DocsPage'

const TOTAL_STEPS = 10

export default function App() {
  const [view, setView] = useState<'demo' | 'spec' | 'docs'>('demo')
  const [state, setState] = useState<SimulationState>(createInitialState)
  const eventIdRef = useRef(0)

  const addEvent = useCallback((entry: Omit<EventLogEntry, 'id' | 'timestamp'>) => {
    setState(s => ({
      ...s,
      eventLog: [
        ...s.eventLog,
        { ...entry, id: `evt-${++eventIdRef.current}`, timestamp: Date.now() },
      ],
    }))
  }, [])

  const nextStep = useCallback(() => {
    setState(s => {
      if (s.currentStep >= TOTAL_STEPS) return s
      const next = s.currentStep + 1
      addEvent({
        severity: 'info',
        actor:    'system',
        message:  `Advancing to Step ${next}`,
      })
      return { ...s, currentStep: next, activeEdges: edgesForStep(next) }
    })
  }, [addEvent])

  const prevStep = useCallback(() => {
    setState(s => {
      if (s.currentStep <= 1) return s
      return { ...s, currentStep: s.currentStep - 1, activeEdges: edgesForStep(s.currentStep - 1) }
    })
  }, [])

  const goToStep = useCallback((step: number) => {
    setState(s => ({ ...s, currentStep: step, activeEdges: edgesForStep(step) }))
  }, [])

  const reset = useCallback(() => {
    setState(createInitialState())
    eventIdRef.current = 0
  }, [])

  const updateCredentialValues = useCallback((values: Partial<SimulatedCredentialValues>) => {
    setState(s => ({ ...s, credentialValues: { ...s.credentialValues, ...values } }))
  }, [])

  const updatePredicateConditions = useCallback((conditions: SimulatedPredicateCondition[]) => {
    setState(s => ({ ...s, predicateConditions: conditions }))
  }, [])

  const runProofGeneration = useCallback(async () => {
    setState(s => ({ ...s, proofGenerating: true, proofProgress: 0 }))
    addEvent({ severity: 'info', actor: 'holder', message: 'Starting ZK proof generation…' })

    const DURATION = 1800
    const STEPS = 20
    for (let i = 1; i <= STEPS; i++) {
      await new Promise(r => setTimeout(r, DURATION / STEPS))
      setState(s => ({ ...s, proofProgress: Math.round((i / STEPS) * 100) }))
    }

    setState(s => ({ ...s, proofGenerating: false, proofProgress: 100, proofTimeMs: DURATION }))
    addEvent({ severity: 'success', actor: 'holder', message: `ZK proof generated in ${DURATION}ms`, detail: `Nullifier: ${state.publicSignals.nullifier.slice(0, 22)}…` })
  }, [addEvent, state.publicSignals.nullifier])

  const runVerificationSteps = useCallback(async () => {
    addEvent({ severity: 'info', actor: 'verifier', message: 'Beginning 10-step on-chain verification' })
    for (let i = 0; i < 10; i++) {
      await new Promise(r => setTimeout(r, 280 + Math.random() * 120))
      setState(s => {
        const steps = [...s.verificationSteps]
        steps[i] = { ...steps[i], status: 'done' }
        return { ...s, verificationSteps: steps }
      })
      addEvent({
        severity: 'success',
        actor:    'contract',
        message:  `Step ${i + 1}: ${state.verificationSteps[i]?.label ?? ''}`,
      })
    }
    addEvent({
      severity: 'success',
      actor:    'contract',
      message:  'PresentationAccepted emitted',
      detail:   `nullifier: ${state.nullifier.slice(0, 22)}…`,
      txHash:   state.verificationTxHash,
    })
  }, [addEvent, state.verificationSteps, state.nullifier, state.verificationTxHash])

  const grantAccess = useCallback(() => {
    setState(s => ({ ...s, accessGranted: true }))
    addEvent({ severity: 'success', actor: 'contract', message: 'AgentAccessGate: access granted', detail: `nullifier: ${state.nullifier.slice(0, 22)}…` })
  }, [addEvent, state.nullifier])

  const attemptReplay = useCallback(() => {
    setState(s => ({ ...s, replayAttempted: true, replayReverted: true }))
    addEvent({
      severity: 'error',
      actor:    'contract',
      message:  'Replay rejected: NullifierAlreadyActive',
      detail:   `The nullifier ${state.nullifier.slice(0, 22)}… is already registered. Replay attacks are impossible.`,
    })
  }, [addEvent, state.nullifier])

  const contextValue = {
    state,
    nextStep,
    prevStep,
    goToStep,
    reset,
    updateCredentialValues,
    updatePredicateConditions,
    runProofGeneration,
    runVerificationSteps,
    grantAccess,
    attemptReplay,
    addEvent,
  }

  return (
    <SimulationContext.Provider value={contextValue}>
      <div className="flex flex-col h-screen bg-dark-900 text-gray-100 overflow-hidden">
        {/* Header */}
        <header className="flex items-center justify-between px-6 py-3 bg-dark-800 border-b border-gray-700/60 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-brand-600 rounded-lg flex items-center justify-center">
              <Shield size={16} className="text-white" />
            </div>
            <div>
              <h1 className="text-sm font-semibold text-white">ACTA Interactive Demo</h1>
              <p className="text-xs text-gray-400">Anonymous Credentials for Trustless Agents</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* View toggle */}
            <div className="flex items-center gap-1 bg-dark-700 rounded-lg p-0.5 border border-gray-700/60">
              <button
                onClick={() => setView('demo')}
                className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${
                  view === 'demo'
                    ? 'bg-brand-600 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Demo
              </button>
              <button
                onClick={() => setView('spec')}
                className={`flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md transition-all ${
                  view === 'spec'
                    ? 'bg-brand-600 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <FileText size={11} />
                Specification
              </button>
              <button
                onClick={() => setView('docs')}
                className={`flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md transition-all ${
                  view === 'docs'
                    ? 'bg-brand-600 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <BookOpen size={11} />
                Documentation
              </button>
            </div>

            {/* Step progress — only shown in demo view */}
            {view === 'demo' && (
              <>
                <div className="flex items-center gap-2">
                  {Array.from({ length: TOTAL_STEPS }).map((_, i) => (
                    <button
                      key={i}
                      onClick={() => goToStep(i + 1)}
                      className={`w-6 h-6 rounded-full text-xs font-medium transition-all duration-200 ${
                        i + 1 === state.currentStep
                          ? 'bg-brand-600 text-white scale-110'
                          : i + 1 < state.currentStep
                          ? 'bg-green-700 text-green-200'
                          : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                      }`}
                    >
                      {i + 1}
                    </button>
                  ))}
                </div>

                <span className="text-xs text-gray-400 font-mono">
                  Step {state.currentStep} of {TOTAL_STEPS}
                </span>

                <div className="flex items-center gap-1">
                  <button className="btn-ghost" onClick={prevStep} disabled={state.currentStep <= 1}>
                    <ChevronLeft size={16} />
                  </button>
                  <button
                    className="btn-primary text-xs px-3 py-1.5"
                    onClick={nextStep}
                    disabled={state.currentStep >= TOTAL_STEPS}
                  >
                    Next Step
                    <ChevronRight size={14} />
                  </button>
                  <button className="btn-ghost ml-2" onClick={reset} title="Reset simulation">
                    <RotateCcw size={14} />
                  </button>
                </div>
              </>
            )}
          </div>
        </header>

        {/* Spec page */}
        {view === 'spec' && <SpecPage />}

        {/* Documentation page */}
        {view === 'docs' && <div className="flex-1 overflow-hidden"><DocsPage /></div>}

        {/* Demo layout */}
        {view === 'demo' && (
          <>
            <div className="flex flex-1 overflow-hidden">
              {/* Left: Architecture Diagram */}
              <div className="w-72 flex-shrink-0 border-r border-gray-700/60 overflow-hidden">
                <FlowDiagram />
              </div>

              {/* Centre: Active Step Panel */}
              <div className="flex-1 overflow-y-auto">
                <AnimatePresence mode="wait">
                  <motion.div
                    key={state.currentStep}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.2 }}
                    className="h-full"
                  >
                    <StepPanel />
                  </motion.div>
                </AnimatePresence>
              </div>

              {/* Right: Doc Panel */}
              <div className="w-80 flex-shrink-0 border-l border-gray-700/60 overflow-y-auto">
                <DocPanel />
              </div>
            </div>

            {/* Bottom: Event Log */}
            <div className="h-40 flex-shrink-0 border-t border-gray-700/60">
              <EventLog />
            </div>
          </>
        )}
      </div>
    </SimulationContext.Provider>
  )
}

function edgesForStep(step: number): string[] {
  const map: Record<number, string[]> = {
    3:  ['issuer-holder'],
    4:  ['holder-anchor'],
    7:  ['verifier-holder'],
    9:  ['holder-verifier', 'verifier-gpverifier', 'gpverifier-nullifier'],
    10: ['gpv-gate'],
  }
  return map[step] ?? []
}
