export * from './types'
export * from './constants'
export * from './predicateHash'
export * from './predicateCircuit'
export * from './poseidon'
export * from './credentialPoseidon'

// zkID generalized-predicates (v0.3) — namespaced to avoid colliding with v1
// names. Use as: `import { gp } from '@acta/shared'`.
export * as gp from './gp'

// Stealth-address derivation (ADR-0002) — namespaced.
export * as stealth from './stealth'
