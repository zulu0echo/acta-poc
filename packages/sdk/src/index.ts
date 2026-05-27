/**
 * @acta/sdk — ACTA integration SDK.
 *
 * Single integration surface for ACTA. See README.md and ADR-0004 for
 * the design contract.
 *
 * Currently exported (v0.3):
 *   - predicate.*  zkID generalized-predicate IR + canonical hash
 *   - stealth.*    Stealth-address derivation
 *
 * Open (v0.6 — see docs/ROADMAP.md Phase 3):
 *   - ActaClient.create()
 *   - acta.issuer.*, acta.holder.*, acta.verifier.*, acta.ceremony.*
 */

import * as predicate from './predicate'
import * as stealth from './stealth'

export { predicate, stealth }

/** Marker error for surfaces not yet implemented in v0.3. */
export class NotImplementedError extends Error {
  constructor(surface: string) {
    super(
      `@acta/sdk: ${surface} is not implemented in v0.3 — tracked in docs/ROADMAP.md Phase 3 (v0.6).`,
    )
    this.name = 'NotImplementedError'
  }
}

/** Placeholder client API. Concrete clients land in v0.6. */
export class ActaClient {
  static create(_opts: ActaClientOptions): ActaClient {
    throw new NotImplementedError('ActaClient.create()')
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private constructor(_opts: ActaClientOptions) {
    // empty
  }
}

export interface ActaClientOptions {
  network: 'base-sepolia' | 'base-mainnet' | 'hardhat'
  contracts?: Partial<Record<'NullifierRegistry' | 'OpenACCredentialAnchor' | 'GeneralizedPredicateVerifier' | 'OpenACSnarkVerifier' | 'PolicyRegistry', string>>
  prover?: 'wallet-unit-poc' | 'stub'
  unlinkability?: 'stealth' | 'none'
}
