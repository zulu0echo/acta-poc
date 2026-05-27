/**
 * Holder surface — V0.4 OpenACAdapterV2 + V2 stub prover.
 *
 * SDK users wanting to wire a custom prover should implement the
 * `IWalletUnitV2` interface and pass it into `createAdapter()`.
 */

import { OpenACAdapterV2, StubWalletUnitV2 } from '@acta/holder/src/openacAdapterV2'
import type { IWalletUnitV2 } from '@acta/holder/src/openacAdapterV2'

export type { IWalletUnitV2 }

/**
 * Create a V2 holder adapter. If no prover is supplied, defaults to the
 * `StubWalletUnitV2` — suitable for local dev only. Production deployments
 * must inject a snarkjs-backed prover.
 */
export function createAdapter(walletUnit?: IWalletUnitV2): OpenACAdapterV2 {
  return new OpenACAdapterV2(walletUnit)
}

/** The default in-memory dev prover. Re-exported for convenience. */
export { StubWalletUnitV2 }
