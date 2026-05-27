import type { OID4VPAuthRequest } from '@acta/shared'

const TRUSTED_VERIFIER_DIDS = (process.env.TRUSTED_VERIFIER_DIDS ?? '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean)

const TRUSTED_ONCHAIN_VERIFIERS = (process.env.TRUSTED_ONCHAIN_VERIFIERS ?? '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean)

export function validatePresentationRequest(authRequest: OID4VPAuthRequest): void {
  if (!authRequest['x-openac-predicate']) {
    throw new Error('Missing x-openac-predicate in OID4VP request')
  }
  if (!authRequest['x-openac-policy-id']) {
    throw new Error('Missing x-openac-policy-id in OID4VP request')
  }
  if (!authRequest['x-onchain-verifier']) {
    throw new Error('Missing x-onchain-verifier in OID4VP request')
  }

  if (TRUSTED_VERIFIER_DIDS.length > 0 && !TRUSTED_VERIFIER_DIDS.includes(authRequest.client_id)) {
    throw new Error(`Verifier DID not in TRUSTED_VERIFIER_DIDS: ${authRequest.client_id}`)
  }

  const onchain = authRequest['x-onchain-verifier'].toLowerCase()
  if (TRUSTED_ONCHAIN_VERIFIERS.length > 0 && !TRUSTED_ONCHAIN_VERIFIERS.includes(onchain)) {
    throw new Error(`On-chain verifier not in TRUSTED_ONCHAIN_VERIFIERS: ${onchain}`)
  }
}
