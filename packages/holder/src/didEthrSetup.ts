// Re-export the same pattern used in issuer.
// Each package has its own copy so the environment variable (HOLDER_PRIVATE_KEY)
// is resolved in the correct process context.
export { createEthrDIDIdentity, resolvePublicKey } from '../../issuer/src/didEthrSetup'
export type { EthrDIDIdentity } from '../../issuer/src/didEthrSetup'
