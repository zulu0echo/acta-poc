/**
 * Verifier Credo.ts agent configuration.
 * The verifier does not issue or hold credentials — it only verifies them.
 * It uses the did:ethr resolver to verify issuer and holder signatures on
 * JWT-VCs and VP JWTs during the OID4VP callback processing.
 */
export { createEthrDIDIdentity } from '../../issuer/src/didEthrSetup'
export type { EthrDIDIdentity } from '../../issuer/src/didEthrSetup'
