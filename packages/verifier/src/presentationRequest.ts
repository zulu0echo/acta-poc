import * as crypto from 'crypto'
import type { EthrDIDIdentity } from '../../issuer/src/didEthrSetup'
import type { BuiltPredicate } from './predicateBuilder'
import type {
  PresentationRequestParams,
  PresentationRequestResult,
  OID4VPAuthRequest,
} from '@acta/shared'

/**
 * Builds OID4VP authorization requests for ACTA credential presentations.
 *
 * The authorization request includes:
 *   client_id: verifier's did:ethr
 *   x-openac-predicate: JSON-serialised PredicateProgram
 *   x-openac-policy-id: on-chain policyId
 *   x-onchain-verifier: GeneralizedPredicateVerifier address
 */
export class PresentationRequestBuilder {
  constructor(private identity: EthrDIDIdentity) {}

  /**
   * Create an OID4VP authorization request.
   * The returned requestUri can be sent to the holder as a deep link.
   */
  createPresentationRequest(params: PresentationRequestParams): PresentationRequestResult {
    const sessionId = crypto.randomBytes(16).toString('hex')
    const nonce = params.sessionNonce.toString(16).padStart(16, '0')

    const authRequest: OID4VPAuthRequest = {
      response_type:    'vp_token',
      client_id:        this.identity.did,
      client_id_scheme: 'did',
      nonce,
      presentation_definition: {
        id: `acta-${sessionId}`,
        input_descriptors: [
          {
            id:      'AgentCapabilityCredential',
            name:    'Agent Capability Credential',
            purpose: 'Verify agent compliance for ACTA policy',
            constraints: {
              fields: [
                {
                  path:   ['$.vc.type'],
                  filter: { type: 'array', contains: { const: 'AgentCapabilityCredential' } },
                },
              ],
            },
          },
        ],
      },
      'x-openac-predicate':  params.predicate.toJSON(),
      'x-openac-policy-id':  params.policyId,
      'x-onchain-verifier':  params.onchainVerifierAddress,
      response_uri:          params.verifierCallbackUrl,
    }

    const requestUri = `openid4vp://?request=${encodeURIComponent(JSON.stringify(authRequest))}`

    return { requestUri, authorizationRequest: authRequest, sessionId }
  }
}
