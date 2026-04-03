import type { SimulatedCredentialValues } from './SimulationEngine'

export function generateOID4VCITrace(
  issuerDid: string,
  holderDid: string,
  values: SimulatedCredentialValues
) {
  const preAuthCode = 'pac_' + Math.random().toString(36).slice(2, 18)
  const accessToken = 'at_' + Math.random().toString(36).slice(2, 34)
  const cNonce      = 'cn_' + Math.random().toString(36).slice(2, 18)

  return {
    credentialOffer: {
      credential_issuer: 'http://localhost:3001',
      credentials:       ['AgentCapabilityCredential'],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthCode,
        },
      },
    },
    tokenRequest: {
      grant_type:          'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': preAuthCode,
    },
    tokenResponse: {
      access_token:      accessToken,
      token_type:        'Bearer',
      expires_in:        300,
      c_nonce:           cNonce,
      c_nonce_expires_in: 300,
    },
    credentialRequest: {
      format: 'jwt_vc_json',
      types:  ['VerifiableCredential', 'AgentCapabilityCredential'],
      proof: {
        proof_type: 'jwt',
        jwt:        '[proof-of-possession JWT with iss=' + holderDid + ']',
      },
    },
    credentialResponse: {
      format:     'jwt_vc_json',
      credential: '[JWT-VC signed with ES256K by ' + issuerDid + ']',
    },
    credentialDecoded: {
      header:  { alg: 'ES256K', typ: 'JWT', kid: issuerDid + '#controller' },
      payload: {
        iss: issuerDid,
        sub: holderDid,
        vc:  {
          '@context':       ['https://www.w3.org/2018/credentials/v1', 'https://acta.ethereum.org/contexts/AgentCapability/v1'],
          type:             ['VerifiableCredential', 'AgentCapabilityCredential'],
          issuer:           issuerDid,
          issuanceDate:     new Date().toISOString(),
          expirationDate:   new Date(Date.now() + 90 * 86400 * 1000).toISOString(),
          credentialSubject: { id: holderDid, ...values },
        },
      },
    },
  }
}
