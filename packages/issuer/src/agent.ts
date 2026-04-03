import {
  Agent,
  KeyType,
  TypedArrayEncoder,
  type AgentContext,
} from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { OpenId4VcIssuerModule } from '@credo-ts/openid4vc'
import type { EthrDIDIdentity } from './didEthrSetup'
import type { AgentCapabilityCredentialSubject } from '@acta/shared'
import { buildAgentCapabilityVC, DEFAULT_CREDENTIAL_SUBJECT } from './credentialSchema'
import { SignJWT, importPKCS8, exportPKCS8 } from 'jose'
import { ethers } from 'ethers'

const ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? 'http://localhost:3001'
const WALLET_KEY = process.env.WALLET_KEY ?? 'insecure-dev-key-do-not-use-in-production'

/**
 * Creates and initialises a Credo agent configured for did:ethr issuance.
 * The agent:
 *  - Uses did:ethr as its sole DID method
 *  - Registers the ethr-did-resolver so it can resolve any did:ethr DID
 *  - Exposes OID4VCI credential issuance endpoints
 */
export async function createIssuerAgent(identity: EthrDIDIdentity) {
  const agent = new Agent({
    config: {
      label:        'ERC8080-Issuer',
      walletConfig: { id: 'acta-issuer', key: WALLET_KEY },
    },
    dependencies: agentDependencies,
    modules: {
      openId4VcIssuer: new OpenId4VcIssuerModule({
        baseUrl: ISSUER_BASE_URL,
        endpoints: {
          credential: {
            credentialRequestToCredentialMapper: credentialMapper(identity),
          },
        },
      }),
    },
  })

  await agent.initialize()

  // Register did:ethr resolver so Credo can resolve holder/verifier DIDs
  agent.dids.addResolver({
    supportedMethods: ['ethr'],
    resolve: async (did: string) => identity.resolver.resolve(did),
  })

  // Import issuer's did:ethr into Credo's DID store
  // The private key is secp256k1 — stored as raw bytes in Credo's wallet
  const privateKeyBytes = TypedArrayEncoder.fromHex(
    identity.signer.privateKey.slice(2)
  )
  await agent.dids.import({
    did:       identity.did,
    overwrite: true,
    privateKeys: [
      {
        keyType:    KeyType.K256,   // secp256k1 — P256 is a different curve (NIST P-256 / ES256)
        privateKey: privateKeyBytes,
      },
    ],
  })

  return agent
}

/**
 * Credential mapper: called by Credo for each incoming credential request.
 * Signs an AgentCapabilityVC JWT with the issuer's did:ethr key (ES256K).
 *
 * The issued JWT-VC includes:
 *  - iss: issuer's did:ethr
 *  - sub: holder's did:ethr (from proof-of-possession JWT)
 *  - kid: "did:ethr:0x14f69:0x<issuerAddress>#controller"
 *  - alg: ES256K
 */
function credentialMapper(identity: EthrDIDIdentity) {
  return async (_agentContext: AgentContext, request: {
    holderBinding?: { method: 'did'; didUrl: string }
    credentialType?: string
    subjectData?: Partial<AgentCapabilityCredentialSubject>
  }) => {
    const holderDid = request.holderBinding?.didUrl?.split('#')[0] ?? identity.did

    const subjectData: AgentCapabilityCredentialSubject = {
      ...DEFAULT_CREDENTIAL_SUBJECT,
      ...(request.subjectData ?? {}),
      id:        holderDid,
      auditedBy: identity.did,
    }

    const vc = buildAgentCapabilityVC({
      issuerDid: identity.did,
      subjectData,
    })

    const jwt = await signCredentialAsJwt(vc, identity)
    return { type: 'jwt_vc', jwt }
  }
}

/**
 * Signs a W3C VC payload as a compact JWT using the issuer's secp256k1 key.
 *
 * JWT structure:
 *   Header: { alg: "ES256K", typ: "JWT", kid: "<did>#controller" }
 *   Payload: { iss, sub, vc, iat, exp, nbf }
 */
export async function signCredentialAsJwt(
  vc: ReturnType<typeof buildAgentCapabilityVC>,
  identity: EthrDIDIdentity
): Promise<string> {
  const holderDid = vc.credentialSubject.id
  const now = Math.floor(Date.now() / 1000)
  const exp = Math.floor(new Date(vc.expirationDate).getTime() / 1000)

  // Convert secp256k1 private key for jose (ES256K)
  const privKeyBytes = Buffer.from(identity.signer.privateKey.slice(2), 'hex')
  const secp256k1Key = await importSecp256k1PrivateKey(privKeyBytes)

  const jwt = await new SignJWT({
    vc,
    sub: holderDid,
  })
    .setProtectedHeader({
      alg: 'ES256K',
      typ: 'JWT',
      kid: `${identity.did}#controller`,
    })
    .setIssuer(identity.did)
    .setSubject(holderDid)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(exp)
    .sign(secp256k1Key)

  return jwt
}

/**
 * Imports a raw secp256k1 private key for use with jose's ES256K algorithm.
 * jose requires the key in JWK or PKCS#8 format.
 */
async function importSecp256k1PrivateKey(privKeyBytes: Buffer): Promise<CryptoKey> {
  const wallet = new ethers.Wallet('0x' + privKeyBytes.toString('hex'))
  const pubKey = wallet.signingKey.publicKey

  const jwk = {
    kty: 'EC',
    crv: 'secp256k1',
    d:   Buffer.from(privKeyBytes).toString('base64url'),
    x:   Buffer.from(pubKey.slice(4, 68), 'hex').toString('base64url'),
    y:   Buffer.from(pubKey.slice(68), 'hex').toString('base64url'),
  }

  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'secp256k1' }, false, ['sign'])
}
