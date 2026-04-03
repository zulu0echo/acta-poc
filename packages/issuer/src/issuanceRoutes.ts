import { Router, type Request, type Response, type NextFunction } from 'express'
import { ethers } from 'ethers'
import type { EthrDIDIdentity } from './didEthrSetup'
import { buildAgentCapabilityVC, DEFAULT_CREDENTIAL_SUBJECT, AGENT_CAPABILITY_CONTEXT } from './credentialSchema'
import { signCredentialAsJwt } from './agent'
import type { AgentCapabilityCredentialSubject, CredentialOffer } from '@acta/shared'
import { CREDENTIAL_TYPE } from '@acta/shared'
import * as crypto from 'crypto'

const ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? 'http://localhost:3001'

// In-memory pre-authorized code store (replace with Redis in production).
// Each entry stores the issued access token so it can be validated at /credentials.
const preAuthCodes = new Map<
  string,
  {
    holderDid?: string
    subjectData?: Partial<AgentCapabilityCredentialSubject>
    usedAt?: number
    accessToken?: string
    tokenIssuedAt?: number
  }
>()

// Access token TTL: 5 minutes (matches expires_in: 300)
const TOKEN_TTL_MS = 5 * 60 * 1000

/**
 * Wraps async Express routes to forward rejections to the error handler.
 */
function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next)
  }
}

export function createIssuanceRouter(identity: EthrDIDIdentity): Router {
  const router = Router()

  // ── OpenID Connect Discovery / Issuer Metadata ────────────────────────────

  router.get('/.well-known/openid-credential-issuer', (_req: Request, res: Response) => {
    res.json({
      issuer:                ISSUER_BASE_URL,
      credential_issuer:     ISSUER_BASE_URL,
      credential_endpoint:   `${ISSUER_BASE_URL}/credentials`,
      token_endpoint:        `${ISSUER_BASE_URL}/token`,
      jwks_uri:              `${ISSUER_BASE_URL}/.well-known/jwks.json`,
      credentials_supported: [
        {
          format: 'jwt_vc_json',
          id:     CREDENTIAL_TYPE,
          types:  ['VerifiableCredential', CREDENTIAL_TYPE],
          cryptographic_suites_supported: ['ES256K'],
          display: [
            {
              name:             'Agent Capability Credential',
              description:      'Certifies that an AI agent meets ACTA compliance requirements.',
              background_color: '#1a1a2e',
              text_color:       '#ffffff',
            },
          ],
        },
      ],
    })
  })

  // ── JWKS Endpoint ─────────────────────────────────────────────────────────

  router.get('/.well-known/jwks.json', (_req: Request, res: Response) => {
    const pubKey = identity.signer.signingKey.publicKey
    res.json({
      keys: [
        {
          kty: 'EC',
          crv: 'secp256k1',
          use: 'sig',
          alg: 'ES256K',
          kid: `${identity.did}#controller`,
          x:   Buffer.from(pubKey.slice(4, 68), 'hex').toString('base64url'),
          y:   Buffer.from(pubKey.slice(68), 'hex').toString('base64url'),
        },
      ],
    })
  })

  // ── JSON-LD Context ───────────────────────────────────────────────────────

  router.get('/contexts/AgentCapability/v1', (_req: Request, res: Response) => {
    res.json(AGENT_CAPABILITY_CONTEXT)
  })

  // ── Credential Offer ──────────────────────────────────────────────────────

  router.get('/credential-offer', (req: Request, res: Response) => {
    const holderDid = req.query.holder_did as string | undefined
    const code = crypto.randomBytes(16).toString('hex')
    preAuthCodes.set(code, { holderDid })

    const offer: CredentialOffer = {
      credential_issuer: ISSUER_BASE_URL,
      credentials:       [CREDENTIAL_TYPE],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': code,
        },
      },
    }

    const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`
    res.json({ offer_uri: offerUri, offer })
  })

  // ── Token Endpoint ────────────────────────────────────────────────────────

  router.post('/token', (req: Request, res: Response) => {
    const { grant_type, 'pre-authorized_code': code } = req.body as Record<string, string>

    if (grant_type !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      res.status(400).json({ error: 'unsupported_grant_type' })
      return
    }
    if (!code || !preAuthCodes.has(code)) {
      res.status(400).json({ error: 'invalid_grant' })
      return
    }

    const codeData = preAuthCodes.get(code)!
    if (codeData.usedAt) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Code already used' })
      return
    }

    const accessToken = crypto.randomBytes(32).toString('hex')
    codeData.usedAt        = Date.now()
    codeData.accessToken   = accessToken
    codeData.tokenIssuedAt = Date.now()

    res.json({
      access_token:       accessToken,
      token_type:         'Bearer',
      expires_in:         300,
      c_nonce:            crypto.randomBytes(16).toString('hex'),
      c_nonce_expires_in: 300,
    })
  })

  // ── Credential Endpoint (OID4VCI) ─────────────────────────────────────────

  router.post('/credentials', asyncHandler(async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization ?? ''
    if (!authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'invalid_token' })
      return
    }
    const submittedToken = authHeader.slice(7).trim()

    // Validate that this token was actually issued by our /token endpoint and has not expired.
    // Previously, any non-empty Bearer string passed — a complete authentication bypass.
    const tokenEntry = findByAccessToken(submittedToken)
    if (!tokenEntry) {
      res.status(401).json({ error: 'invalid_token', error_description: 'Token not issued by this server' })
      return
    }
    const tokenAgeMs = Date.now() - (tokenEntry.tokenIssuedAt ?? 0)
    if (tokenAgeMs > TOKEN_TTL_MS) {
      res.status(401).json({ error: 'invalid_token', error_description: 'Token expired' })
      return
    }

    const body = req.body as {
      format?: string
      types?: string[]
      proof?: { proof_type: string; jwt?: string }
      credential_subject?: Partial<AgentCapabilityCredentialSubject>
    }

    if (body.format !== 'jwt_vc_json') {
      res.status(400).json({ error: 'unsupported_credential_format' })
      return
    }

    // Extract holder DID from proof-of-possession JWT and cryptographically verify the signature.
    // Without signature verification, any caller can supply any DID as the holder and obtain
    // a credential bound to an arbitrary identity.
    let holderDid = identity.did
    if (body.proof?.proof_type === 'jwt' && body.proof.jwt) {
      const popResult = verifyAndExtractPopJwt(body.proof.jwt, identity.signer.address)
      if (!popResult.valid) {
        res.status(400).json({
          error: 'invalid_proof',
          error_description: popResult.reason,
        })
        return
      }
      if (popResult.holderDid) holderDid = popResult.holderDid
    }

    const subjectData: AgentCapabilityCredentialSubject = {
      ...DEFAULT_CREDENTIAL_SUBJECT,
      ...(body.credential_subject ?? {}),
      id:        holderDid,
      auditedBy: identity.did,
    }

    const vc  = buildAgentCapabilityVC({ issuerDid: identity.did, subjectData })
    const jwt = await signCredentialAsJwt(vc, identity)

    res.json({ format: 'jwt_vc_json', credential: jwt })
  }))

  // ── Error handler ─────────────────────────────────────────────────────────

  router.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: number }).status ?? 500
    console.error('[issuer] Route error:', err.message)
    res.status(status).json({ error: err.message ?? 'Internal server error' })
  })

  return router
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function findByAccessToken(token: string) {
  for (const entry of preAuthCodes.values()) {
    if (entry.accessToken === token) return entry
  }
  return undefined
}

/**
 * Verifies a proof-of-possession JWT issued by the holder.
 *
 * The PoP JWT MUST be signed with the holder's secp256k1 key (ES256K).
 * We verify by recovering the signer address from the signature and checking
 * it matches the Ethereum address in the `iss` claim's DID.
 *
 * Note: In production, also validate `aud` = ISSUER_BASE_URL and `exp` > now.
 */
function verifyAndExtractPopJwt(
  jwt: string,
  _issuerAddress: string
): { valid: boolean; reason?: string; holderDid?: string } {
  try {
    const parts = jwt.split('.')
    if (parts.length !== 3) return { valid: false, reason: 'PoP JWT must have exactly 3 parts' }

    let payload: Record<string, unknown>
    try {
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    } catch {
      return { valid: false, reason: 'PoP JWT payload is not valid JSON' }
    }

    const iss = payload.iss as string | undefined
    if (!iss) return { valid: false, reason: 'PoP JWT missing iss claim' }

    // Check expiry
    if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, reason: 'PoP JWT is expired' }
    }

    // Extract Ethereum address from the DID (did:ethr:...:<address>)
    const holderAddress = iss.split(':').pop()!
    if (!ethers.isAddress(holderAddress)) {
      return { valid: false, reason: `Cannot extract Ethereum address from iss DID: ${iss}` }
    }

    // Verify ES256K signature: digest = keccak256(header.payload)
    const sigInput = `${parts[0]}.${parts[1]}`
    const digest   = ethers.keccak256(ethers.toUtf8Bytes(sigInput))
    const sigHex   = '0x' + Buffer.from(parts[2], 'base64url').toString('hex')

    if (sigHex.length < 130) {
      return { valid: false, reason: 'PoP JWT signature is too short (expected 64-byte secp256k1 signature)' }
    }

    let sigValid = false
    for (const v of [27, 28]) {
      try {
        const recovered = ethers.recoverAddress(digest, {
          r: '0x' + sigHex.slice(2, 66),
          s: '0x' + sigHex.slice(66, 130),
          v,
        })
        if (recovered.toLowerCase() === holderAddress.toLowerCase()) {
          sigValid = true
          break
        }
      } catch { /* try next v */ }
    }

    if (!sigValid) {
      return { valid: false, reason: `PoP JWT signature does not match DID controller address ${holderAddress}` }
    }

    return { valid: true, holderDid: iss }
  } catch (err) {
    return { valid: false, reason: `PoP JWT verification error: ${(err as Error).message}` }
  }
}
