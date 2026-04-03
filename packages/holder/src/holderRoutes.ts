import { Router, type Request, type Response, type NextFunction } from 'express'
import { ethers } from 'ethers'
import axios from 'axios'
import type { EthrDIDIdentity } from './didEthrSetup'
import { CredentialStore } from './credentialStore'
import { PresentationHandler } from './presentationHandler'
import type { OID4VPAuthRequest, SignedJwtVC, AgentCapabilityVC } from '@acta/shared'

const ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? 'http://localhost:3001'

// ── Utilities ─────────────────────────────────────────────────────────────────

/**
 * Wraps an async Express route handler to forward uncaught rejections to the
 * Express error handler. Without this, in Express 4 any unhandled rejection in
 * an async route handler leaves the request hanging and may crash the process.
 */
function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next)
  }
}

/**
 * Validates that a URL is an absolute HTTPS URL pointing to an allowed host.
 * Used to prevent SSRF via user-supplied response_uri fields.
 *
 * In development (NODE_ENV !== 'production'), HTTP localhost URLs are permitted.
 */
function validateCallbackUrl(raw: string | undefined): void {
  if (!raw) return
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch {
    throw new Error(`Invalid URL in response_uri: ${raw}`)
  }

  const isLocalhost =
    parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
  const isHttp = parsed.protocol === 'http:'
  const isHttps = parsed.protocol === 'https:'

  if (process.env.NODE_ENV === 'production') {
    if (!isHttps) throw new Error(`response_uri must use HTTPS in production`)
    if (isLocalhost) throw new Error(`response_uri must not target localhost in production`)
  } else {
    if (!isHttps && !(isHttp && isLocalhost)) {
      throw new Error(`response_uri must be HTTPS or http://localhost`)
    }
  }
}

// ── Router ────────────────────────────────────────────────────────────────────

export function createHolderRouter(identity: EthrDIDIdentity): Router {
  const router = Router()
  const credentialStore = new CredentialStore()
  const presentationHandler = new PresentationHandler(identity, credentialStore)

  // ── Credential Issuance (OID4VCI) ─────────────────────────────────────────
  //
  // issuerUrl is NOT taken from the request body: it is a deployment-time
  // configuration value (ISSUER_BASE_URL env var). Accepting it from the
  // request body would be a Server-Side Request Forgery vulnerability that
  // could expose internal services or cloud metadata endpoints.

  router.post('/request-credential', asyncHandler(async (req: Request, res: Response) => {
    const { subjectOverrides } = req.body as {
      subjectOverrides?: Record<string, unknown>
    }
    const issuerUrl = ISSUER_BASE_URL

    // Step 1: Get credential offer
    const offerResp = await axios.get<{
      offer: {
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': string
          }
        }
      }
    }>(`${issuerUrl}/credential-offer`, { params: { holder_did: identity.did } })

    const preAuthCode =
      offerResp.data.offer.grants[
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'
      ]['pre-authorized_code']

    // Step 2: Exchange code for token
    const tokenResp = await axios.post<{ access_token: string; c_nonce: string }>(
      `${issuerUrl}/token`,
      new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode,
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    )
    const { access_token, c_nonce } = tokenResp.data

    // Step 3: Build proof-of-possession JWT
    const popJwt = await buildProofOfPossessionJwt(identity, c_nonce, issuerUrl)

    // Step 4: Request credential
    const credResp = await axios.post<{ credential: string }>(
      `${issuerUrl}/credentials`,
      {
        format: 'jwt_vc_json',
        types: ['VerifiableCredential', 'AgentCapabilityCredential'],
        proof: { proof_type: 'jwt', jwt: popJwt },
        credential_subject: subjectOverrides,
      },
      { headers: { Authorization: `Bearer ${access_token}` } }
    )

    const jwtVc = credResp.data.credential
    const payload = JSON.parse(Buffer.from(jwtVc.split('.')[1], 'base64url').toString())
    const decoded = payload.vc as AgentCapabilityVC

    const signed: SignedJwtVC = { jwt: jwtVc, decoded }
    const credId = credentialStore.store(signed)

    res.json({
      credentialId: credId,
      issuerDid: decoded.issuer,
      holderDid: identity.did,
      expirationDate: decoded.expirationDate,
    })
  }))

  // ── Credential Store ───────────────────────────────────────────────────────

  router.get('/credentials', (_req: Request, res: Response) => {
    res.json(credentialStore.getAll())
  })

  router.get('/credentials/:id', (req: Request, res: Response) => {
    const cred = credentialStore.getById(req.params.id)
    if (!cred) { res.status(404).json({ error: 'Not found' }); return }
    res.json(cred)
  })

  // ── Presentation (OID4VP) ─────────────────────────────────────────────────

  router.post('/present', asyncHandler(async (req: Request, res: Response) => {
    const authRequest = req.body as OID4VPAuthRequest

    // Validate response_uri before making any outbound request with it.
    // An attacker-supplied response_uri pointing to an internal service would be an SSRF.
    validateCallbackUrl(authRequest.response_uri)

    const response = await presentationHandler.handlePresentationRequest(authRequest)

    // Submit VP to verifier's response_uri
    if (authRequest.response_uri) {
      await axios.post(authRequest.response_uri, {
        vp_token: response.vpJwt,
        state: authRequest.nonce,
      })
    }

    res.json({
      nullifier: response.nullifier,
      contextHash: response.zkProof.contextHash,
      publicSignals: response.zkProof.publicSignals,
    })
  }))

  // ── Status ────────────────────────────────────────────────────────────────

  router.get('/identity', (_req: Request, res: Response) => {
    res.json({ did: identity.did, address: identity.signer.address })
  })

  // ── Error handler for this router ─────────────────────────────────────────

  router.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: number }).status ?? 500
    console.error('[holder] Route error:', err.message)
    res.status(status).json({ error: err.message ?? 'Internal server error' })
  })

  return router
}

async function buildProofOfPossessionJwt(
  identity: EthrDIDIdentity,
  nonce: string,
  audience: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'ES256K', typ: 'openid4vci-proof+jwt', kid: `${identity.did}#controller` }
  const payload = { iss: identity.did, aud: audience, iat: now, exp: now + 300, nonce }

  const h = Buffer.from(JSON.stringify(header)).toString('base64url')
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const input = `${h}.${p}`
  const sig = identity.signer.signingKey.sign(ethers.keccak256(ethers.toUtf8Bytes(input)))
  const sigB64 = Buffer.from(sig.r.slice(2) + sig.s.slice(2), 'hex').toString('base64url')
  return `${input}.${sigB64}`
}
