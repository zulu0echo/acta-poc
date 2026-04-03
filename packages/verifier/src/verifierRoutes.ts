import { Router, type Request, type Response, type NextFunction } from 'express'
import type { EthrDIDIdentity } from '../../issuer/src/didEthrSetup'
import { PredicateBuilder } from './predicateBuilder'
import { PresentationRequestBuilder } from './presentationRequest'
import { PolicyRegistry } from './policyRegistry'
import { OffchainVerifier } from './offchainVerifier'
import { OnchainSubmitter } from './onchainSubmitter'
import type { OpenACPresentation, OID4VPAuthRequest } from '@acta/shared'
import { ethers } from 'ethers'

const GP_VERIFIER_ADDRESS = process.env.GP_VERIFIER_ADDRESS ?? ''
const VERIFIER_BASE_URL   = process.env.VERIFIER_BASE_URL   ?? 'http://localhost:3003'

// In-memory session store (replace with Redis in production).
// Key: sessionId (UUID). Each session has its own nonce so parallel presentations
// for the same policyId do not interfere with each other.
const sessions = new Map<string, {
  authRequest: OID4VPAuthRequest
  nonce: bigint
  policyId: string
  expectedHolderDid?: string
  result?: unknown
  createdAt: number
}>()

// Clean up sessions older than 10 minutes to prevent unbounded growth.
const SESSION_TTL_MS = 10 * 60 * 1000
setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS
  for (const [id, s] of sessions) {
    if (s.createdAt < cutoff) sessions.delete(id)
  }
}, 60_000)

/**
 * Wraps async Express routes to forward rejections to the error handler.
 * Without this, in Express 4 unhandled async rejections leave requests hanging.
 */
function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next)
  }
}

export function createVerifierRouter(identity: EthrDIDIdentity): Router {
  const router = Router()
  const policyRegistry   = new PolicyRegistry(identity, GP_VERIFIER_ADDRESS)
  const requestBuilder   = new PresentationRequestBuilder(identity)
  const offchainVerifier = new OffchainVerifier(identity)
  const onchainSubmitter = new OnchainSubmitter(identity, GP_VERIFIER_ADDRESS)

  // ── Policy Registration ───────────────────────────────────────────────────

  router.post('/register-policy', asyncHandler(async (req: Request, res: Response) => {
    const { predicateConditions, issuerCommitment, expiryBlock } = req.body as {
      predicateConditions: Array<{
        attribute: string
        operator: string
        value: unknown
        connective?: string
      }>
      issuerCommitment: string
      expiryBlock?: number
    }

    if (!Array.isArray(predicateConditions) || predicateConditions.length === 0) {
      res.status(400).json({ error: 'predicateConditions must be a non-empty array' })
      return
    }

    const builder = new PredicateBuilder('AgentCapabilityCredential')
    for (let i = 0; i < predicateConditions.length; i++) {
      const c = predicateConditions[i]
      if (i > 0) {
        if (c.connective === 'OR') builder.or()
        else builder.and()
      }
      builder.require(c.attribute)[mapOperator(c.operator)](c.value as never)
    }

    const predicate = builder.build()

    // In dev mode without a deployed contract, compute policyId locally
    const policyId = GP_VERIFIER_ADDRESS
      ? await policyRegistry.registerPolicy(predicate, issuerCommitment ?? ethers.ZeroHash, expiryBlock ?? 0)
      : ethers.keccak256(ethers.toUtf8Bytes(predicate.toJSON()))

    res.json({
      policyId,
      predicateProgramHash: predicate.hash,
      description: predicate.toDescription(),
    })
  }))

  // ── Presentation Request (OID4VP) ─────────────────────────────────────────

  router.post('/presentation-request', asyncHandler(async (req: Request, res: Response) => {
    const { policyId, predicateJson, holderDid } = req.body as {
      policyId: string
      predicateJson: string
      holderDid?: string
    }

    if (!policyId || !predicateJson) {
      res.status(400).json({ error: 'policyId and predicateJson are required' })
      return
    }

    const nonce = BigInt('0x' + Buffer.from(ethers.randomBytes(8)).toString('hex'))

    const predicate = JSON.parse(predicateJson)
    const result = requestBuilder.createPresentationRequest({
      policyId,
      predicate: {
        toJSON:        () => predicateJson,
        hash:          predicate.hash ?? ethers.keccak256(ethers.toUtf8Bytes(predicateJson)),
        toDescription: () => '',
        raw:           predicate,
      } as never,
      verifierCallbackUrl:    `${VERIFIER_BASE_URL}/verify-callback/${policyId}`,
      sessionNonce:           nonce,
      onchainVerifierAddress: GP_VERIFIER_ADDRESS,
    })

    sessions.set(result.sessionId, {
      authRequest:       result.authorizationRequest,
      nonce,
      policyId,
      expectedHolderDid: holderDid,
      createdAt:         Date.now(),
    })

    res.json({
      requestUri: result.requestUri,
      sessionId:  result.sessionId,
      // Expose the sessionId so the holder can include it in the callback as `state`,
      // allowing the verifier to look up the exact session and nonce.
      nonce:      nonce.toString(),
    })
  }))

  // ── VP Callback ───────────────────────────────────────────────────────────

  router.post('/verify-callback/:policyId', asyncHandler(async (req: Request, res: Response) => {
    const { vp_token, state: sessionId } = req.body as {
      vp_token: string
      state?: string
    }
    const policyId = req.params.policyId

    if (!vp_token) { res.status(400).json({ error: 'missing vp_token' }); return }

    // Extract zkProof and holder DID from VP JWT
    const parts = vp_token.split('.')
    if (parts.length !== 3) {
      res.status(400).json({ error: 'malformed vp_token: expected compact JWT' }); return
    }
    const vpPayload    = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    const presentation = vpPayload.zkProof as OpenACPresentation
    const holderDid    = vpPayload.iss as string
    const issuerDid    = extractIssuerFromVC(vpPayload.vp?.verifiableCredential?.[0] ?? '')

    // Phase 1: Off-chain verification
    const offchainResult = await offchainVerifier.verifyOffchain({
      presentation,
      policyId,
      issuerDid,
      vpJwt:    vp_token,
      holderDid,
    })
    if (!offchainResult.valid) {
      res.status(422).json({
        error:  'off-chain verification failed',
        reason: offchainResult.reason,
      })
      return
    }

    // Phase 2: On-chain submission
    let onchainResult = null
    if (GP_VERIFIER_ADDRESS) {
      // Look up the nonce by sessionId (supplied as `state` in the callback).
      // Falling back to any session with the matching policyId is WRONG: if two
      // concurrent sessions exist for the same policy, the wrong nonce is used,
      // causing a ContextHashMismatch revert. Always require an explicit sessionId.
      const session = sessionId ? sessions.get(sessionId) : undefined
      if (!session) {
        res.status(400).json({
          error: 'Unknown or expired session. Include sessionId as `state` in the VP callback.',
        })
        return
      }
      if (session.policyId !== policyId) {
        res.status(400).json({ error: 'Session policyId does not match callback policyId' })
        return
      }

      onchainResult = await onchainSubmitter.submit({
        policyId,
        presentation,
        agentDid: holderDid,
        nonce:    session.nonce,
      })

      // Clean up session after successful use to prevent replay
      sessions.delete(sessionId!)
    }

    res.json({
      verified:  true,
      offchain:  { valid: true, timingMs: offchainResult.timingMs },
      onchain:   onchainResult,
      nullifier: presentation.publicSignals.nullifier,
      holderDid,
    })
  }))

  // ── Policy List ───────────────────────────────────────────────────────────

  router.get('/policies', (_req: Request, res: Response) => {
    res.json(policyRegistry.getAllPolicies())
  })

  router.get('/identity', (_req: Request, res: Response) => {
    res.json({ did: identity.did, address: identity.signer.address })
  })

  // ── Error handler ─────────────────────────────────────────────────────────

  router.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: number }).status ?? 500
    console.error('[verifier] Route error:', err.message)
    res.status(status).json({ error: err.message ?? 'Internal server error' })
  })

  return router
}

function mapOperator(op: string): keyof import('./predicateBuilder').AttributeConstraint {
  const map: Record<string, string> = {
    gte: 'greaterThanOrEqual', '>=': 'greaterThanOrEqual',
    lte: 'lessThanOrEqual',    '<=': 'lessThanOrEqual',
    eq:  'equals', '=': 'equals', '==': 'equals',
    neq: 'notEquals', '!=': 'notEquals',
    includes: 'includes',
    not_in: 'notIn', notIn: 'notIn',
    between: 'between',
  }
  return (map[op] ?? 'equals') as keyof import('./predicateBuilder').AttributeConstraint
}

function extractIssuerFromVC(vcJwt: string): string {
  try {
    const [, payloadB64] = vcJwt.split('.')
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
    return payload.iss ?? payload.vc?.issuer ?? ''
  } catch {
    return ''
  }
}
