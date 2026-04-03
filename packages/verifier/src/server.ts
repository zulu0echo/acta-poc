import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { createEthrDIDIdentity } from '../../issuer/src/didEthrSetup'
import { createVerifierRouter } from './verifierRoutes'

const PORT = parseInt(process.env.VERIFIER_PORT ?? '3003', 10)

async function start() {
  const identity = await createEthrDIDIdentity(process.env.VERIFIER_PRIVATE_KEY)
  console.log(`[verifier] DID: ${identity.did}`)

  const app = express()
  app.use(cors())
  app.use(express.json())
  app.use('/', createVerifierRouter(identity))
  app.get('/health', (_req, res) => res.json({ status: 'ok', did: identity.did }))

  app.listen(PORT, () => console.log(`[verifier] Listening on http://localhost:${PORT}`))
}

start().catch(err => { console.error('[verifier] Fatal:', err); process.exit(1) })
