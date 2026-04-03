import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { createEthrDIDIdentity } from './didEthrSetup'
import { createHolderRouter } from './holderRoutes'

const PORT = parseInt(process.env.HOLDER_PORT ?? '3002', 10)

async function start() {
  const identity = await createEthrDIDIdentity(process.env.HOLDER_PRIVATE_KEY)
  console.log(`[holder] DID: ${identity.did}`)

  const app = express()
  app.use(cors())
  app.use(express.json())
  app.use('/', createHolderRouter(identity))
  app.get('/health', (_req, res) => res.json({ status: 'ok', did: identity.did }))

  app.listen(PORT, () => console.log(`[holder] Listening on http://localhost:${PORT}`))
}

start().catch(err => { console.error('[holder] Fatal:', err); process.exit(1) })
