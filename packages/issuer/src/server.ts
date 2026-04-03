import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { createEthrDIDIdentity } from './didEthrSetup'
import { createIssuanceRouter } from './issuanceRoutes'

const PORT = parseInt(process.env.ISSUER_PORT ?? '3001', 10)

async function start() {
  const identity = await createEthrDIDIdentity(process.env.ISSUER_PRIVATE_KEY)
  console.log(`[issuer] DID: ${identity.did}`)
  console.log(`[issuer] Address: ${identity.signer.address}`)

  const app = express()
  app.use(cors())
  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))

  app.use('/', createIssuanceRouter(identity))

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', did: identity.did, address: identity.signer.address })
  })

  app.listen(PORT, () => {
    console.log(`[issuer] Listening on http://localhost:${PORT}`)
    console.log(`[issuer] Credential offer: GET http://localhost:${PORT}/credential-offer`)
    console.log(`[issuer] OID4VCI metadata: GET http://localhost:${PORT}/.well-known/openid-credential-issuer`)
  })
}

start().catch(err => {
  console.error('[issuer] Fatal error:', err)
  process.exit(1)
})
