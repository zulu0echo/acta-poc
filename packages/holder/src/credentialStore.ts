import type { SignedJwtVC, AgentCapabilityVC } from '@acta/shared'
import * as fs from 'fs'
import * as path from 'path'

const STORE_PATH =
  process.env.CREDENTIAL_STORE_PATH ?? path.join(process.cwd(), '.credential-store.json')

interface StoredCredential {
  id: string
  jwtVc: string
  decoded: AgentCapabilityVC
  receivedAt: number
  issuerDid: string
  commitmentHex?: string
  merkleRootHex?: string
  /**
   * Persisted BN254 randomness (hex, no 0x prefix) used when importing this credential
   * into the OpenAC wallet unit. Must be supplied on re-import so the same on-chain
   * commitment is reproduced. If lost, re-import will generate a different commitment
   * and fail with CommitmentAlreadyAnchored on the on-chain anchor contract.
   */
  randomnessHex?: string
}

/**
 * Simple file-backed credential store for the holder.
 *
 * In production, replace with an encrypted database or HSM-backed store.
 * The store contains plaintext JWT-VCs including all credential attributes.
 * Protect the store file with filesystem permissions (chmod 600).
 *
 * Concurrency: this implementation is single-process and not concurrent-write-safe.
 * For multi-instance deployments, use a database with row-level locking.
 */
export class CredentialStore {
  private credentials: Map<string, StoredCredential> = new Map()

  constructor() {
    this.load()
  }

  private load(): void {
    if (fs.existsSync(STORE_PATH)) {
      try {
        const raw = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8')) as StoredCredential[]
        for (const cred of raw) {
          this.credentials.set(cred.id, cred)
        }
      } catch {
        // Corrupt store — start fresh
        console.warn(`[CredentialStore] Could not load ${STORE_PATH}, starting with empty store`)
      }
    }
  }

  private save(): void {
    const arr = Array.from(this.credentials.values())
    const tmp = STORE_PATH + '.tmp'
    // Write to a temp file then rename atomically to prevent partial writes corrupting the store.
    fs.writeFileSync(tmp, JSON.stringify(arr, null, 2), { mode: 0o600 })
    fs.renameSync(tmp, STORE_PATH)
  }

  /**
   * Store a received JWT-VC. Returns the generated credential ID.
   */
  store(signed: SignedJwtVC): string {
    const id = `${signed.decoded.issuer}::${signed.decoded.issuanceDate}`
    const record: StoredCredential = {
      id,
      jwtVc:      signed.jwt,
      decoded:    signed.decoded,
      receivedAt: Date.now(),
      issuerDid:  signed.decoded.issuer,
    }
    this.credentials.set(id, record)
    this.save()
    return id
  }

  /**
   * Attach the on-chain commitment, merkle root, and the BN254 randomness that produced them.
   * Call this after anchorCredential() succeeds. The randomnessHex must be persisted so that
   * re-importing the credential (e.g., after a server restart) reproduces the same commitment.
   */
  setAnchorData(
    credentialId: string,
    commitmentHex: string,
    merkleRootHex: string,
    randomnessHex: string
  ): void {
    const cred = this.credentials.get(credentialId)
    if (!cred) throw new Error(`Credential ${credentialId} not found in store`)
    cred.commitmentHex = commitmentHex
    cred.merkleRootHex = merkleRootHex
    cred.randomnessHex = randomnessHex
    this.save()
  }

  /** @deprecated Use setAnchorData() to also persist randomness. */
  setCommitment(credentialId: string, commitmentHex: string): void {
    const cred = this.credentials.get(credentialId)
    if (!cred) throw new Error(`Credential ${credentialId} not found in store`)
    cred.commitmentHex = commitmentHex
    this.save()
  }

  getById(id: string): StoredCredential | undefined {
    return this.credentials.get(id)
  }

  getAll(): StoredCredential[] {
    return Array.from(this.credentials.values())
  }

  /**
   * Returns the most recently received credential.
   */
  getLatest(): StoredCredential | undefined {
    const all = this.getAll().sort((a, b) => b.receivedAt - a.receivedAt)
    return all[0]
  }

  remove(id: string): void {
    this.credentials.delete(id)
    this.save()
  }
}
