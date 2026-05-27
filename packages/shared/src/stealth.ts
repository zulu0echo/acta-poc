/**
 * Stealth-address derivation for ACTA unlinkability (ADR-0002).
 *
 * The holder owns a 256-bit master secret. For every presentation context
 * `(verifierAddress, policyId, sessionIndex)` it derives a fresh secp256k1
 * keypair and the corresponding Ethereum address. The stealth address
 * signs the VP JWT and is `msg.sender` for the on-chain verification call.
 *
 * Derivation:
 *
 *   stealthSeed = HKDF-SHA256(
 *     ikm  = holderMasterSecret,
 *     salt = "acta-stealth/v1",
 *     info = "verifier:" || verifierAddress || "|policy:" || policyId || "|session:" || sessionIndex
 *   )
 *   stealthPriv = SHA256(stealthSeed) mod (n - 1) + 1
 *   stealthPub  = stealthPriv · G                          (secp256k1)
 *   stealthAddr = keccak256(stealthPub.uncompressed[1:])[12:]
 *
 * Properties (see ADR-0002 for analysis):
 *   - Determinism: same inputs ⇒ same keypair (the holder can recover from
 *     local state loss).
 *   - Indistinguishability: the address is pseudorandom given an attacker
 *     who does not know the master.
 *   - Domain separation: the "acta-stealth/v1" salt isolates ACTA stealth
 *     keys from any other key derivation the holder might do with the same
 *     master secret.
 *
 * This module is dependency-free of `ethers` for the derivation core to
 * keep the function self-contained and audit-friendly; we use `ethers`
 * only for the public-key → Ethereum address conversion at the end.
 */

import { createHash, createHmac } from 'crypto'
import { ethers } from 'ethers'

/** secp256k1 group order n (from SEC 2 v2). */
const SECP256K1_N =
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n

const STEALTH_SALT = Buffer.from('acta-stealth/v1', 'utf8')

/** Derivation context. */
export interface StealthContext {
  /** 0x-prefixed Ethereum address of the verifier contract or DID. */
  verifierAddress: string
  /** 0x-prefixed bytes32 policy id. */
  policyId: string
  /**
   * Monotonically increasing per-presentation index. Even within the same
   * `(verifier, policyId)` pair, callers SHOULD bump this each session for
   * full unlinkability across sessions.
   */
  sessionIndex: number | bigint
}

/** Output of a stealth derivation. */
export interface StealthIdentity {
  /** 0x-prefixed 32-byte secp256k1 private key. */
  privateKey: string
  /** 0x-prefixed uncompressed (0x04…) public key in hex. */
  publicKeyUncompressed: string
  /** 0x-prefixed 20-byte Ethereum address (EIP-55 checksum). */
  address: string
  /** `did:ethr` DID for the stealth address (Base Sepolia chain prefix). */
  did: string
}

/** Chain prefix for the stealth DID (kept aligned with @acta/shared/constants). */
const STEALTH_DID_CHAIN_PREFIX = 'did:ethr:0x14f69:'

// ── HKDF (RFC 5869) ────────────────────────────────────────────────────────

function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
  return createHmac('sha256', salt).update(ikm).digest()
}

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const out: Buffer[] = []
  // Use explicit `Buffer<ArrayBufferLike>` to match createHmac().digest()'s
  // newer @types/node signature.
  let t: Buffer = Buffer.from([])
  let counter = 1
  while (Buffer.concat(out).length < length) {
    const hm = createHmac('sha256', prk)
    hm.update(t)
    hm.update(info)
    hm.update(Buffer.from([counter]))
    t = Buffer.from(hm.digest())
    out.push(t)
    counter += 1
  }
  return Buffer.from(Buffer.concat(out).slice(0, length))
}

function hkdf(masterSecret: Buffer, info: Buffer, length: number): Buffer {
  const prk = hkdfExtract(STEALTH_SALT, masterSecret)
  return hkdfExpand(prk, info, length)
}

// ── Helpers ────────────────────────────────────────────────────────────────

function hexToBuffer(hex: string): Buffer {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) {
    throw new Error('stealth: hex string must have even length')
  }
  return Buffer.from(clean, 'hex')
}

function buildInfo(ctx: StealthContext): Buffer {
  // Canonical lower-case hex for verifier/policy plus decimal session.
  const verifier = ctx.verifierAddress.toLowerCase()
  const policy = ctx.policyId.toLowerCase()
  const session = BigInt(ctx.sessionIndex).toString(10)
  return Buffer.from(
    `verifier:${verifier}|policy:${policy}|session:${session}`,
    'utf8',
  )
}

function privFromSeed(seed: Buffer): bigint {
  // priv = SHA256(seed) mod (n - 1) + 1   →  ∈ [1, n-1]
  const digest = createHash('sha256').update(seed).digest()
  const raw = BigInt('0x' + digest.toString('hex'))
  return (raw % (SECP256K1_N - 1n)) + 1n
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Derive a stealth identity from the holder's master secret and a context.
 *
 * `masterSecret` must be at least 32 bytes (rejected otherwise). Pass the
 * holder's persistent 256-bit secret here — never a per-session value.
 */
export function deriveStealthIdentity(
  masterSecret: Uint8Array | Buffer | string,
  ctx: StealthContext,
): StealthIdentity {
  // Normalise master to buffer
  let mk: Buffer
  if (typeof masterSecret === 'string') {
    mk = hexToBuffer(masterSecret)
  } else if (masterSecret instanceof Uint8Array) {
    mk = Buffer.from(masterSecret)
  } else {
    mk = masterSecret as Buffer
  }
  if (mk.length < 32) {
    throw new Error(
      `stealth: holderMasterSecret must be ≥ 32 bytes (got ${mk.length})`,
    )
  }

  // Argument validation
  if (!/^0x[0-9a-fA-F]{40}$/.test(ctx.verifierAddress)) {
    throw new Error(`stealth: verifierAddress must be a 20-byte 0x-prefixed hex (${ctx.verifierAddress})`)
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(ctx.policyId)) {
    throw new Error(`stealth: policyId must be a bytes32 0x-prefixed hex (${ctx.policyId})`)
  }
  const sessionIndex = BigInt(ctx.sessionIndex)
  if (sessionIndex < 0n) {
    throw new Error('stealth: sessionIndex must be ≥ 0')
  }

  const seed = hkdf(mk, buildInfo(ctx), 32)
  const priv = privFromSeed(seed)
  const privHex = '0x' + priv.toString(16).padStart(64, '0')

  // Use ethers to derive public key + address (well-audited path).
  const wallet = new ethers.SigningKey(privHex)
  const pubUncompressed = wallet.publicKey // 0x04 || x || y
  const addr = ethers.computeAddress(privHex) // EIP-55 checksum

  return {
    privateKey: privHex,
    publicKeyUncompressed: pubUncompressed,
    address: addr,
    did: STEALTH_DID_CHAIN_PREFIX + addr,
  }
}

/**
 * Compute the holder-binding commitment used by ADR-0003 anchoring.
 * Currently exposed as a Keccak-based fallback because the production
 * version requires Poseidon parity with the anchor contract.
 *
 * **Stability note**: this signature is part of the public ADR-0003 API.
 */
export function holderCommitment(masterSecret: Uint8Array | Buffer | string, salt: bigint): string {
  let mk: Buffer
  if (typeof masterSecret === 'string') mk = hexToBuffer(masterSecret)
  else if (masterSecret instanceof Uint8Array) mk = Buffer.from(masterSecret)
  else mk = masterSecret as Buffer
  if (mk.length < 32) {
    throw new Error('holderCommitment: masterSecret must be ≥ 32 bytes')
  }
  const hex = salt.toString(16).padStart(64, '0')
  const saltBuf = Buffer.from(hex, 'hex')
  // TODO(v0.5): replace with Poseidon to match the anchor circuit.
  // The Keccak placeholder is acceptable for v0.3 while the anchor V2
  // contract / circuit are still being designed.
  const h = createHash('sha256').update(mk).update(saltBuf).digest()
  return '0x' + h.toString('hex')
}
