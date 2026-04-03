import { EthrDID } from 'ethr-did'
import { getResolver } from 'ethr-did-resolver'
import { Resolver } from 'did-resolver'
import { ethers } from 'ethers'
import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_CHAIN_HEX,
  ERC1056_REGISTRY,
  BASE_SEPOLIA_RPC,
  DID_ETHR_PREFIX,
} from '@acta/shared'

export interface EthrDIDIdentity {
  /** Full DID: "did:ethr:0x14f69:0x<checksummed-address>" */
  did: string
  /** Underlying EthrDID instance for JWT signing and DID document updates */
  ethrDid: EthrDID
  /** JSON-RPC provider connected to Base Sepolia */
  provider: ethers.JsonRpcProvider
  /** Wallet for signing Ethereum transactions */
  signer: ethers.Wallet
  /** Universal DID resolver capable of resolving any did:ethr DID */
  resolver: Resolver
}

/**
 * Creates or loads a did:ethr identity on Base Sepolia.
 *
 * If PRIVATE_KEY environment variable is set, loads that key.
 * Otherwise generates a fresh key and logs the address.
 *
 * The DID has the form: did:ethr:0x14f69:0x<checksummedAddress>
 *
 * No transaction is sent to ERC-1056 at creation time. The DID document is
 * implicit from the Ethereum address until the first key rotation or attribute
 * update — this is native to ERC-1056 (EthereumDIDRegistry).
 *
 * Key format: secp256k1 (matching Ethereum) — used for ES256K JWT signing.
 */
export async function createEthrDIDIdentity(
  privateKey?: string
): Promise<EthrDIDIdentity> {
  const rpc = BASE_SEPOLIA_RPC
  const provider = new ethers.JsonRpcProvider(rpc, BASE_SEPOLIA_CHAIN_ID, {
    staticNetwork: true,
  })

  const wallet = privateKey
    ? new ethers.Wallet(privateKey, provider)
    : ethers.Wallet.createRandom().connect(provider)

  if (!privateKey) {
    console.log(`[did:ethr] Generated new identity: ${wallet.address}`)
    // Private key intentionally NOT logged — write it to a secrets manager or .env file.
    // It is available as wallet.privateKey during this process lifetime only.
    console.warn(`[did:ethr] WARNING: running with an ephemeral key — set the PRIVATE_KEY env var to persist identity`)
  }

  const ethrDid = new EthrDID({
    identifier:      wallet.address,
    privateKey:      wallet.privateKey.slice(2), // EthrDID expects no 0x prefix
    provider:        provider as unknown as Parameters<typeof EthrDID>[0]['provider'],
    chainNameOrId:   BASE_SEPOLIA_CHAIN_ID,
    registry:        ERC1056_REGISTRY,
  })

  const resolver = new Resolver(
    getResolver({
      networks: [
        {
          name:      'base-sepolia',
          chainId:   BASE_SEPOLIA_CHAIN_ID,
          rpcUrl:    rpc,
          registry:  ERC1056_REGISTRY,
        },
      ],
    })
  )

  // ethrDid.did returns "did:ethr:0x14f69:0x<address>"
  return {
    did:      ethrDid.did,
    ethrDid,
    provider,
    signer:   wallet,
    resolver,
  }
}

/**
 * Resolves a did:ethr DID document and returns the first secp256k1 verification key.
 * Used to verify JWT signatures from unknown actors.
 */
export async function resolvePublicKey(
  did: string,
  resolver: Resolver
): Promise<string> {
  const result = await resolver.resolve(did)
  if (!result.didDocument) {
    throw new Error(`Failed to resolve DID: ${did}`)
  }
  const vms = result.didDocument.verificationMethod ?? []
  const secp = vms.find(
    vm => vm.type === 'EcdsaSecp256k1VerificationKey2019' ||
          vm.type === 'EcdsaSecp256k1RecoveryMethod2020'
  )
  if (!secp) {
    throw new Error(`No secp256k1 verification method found for ${did}`)
  }
  const key = secp.publicKeyHex ?? secp.publicKeyBase58 ?? secp.publicKeyJwk?.x
  if (!key) throw new Error(`Cannot extract public key from verification method for ${did}`)
  return String(key)
}
