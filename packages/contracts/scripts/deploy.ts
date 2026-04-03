import { ethers } from 'hardhat'
import * as fs from 'fs'
import * as path from 'path'

/**
 * Deploys all ACTA contracts in dependency order:
 *   1. NullifierRegistry
 *   2. OpenACCredentialAnchor
 *   3. OpenACSnarkVerifier
 *   4. GeneralizedPredicateVerifier
 *   5. ZKReputationAccumulator
 *   6. AgentAccessGate (example — with a dummy policyId)
 *   7. AnonymousReputationPool (example)
 *
 * Writes deployed addresses to deployments/<network>.json.
 */
async function main() {
  const [deployer] = await ethers.getSigners()
  console.log(`Deploying with account: ${deployer.address}`)

  const balance = await ethers.provider.getBalance(deployer.address)
  console.log(`Account balance: ${ethers.formatEther(balance)} ETH`)

  const network = await ethers.provider.getNetwork()
  console.log(`Network: ${network.name} (chainId: ${network.chainId})`)

  // ── 1. NullifierRegistry ──────────────────────────────────────────────
  const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry')
  const nullifierRegistry = await NullifierRegistry.deploy(deployer.address)
  await nullifierRegistry.waitForDeployment()
  const nullifierRegistryAddr = await nullifierRegistry.getAddress()
  console.log(`NullifierRegistry deployed to: ${nullifierRegistryAddr}`)

  // ── 2. OpenACCredentialAnchor ─────────────────────────────────────────
  const OpenACCredentialAnchor = await ethers.getContractFactory('OpenACCredentialAnchor')
  const credentialAnchor = await OpenACCredentialAnchor.deploy(deployer.address)
  await credentialAnchor.waitForDeployment()
  const credentialAnchorAddr = await credentialAnchor.getAddress()
  console.log(`OpenACCredentialAnchor deployed to: ${credentialAnchorAddr}`)

  // ── 3. OpenACSnarkVerifier ────────────────────────────────────────────
  const OpenACSnarkVerifier = await ethers.getContractFactory('OpenACSnarkVerifier')
  const snarkVerifier = await OpenACSnarkVerifier.deploy()
  await snarkVerifier.waitForDeployment()
  const snarkVerifierAddr = await snarkVerifier.getAddress()
  console.log(`OpenACSnarkVerifier deployed to: ${snarkVerifierAddr}`)

  // ── 4. GeneralizedPredicateVerifier ───────────────────────────────────
  const GeneralizedPredicateVerifier = await ethers.getContractFactory('GeneralizedPredicateVerifier')
  const gpVerifier = await GeneralizedPredicateVerifier.deploy(
    deployer.address,
    nullifierRegistryAddr,
    credentialAnchorAddr
  )
  await gpVerifier.waitForDeployment()
  const gpVerifierAddr = await gpVerifier.getAddress()
  console.log(`GeneralizedPredicateVerifier deployed to: ${gpVerifierAddr}`)

  // ── Authorize GPVerifier to register nullifiers ───────────────────────
  const authTx = await nullifierRegistry.lockAuthorization(gpVerifierAddr)
  await authTx.wait()
  console.log(`Authorized GPVerifier to register nullifiers`)

  // ── Register circuit verifier ─────────────────────────────────────────
  const circuitId = await snarkVerifier.circuitId()
  const regTx = await gpVerifier.registerCircuitVerifier(circuitId, snarkVerifierAddr)
  await regTx.wait()
  console.log(`Registered OpenACSnarkVerifier for circuit: ${circuitId}`)

  // ── 5. ZKReputationAccumulator ────────────────────────────────────────
  const ZKReputationAccumulator = await ethers.getContractFactory('ZKReputationAccumulator')
  const reputationAccumulator = await ZKReputationAccumulator.deploy(deployer.address, gpVerifierAddr)
  await reputationAccumulator.waitForDeployment()
  const reputationAccumulatorAddr = await reputationAccumulator.getAddress()
  console.log(`ZKReputationAccumulator deployed to: ${reputationAccumulatorAddr}`)

  // ── 6. AgentAccessGate (example, no real policyId yet) ───────────────
  const placeholderPolicyId = ethers.keccak256(ethers.toUtf8Bytes('placeholder-policy'))
  const AgentAccessGate = await ethers.getContractFactory('AgentAccessGate')
  const agentAccessGate = await AgentAccessGate.deploy(deployer.address, gpVerifierAddr, placeholderPolicyId)
  await agentAccessGate.waitForDeployment()
  const agentAccessGateAddr = await agentAccessGate.getAddress()
  console.log(`AgentAccessGate deployed to: ${agentAccessGateAddr}`)

  // ── 7. AnonymousReputationPool ────────────────────────────────────────
  const AnonymousReputationPool = await ethers.getContractFactory('AnonymousReputationPool')
  const anonymousReputationPool = await AnonymousReputationPool.deploy(
    deployer.address,
    gpVerifierAddr,
    reputationAccumulatorAddr,
    placeholderPolicyId
  )
  await anonymousReputationPool.waitForDeployment()
  const anonymousReputationPoolAddr = await anonymousReputationPool.getAddress()
  console.log(`AnonymousReputationPool deployed to: ${anonymousReputationPoolAddr}`)

  // ── Save addresses ────────────────────────────────────────────────────
  const deployments = {
    network:                   network.name,
    chainId:                   network.chainId.toString(),
    deployer:                  deployer.address,
    deployedAt:                new Date().toISOString(),
    NullifierRegistry:         nullifierRegistryAddr,
    OpenACCredentialAnchor:    credentialAnchorAddr,
    OpenACSnarkVerifier:       snarkVerifierAddr,
    GeneralizedPredicateVerifier: gpVerifierAddr,
    ZKReputationAccumulator:   reputationAccumulatorAddr,
    AgentAccessGate:           agentAccessGateAddr,
    AnonymousReputationPool:   anonymousReputationPoolAddr,
  }

  const deploymentsDir = path.join(__dirname, '../deployments')
  if (!fs.existsSync(deploymentsDir)) fs.mkdirSync(deploymentsDir, { recursive: true })
  fs.writeFileSync(
    path.join(deploymentsDir, `${network.name}.json`),
    JSON.stringify(deployments, null, 2)
  )
  console.log(`\nDeployments saved to deployments/${network.name}.json`)
  console.log('\n✅ All contracts deployed successfully')
}

main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
