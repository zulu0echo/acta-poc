export function generateAnchorTx(holderAddress: string, commitment: string, merkleRoot: string) {
  return {
    to:       '0xOpenACCredentialAnchor',
    from:     holderAddress,
    function: 'anchorCredential(uint256 agentId, bytes32 credentialType, bytes32 commitment, bytes32 merkleRoot)',
    args: {
      agentId:        `uint256(uint160(${holderAddress}))`,
      credentialType: '0x' + Array.from(new TextEncoder().encode('AgentCapabilityCredential')).map(b => b.toString(16).padStart(2, '0')).join('').padEnd(64, '0').slice(0, 64),
      commitment,
      merkleRoot,
    },
    gasEstimate: '~65,000 gas',
    event: 'CredentialAnchored(agentId, credentialType, commitment, merkleRoot, anchoredAt)',
  }
}

export function generateOID4VPResponse(
  holderDid: string,
  verifierDid: string,
  nullifier: string,
  predicateProgramHash: string
) {
  return {
    vp_token: {
      header: { alg: 'ES256K', typ: 'JWT', kid: `${holderDid}#controller` },
      payload: {
        iss:    holderDid,
        aud:    verifierDid,
        vp:     { '@context': ['…'], type: ['VerifiablePresentation'], verifiableCredential: ['[JWT-VC]'] },
        zkProof: {
          proofBytes:   '0x[256-byte-groth16-proof]',
          publicSignals: {
            nullifier,
            predicateProgramHash,
            contextHash:            '0x[32-byte-context-hash]',
            issuerPubKeyCommitment: '0x[32-byte-commitment]',
            credentialMerkleRoot:   '0x[32-byte-root]',
            expiryBlock:            12456789,
          },
        },
      },
    },
  }
}
