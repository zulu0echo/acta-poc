const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ACTA Use Cases</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;height:100vh;display:flex;flex-direction:column;overflow:hidden}
#tabs{display:flex;background:#0d1117;border-bottom:1px solid #1e293b;flex-shrink:0;overflow-x:auto;gap:2px;padding:0 8px}
.tab{padding:8px 12px;cursor:pointer;font-size:11px;font-weight:600;color:#475569;border-bottom:2px solid transparent;white-space:nowrap;margin-bottom:-1px;transition:color .15s,border-color .15s}
.tab:hover{color:#94a3b8}
.tab.active{color:#e2e8f0;border-bottom-color:#16a34a}
#panels{flex:1;overflow:hidden;display:flex;flex-direction:column}
.panel{display:none;flex:1;overflow-y:auto;padding:16px 20px}
.panel.active{display:flex;flex-direction:column;gap:10px}
.sub{font-size:11px;color:#475569;margin-bottom:4px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:12px;flex:1}
.col{display:flex;flex-direction:column;gap:6px}
.col-label{font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:3px 8px;border-radius:4px;align-self:flex-start}
.col-label.erc{background:#3f0505;color:#ef4444;border:1px solid #3a1010}
.col-label.acta{background:#052e16;color:#16a34a;border:1px solid #0a3a1e}
.flow{display:flex;flex-direction:column;gap:0;flex:1}
.step{display:flex;align-items:stretch;gap:0;min-height:44px}
.step-actor{width:72px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:600;text-align:center;padding:4px 3px;border-radius:0;line-height:1.3}
.sa-issuer{color:#60a5fa;background:#0a1a35}
.sa-holder{color:#4ade80;background:#041a0c}
.sa-chain{color:#fbbf24;background:#1c1005}
.sa-verifier{color:#c084fc;background:#12062a}
.sa-erc{color:#f87171;background:#1f0505}
.step-content{flex:1;background:#161d2b;border:1px solid #1e293b;border-radius:6px;padding:7px 10px;margin:2px 0;font-size:11px;color:#cbd5e1;display:flex;flex-direction:column;justify-content:center;gap:2px}
.step-content strong{font-size:11px;font-weight:600;color:#e2e8f0;display:block}
.step-content code{font-family:'Fira Code','SF Mono',monospace;font-size:9.5px;color:#94a3b8;background:#0d1117;padding:1px 4px;border-radius:3px;display:inline-block;margin-top:2px}
.connector{display:flex;align-items:center;padding:0 4px;min-height:14px}
.conn-line{flex:1;height:1px;background:#1e293b;position:relative}
.conn-line::after{content:'▶';position:absolute;right:-4px;top:-7px;font-size:10px;color:#1e293b}
.conn-label{font-size:9px;color:#475569;padding:0 6px;white-space:nowrap}
.badge-e{display:inline-block;background:#2a0808;border:1px solid #7f1d1d;color:#fca5a5;border-radius:3px;padding:1px 5px;font-size:9px;font-weight:600;margin-top:2px}
.badge-p{display:inline-block;background:#052014;border:1px solid #14532d;color:#86efac;border-radius:3px;padding:1px 5px;font-size:9px;font-weight:600;margin-top:2px}
.callout{border-radius:6px;padding:7px 10px;font-size:11px;line-height:1.5}
.callout.red{background:#1a0606;border:1px solid #5c1414;color:#fca5a5}
.callout.green{background:#031208;border:1px solid #14532d;color:#86efac}
.flow-wide{display:flex;flex-direction:column;gap:0}
.step-wide{display:flex;align-items:stretch;gap:0;min-height:44px}
.step-actor-w{width:82px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:600;text-align:center;padding:4px 3px;border-radius:0;line-height:1.3}
.step-content-w{flex:1;background:#161d2b;border:1px solid #1e293b;border-radius:6px;padding:7px 10px;margin:2px 0;font-size:11px;color:#cbd5e1;display:flex;flex-direction:column;justify-content:center;gap:2px}
.sa-human{color:#a78bfa;background:#0e0720}
.legend{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:2px}
.leg{display:flex;align-items:center;gap:4px;font-size:10px}
.leg-dot{width:8px;height:8px;border-radius:50%}
</style>
</head>
<body>
<div id="tabs">
  <div class="tab active" onclick="show(0)">1 · DeFi delegation</div>
  <div class="tab" onclick="show(1)">2 · Agent reputation</div>
  <div class="tab" onclick="show(2)">3 · KYC / AML</div>
  <div class="tab" onclick="show(3)">4 · Open-source criteria</div>
  <div class="tab" onclick="show(4)">5 · Cross-protocol identity</div>
  <div class="tab" onclick="show(5)">6 · Reputation bootstrap</div>
  <div class="tab" onclick="show(6)">7 · Personhood</div>
</div>
<div id="panels">

<!-- 1. DeFi Delegation -->
<div class="panel active">
<div class="sub">Who participates at each step when an AI agent requests DeFi protocol access</div>
<div class="legend">
  <div class="leg"><div class="leg-dot" style="background:#60a5fa"></div><span style="color:#60a5fa">Issuer</span></div>
  <div class="leg"><div class="leg-dot" style="background:#4ade80"></div><span style="color:#4ade80">Agent / holder</span></div>
  <div class="leg"><div class="leg-dot" style="background:#fbbf24"></div><span style="color:#fbbf24">Chain</span></div>
  <div class="leg"><div class="leg-dot" style="background:#c084fc"></div><span style="color:#c084fc">Verifier</span></div>
  <div class="leg"><div class="leg-dot" style="background:#f87171"></div><span style="color:#f87171">ERC-8004</span></div>
</div>
<div class="cols">
  <div class="col">
    <div class="col-label erc">⚠ ERC-8004 path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Issuer</div><div class="step-content"><strong>Issues credential with all fields</strong><code>auditScore, modelHash, operator, caps</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">credential →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Registers on-chain with full credential</strong><span class="badge-e">⚠ all values public</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">registerAgent(…) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-erc">ERC-8004</div><div class="step-content"><strong>Stores every field publicly</strong><code>agentId → {score:91, wallet:0x9f3, caps}</code><span class="badge-e">⚠ competitor indexer reads all</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">access check →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Grants access</strong>Competitor already cloned the strategy</div></div>
    </div>
    <div class="callout red">Competitor sees: exact score, model provenance, operator wallet, call frequency</div>
  </div>
  <div class="col">
    <div class="col-label acta">🔒 ACTA path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Issuer</div><div class="step-content"><strong>Issues W3C JWT-VC</strong>Sent off-chain to agent only</div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">VC (private) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Generates Groth16 ZK proof locally</strong><code>auditScore ≥ 80 ∧ caps ⊇ 'evm-exec'</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">proof π + nullifier N →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-chain">Chain</div><div class="step-content"><strong>Verifies π, checks N not replayed</strong><code>verifyProof(π, policyId)</code><span class="badge-p">🔒 no credential values stored</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">access signal →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Grants capability: liquidate / MEV</strong>Knows only: proof valid ✓</div></div>
    </div>
    <div class="callout green">Competitor sees: predicate hash, proof valid/invalid. Nothing else.</div>
  </div>
</div>
</div>

<!-- 2. Agent Reputation -->
<div class="panel">
<div class="sub">Anonymous reviewer feedback via ZK accumulator — nullifier prevents double-voting without exposing identity</div>
<div class="legend">
  <div class="leg"><div class="leg-dot" style="background:#60a5fa"></div><span style="color:#60a5fa">Market / issuer</span></div>
  <div class="leg"><div class="leg-dot" style="background:#4ade80"></div><span style="color:#4ade80">Reviewer / holder</span></div>
  <div class="leg"><div class="leg-dot" style="background:#fbbf24"></div><span style="color:#fbbf24">ZK accumulator</span></div>
  <div class="leg"><div class="leg-dot" style="background:#c084fc"></div><span style="color:#c084fc">Reputation registry</span></div>
</div>
<div class="cols">
  <div class="col">
    <div class="col-label erc">⚠ ERC-8004 path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Market</div><div class="step-content"><strong>Exposes resolution agent for review</strong><code>getSummary(clientAddresses[])</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">request →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-erc">Reviewer</div><div class="step-content"><strong>Submits feedback from wallet 0x7bc…</strong><span class="badge-e">⚠ wallet + open positions visible</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">submitFeedback(reviewer:0x7bc) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-erc">ERC-8004</div><div class="step-content"><strong>Links reviewer ↔ open positions on-chain</strong><span class="badge-e">⚠ dominant actor identifies &amp; pressures</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">biased signal →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Registry</div><div class="step-content"><strong>Stores coerced, biased reputation</strong></div></div>
    </div>
    <div class="callout red">Reviewer identity traceable; dominant actor silences dissent</div>
  </div>
  <div class="col">
    <div class="col-label acta">🔒 ACTA path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Market</div><div class="step-content"><strong>Issues reviewer ZK credential</strong>Off-chain JWT-VC</div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">VC (private) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Reviewer</div><div class="step-content"><strong>Generates anonymous proof + nullifier</strong><code>N = H(secret, Poseidon(v, p, n))</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">proof π + N →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-chain">Accum.</div><div class="step-content"><strong>N not seen before? Accept, append leaf</strong>Adds N to nullifier set — no double-vote<span class="badge-p">🔒 no reviewer address on-chain</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">Merkle root anchored →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Registry</div><div class="step-content"><strong>Stores root as composable signal</strong>No reviewer identity, no positions</div></div>
    </div>
    <div class="callout green">Reviewer unlinkable · double-vote impossible · honest signal preserved</div>
  </div>
</div>
</div>

<!-- 3. KYC / AML -->
<div class="panel">
<div class="sub">Regulated protocol verifies operator compliance without broadcasting identity or wallet on-chain</div>
<div class="legend">
  <div class="leg"><div class="leg-dot" style="background:#60a5fa"></div><span style="color:#60a5fa">KYC provider</span></div>
  <div class="leg"><div class="leg-dot" style="background:#4ade80"></div><span style="color:#4ade80">Agent</span></div>
  <div class="leg"><div class="leg-dot" style="background:#fbbf24"></div><span style="color:#fbbf24">Chain</span></div>
  <div class="leg"><div class="leg-dot" style="background:#c084fc"></div><span style="color:#c084fc">Reg. protocol</span></div>
</div>
<div class="cols">
  <div class="col">
    <div class="col-label erc">⚠ ERC-8004 path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">KYC</div><div class="step-content"><strong>Certifies operator wallet 0x9f3…</strong>Result linked to wallet address</div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">wallet certified →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Registers with operator wallet</strong><code>agentId:0x4fa → operator:0x9f3</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">public mapping →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-erc">ERC-8004</div><div class="step-content"><strong>agentId → operatorWallet visible to all</strong><span class="badge-e">⚠ jurisdiction traceable from wallet history</span><span style="font-size:9px;color:#64748b;margin-top:2px;display:block">FATF: counterparty data leaked</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">check →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Grants access — operator fully doxed</strong></div></div>
    </div>
    <div class="callout red">Operator identity, jurisdiction, wallet permanently on-chain</div>
  </div>
  <div class="col">
    <div class="col-label acta">🔒 ACTA path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">KYC</div><div class="step-content"><strong>Issues W3C JWT-VC with compliance claims</strong><code>jurisdiction, kyc_tier, expiry</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">VC (off-chain) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Generates ZK proof of predicate</strong><code>jurisdiction ∉ sanctionsList</code><code>∧ kyc_tier ≥ 2 ∧ expiry &gt; now</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">proof π + nullifier →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-chain">Chain</div><div class="step-content"><strong>Verifies Groth16 π, checks nullifier</strong><code>verifyComplianceProof(π)</code><span class="badge-p">🔒 no identity stored</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">compliant=true →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Grants access</strong>Learns: compliant ✓ · Never learns: name, wallet, jurisdiction</div></div>
    </div>
    <div class="callout green">Operator identity never on-chain · satisfies FATF without disclosing originator data</div>
  </div>
</div>
</div>

<!-- 4. Open-Source Criteria -->
<div class="panel">
<div class="sub">Predicate hash is auditable on-chain; which agents satisfy it and their scores are not constructible</div>
<div class="legend">
  <div class="leg"><div class="leg-dot" style="background:#60a5fa"></div><span style="color:#60a5fa">Issuer</span></div>
  <div class="leg"><div class="leg-dot" style="background:#4ade80"></div><span style="color:#4ade80">Agent</span></div>
  <div class="leg"><div class="leg-dot" style="background:#fbbf24"></div><span style="color:#fbbf24">Chain</span></div>
  <div class="leg"><div class="leg-dot" style="background:#c084fc"></div><span style="color:#c084fc">Protocol</span></div>
</div>
<div class="cols">
  <div class="col">
    <div class="col-label erc">⚠ ERC-8004 path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Issuer</div><div class="step-content"><strong>Issues credential with raw scores</strong><code>score:92, caps:[exec,read]</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">credential →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Registers — all fields public</strong><span class="badge-e">⚠ score + caps fully visible</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">all fields on-chain →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-erc">ERC-8004</div><div class="step-content"><strong>Scores &amp; caps indexed for all agents</strong><span class="badge-e">⚠ competitor reverse-engineers threshold, clones passing agents</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">access →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Grants access — criteria gamed</strong></div></div>
    </div>
    <div class="callout red">Competitor sees: exact scores, caps, interaction frequency → selection logic fully reconstructible</div>
  </div>
  <div class="col">
    <div class="col-label acta">🔒 ACTA path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Issuer</div><div class="step-content"><strong>Issues private JWT-VC</strong>Protocol publishes predicateHash on-chain</div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">VC (off-chain) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Generates proof against public predicateHash</strong><code>predicateHash: 0x3e9f…</code>No score or caps revealed</div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">proof π →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-chain">Chain</div><div class="step-content"><strong>Verifies π vs predicateHash</strong>Records: valid or invalid only<span class="badge-p">🔒 passing agents unobservable</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">bool result →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Grants access</strong>Predicate auditable · passing set invisible</div></div>
    </div>
    <div class="callout green">Competitor sees: predicate hash + true/false. Scores, caps, agent identities: invisible.</div>
  </div>
</div>
</div>

<!-- 5. Cross-Protocol Identity -->
<div class="panel">
<div class="sub">Same agent, three protocols — context-scoped nullifiers prevent cross-protocol correlation</div>
<div class="legend">
  <div class="leg"><div class="leg-dot" style="background:#4ade80"></div><span style="color:#4ade80">Agent</span></div>
  <div class="leg"><div class="leg-dot" style="background:#fbbf24"></div><span style="color:#fbbf24">Protocol contracts</span></div>
  <div class="leg"><div class="leg-dot" style="background:#f87171"></div><span style="color:#f87171">ERC-8004 registries</span></div>
  <div class="leg"><div class="leg-dot" style="background:#c084fc"></div><span style="color:#c084fc">Indexer</span></div>
</div>
<div class="cols">
  <div class="col">
    <div class="col-label erc">⚠ ERC-8004 path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Registers with same agentId: 0x4fa across all protocols</strong></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">same ID → Uniswap, Aave, DAO →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-erc">Registries</div><div class="step-content"><strong>Three registries store agentId: 0x4fa</strong><code>Uniswap · Aave · DAO</code><span class="badge-e">⚠ same ID, three chains of history</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">← JOIN on agentId</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Indexer</div><div class="step-content"><strong>Builds full cross-protocol interaction graph</strong>Trading strategy inferred · governance influence mapped<span class="badge-e">⚠ correlation attack</span></div></div>
    </div>
    <div class="callout red">Permanent, linkable identity graph across all protocols</div>
  </div>
  <div class="col">
    <div class="col-label acta">🔒 ACTA path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Generates fresh proof per protocol with context-scoped nullifier</strong><code>N₁ = H(s, Poseidon(uni, p, n₁))</code><code>N₂ = H(s, Poseidon(aav, p, n₂))</code><code>N₃ = H(s, Poseidon(dao, p, n₃))</code></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">π₁+N₁, π₂+N₂, π₃+N₃ (separate) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-chain">Contracts</div><div class="step-content"><strong>Each contract verifies its own proof independently</strong>N₁, N₂, N₃ scoped to separate verifier contexts<span class="badge-p">🔒 unlinkable across protocols</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">← N₁, N₂, N₃ cryptographically independent</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Indexer</div><div class="step-content"><strong>Sees 3 valid proofs — cannot JOIN them</strong>No common identifier · no graph constructible<span class="badge-p">🔒 unlinkable</span></div></div>
    </div>
    <div class="callout green">No cross-protocol graph possible even with all on-chain data</div>
  </div>
</div>
</div>

<!-- 6. Reputation Bootstrap -->
<div class="panel">
<div class="sub">ZK accumulator builds anonymous reputation from interaction #1 — no cold-start exposure</div>
<div class="legend">
  <div class="leg"><div class="leg-dot" style="background:#60a5fa"></div><span style="color:#60a5fa">Issuer</span></div>
  <div class="leg"><div class="leg-dot" style="background:#4ade80"></div><span style="color:#4ade80">New agent</span></div>
  <div class="leg"><div class="leg-dot" style="background:#fbbf24"></div><span style="color:#fbbf24">Chain / accumulator</span></div>
  <div class="leg"><div class="leg-dot" style="background:#c084fc"></div><span style="color:#c084fc">Protocol</span></div>
</div>
<div class="cols">
  <div class="col">
    <div class="col-label erc">⚠ ERC-8004 path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Issuer</div><div class="step-content"><strong>Issues credential</strong></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">credential →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Interaction #1 — no reputation, no protection</strong>Full credential registered immediately</div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">full credential on-chain →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-erc">ERC-8004</div><div class="step-content"><strong>Interaction #1 indexed publicly</strong>Strategy, wallet, caps exposed at weakest moment<span class="badge-e">⚠ most vulnerable = most exposed</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">competitor clones before rep builds →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Agent competes with clones from day 1</strong>Full history permanently archived</div></div>
    </div>
    <div class="callout red">Cold-start catch-22: must interact to build rep; interacting exposes strategy before rep protects it</div>
  </div>
  <div class="col">
    <div class="col-label acta">🔒 ACTA path</div>
    <div class="flow">
      <div class="step"><div class="step-actor sa-issuer">Issuer</div><div class="step-content"><strong>Issues W3C JWT-VC (off-chain)</strong></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">VC (private) →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-holder">Agent</div><div class="step-content"><strong>Interactions #1–N: ZK proof per interaction</strong>No wallet ever on-chain</div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">anon leaf per interaction →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-chain">Accum.</div><div class="step-content"><strong>Merkle tree grows anonymously</strong>Root anchored to ERC-8004 registry<span class="badge-p">🔒 no raw history exposed</span></div></div>
      <div class="connector"><div class="conn-line"></div><div class="conn-label">aggregateScore &gt; threshold →</div><div class="conn-line"></div></div>
      <div class="step"><div class="step-actor sa-verifier">Protocol</div><div class="step-content"><strong>Grants access</strong>Learns: score ≥ 75 ✓ · Never learns: individual interactions</div></div>
    </div>
    <div class="callout green">Anonymous from interaction #1 · aggregate score provable without revealing history</div>
  </div>
</div>
</div>

<!-- 7. Personhood -->
<div class="panel">
<div class="sub">Three-layer ZK delegation: DAO verifies a real human backs an agent — without learning who (Adler, Hitzig, Jain et al. 2024)</div>
<div class="legend">
  <div class="leg"><div class="leg-dot" style="background:#60a5fa"></div><span style="color:#60a5fa">PHC issuer</span></div>
  <div class="leg"><div class="leg-dot" style="background:#a78bfa"></div><span style="color:#a78bfa">Human principal</span></div>
  <div class="leg"><div class="leg-dot" style="background:#4ade80"></div><span style="color:#4ade80">AI agent</span></div>
  <div class="leg"><div class="leg-dot" style="background:#fbbf24"></div><span style="color:#fbbf24">DAO contract</span></div>
</div>
<div class="flow-wide">
  <div style="font-size:10px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:#475569;padding:4px 0 6px">① Personhood credential issuance</div>
  <div class="step-wide"><div class="step-actor-w sa-issuer">PHC Issuer</div><div class="step-content-w"><strong>Verifies human via biometric / web-of-trust / gov ID · Issues Personhood Credential (PHC)</strong><code>type: PersonhoodCredential · humanVerified: true</code></div></div>
  <div class="connector"><div class="conn-line"></div><div class="conn-label">PHC (off-chain, private) →</div><div class="conn-line"></div></div>
  <div class="step-wide"><div class="step-actor-w sa-human">Human</div><div class="step-content-w"><strong>Receives PHC · decides to delegate to an AI agent</strong></div></div>
  <div style="font-size:10px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:#475569;padding:10px 0 6px">② Human → agent delegation via ZK commitment</div>
  <div class="step-wide"><div class="step-actor-w sa-human">Human</div><div class="step-content-w"><strong>Links PHC to agent DID via ZK commitment</strong><code>H(humanDID, agentDID, salt) = commitment (opaque on-chain)</code></div></div>
  <div class="connector"><div class="conn-line"></div><div class="conn-label">commitment anchored on-chain · witness delivered to agent (off-chain) →</div><div class="conn-line"></div></div>
  <div class="step-wide"><div class="step-actor-w sa-holder">AI Agent</div><div class="step-content-w"><strong>Receives delegation witness · holds PHC + witness privately</strong><span class="badge-p">🔒 commitment is opaque on-chain</span></div></div>
  <div style="font-size:10px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:#475569;padding:10px 0 6px">③ Agent proves personhood to DAO (ZK)</div>
  <div class="step-wide"><div class="step-actor-w sa-holder">AI Agent</div><div class="step-content-w"><strong>Generates Groth16 ZK proof</strong>Valid PHC from trusted issuer · human delegated to this agent · nullifier N (no double-vote)<span class="badge-p">🔒 human identity hidden</span></div></div>
  <div class="connector"><div class="conn-line"></div><div class="conn-label">proof π + nullifier N →</div><div class="conn-line"></div></div>
  <div class="step-wide"><div class="step-actor-w sa-chain">DAO Contract</div><div class="step-content-w">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div><strong style="color:#86efac;font-size:10px">CONTRACT LEARNS ✓</strong><div style="font-size:10px;color:#86efac;margin-top:3px">Real human backs this agent<br>PHC from trusted issuer<br>PHC not expired<br>No double-representation<br>Agent authorised by human</div></div>
      <div><strong style="color:#fca5a5;font-size:10px">CONTRACT NEVER LEARNS ✗</strong><div style="font-size:10px;color:#fca5a5;margin-top:3px">Human's name or identity<br>Human's wallet address<br>Which human → which agent<br>Human's other protocols<br>PHC verification method</div></div>
    </div>
  </div></div>
</div>
<div class="callout green" style="margin-top:8px">Bots without a PHC-linked human are excluded · governance rights restricted to real, accountable principals</div>
</div>

</div>
<script>
function show(n){
  document.querySelectorAll('.tab').forEach(function(t,i){t.classList.toggle('active',i===n)});
  document.querySelectorAll('.panel').forEach(function(p,i){p.classList.toggle('active',i===n)});
}
</script>
</body>
</html>`

export default function UseCasesPage() {
  return (
    <iframe
      srcDoc={HTML}
      className="w-full flex-1 border-0"
      title="ACTA Use Cases"
      sandbox="allow-scripts"
    />
  )
}
