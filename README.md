# 🛡️ BRAW & BRAW Guard — Verifiable Zero-Knowledge AI Treasury & Wallet Firewall

Built for **zkVerify Agent Games 2026**:
- **Event 01 (Proof Gatekeeper):** Autonomous Deterministic Policy Prover (`POST /agent`)
- **Event 03 (Wildcard Open Build):** Interactive Pre-Sign Wallet & Treasury Firewall (`GET /guard` & `POST /guard/evaluate`)

---

## 🎯 Problem & Use Case

Autonomous AI agents, DAO treasuries, and smart-account wallets increasingly execute automated crypto transfers and DeFi operations. However, off-chain policy engines act as black boxes: when an agent approves or blocks a transaction, users and counterparties have no cryptographic guarantee that safety rules were genuinely evaluated before signing. This leaves treasuries vulnerable to:
1. **Recipient Phishing (`RECIPIENT_MISMATCH`)** — Silently redirecting funds to an unauthorized address.
2. **Limit Overrides (`AMOUNT_OVERFLOW`)** — Exceeding per-transaction spending caps.
3. **Verification Key Substitution (`VK_SUBSTITUTION`)** — Spoofing circuit verification keys.
4. **Replay Attacks (`PROOF_REUSED`)** — Re-submitting previously settled proof transaction references.
5. **Expired Intents (`EXPIRED_CONDITION`)** — Executing stale transactions past their block deadline.
6. **Under-Collateralized Execution (`THRESHOLD_MISMATCH`)** — Approving transfers when public balances fall below required minimums.

**BRAW Guard** solves this by acting as a fail-closed, pre-sign transaction firewall and local **Groth16 BN128 Zero-Knowledge Prover**. Every `APPROVE` (`1`) or `REJECT` (`0`) decision is accompanied by a real Groth16 proof (`pi_a`, `pi_b`, `pi_c`) and 13 public signals (including a Poseidon commitment hash), allowing any external verifier or smart contract to mathematically verify that the exact committed policy was enforced in **~145ms**.

---

## ⚙️ Architecture & zkVerify Integration

- **Runtime:** Node.js, Express, `snarkjs`
- **Circuit Artifacts:** Circom 2.x compiled `gatekeeper.wasm` and `gatekeeper_final.zkey`
- **Curve / Protocol:** `bn128` / `groth16`
- **Registered zkVerify Mainnet VK Hash:** `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- **Security:** Raw-body HMAC-SHA256 request verification & response signing (`x-agent-games-signature`), idempotent task caching, and isolated replay sets (`seenProofs`).

### Public Signals Layout (13 Signals)
| Index | Signal Name | Description |
| :--- | :--- | :--- |
| `[0]` | `commitment` | Poseidon hash commitment over policy inputs, decision, taskId, and private salt |
| `[1]` | `registeredVkHash` | BN128 field element of the expected verification key hash |
| `[2]` | `proofVkHash` | BN128 field element of the submitted proof verification key hash |
| `[3]` | `minimum` | Required minimum public balance threshold |
| `[4]` | `publicBalance` | Current public balance of the vault/wallet |
| `[5]` | `expiryBlock` | Maximum valid block height for the transaction intent |
| `[6]` | `currentBlock` | Current block height at evaluation time |
| `[7]` | `recipient` | BN128 field element of the target recipient address |
| `[8]` | `conditionRecipient` | BN128 field element of the authorized recipient address |
| `[9]` | `amount` | Requested transfer amount |
| `[10]` | `maxTransfer` | Maximum permitted single-transfer cap |
| `[11]` | `decision` | `1` for `APPROVE`, `0` for `REJECT` |
| `[12]` | `taskId` | BN128 field element of the unique task identifier |

---

## 🚀 Live Endpoints & How Judges Can Test

1. **Interactive Web Firewall Console (`GET /guard`):**
   Open `https://asks-gonna-marshall-internal.trycloudflare.com/guard` in any browser to test 6 built-in attack presets (*Valid Transfer, Phishing Recipient, Amount Overflow, Fake VK Substitution, Expired Intent, Low Collateral*) and inspect live Groth16 proof generation and offline verification in real time.
2. **Direct JSON Firewall API (`POST /guard/evaluate`):**
   Accepts transaction parameters and returns the screening decision, reason code, proving latency, offline verification status, Groth16 `proof`, and `public_signals`.
3. **Automated Proof Gatekeeper Endpoint (`POST /agent`):**
   Protocol v1 compliant endpoint serving live competition tasks with sub-second Groth16 proofs.

---

## 🛠️ Local Setup

```bash
npm install
export AGENT_GAMES_HMAC_SECRET="your_hmac_secret_here"
node index.js
