# BRAW — zkVerify Proof Gatekeeper Agent

Automated verification agent built for **zkVerify Agent Games (Event 01: Proof Gatekeeper)** with local **Groth16/BN128 Zero-Knowledge Proof** generation via `snarkjs`.

## Features
- **Local Groth16 Proof Generation:** Generates cryptographic proofs (`pi_a`, `pi_b`, `pi_c`) and 13 `public_signals` locally against `gatekeeper.wasm` and `gatekeeper_final.zkey` (registered zkVerify mainnet VK hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
- **Protocol v1 HMAC-SHA256 Authentication:** Verifies incoming `x-agent-games-signature` over raw request bodies and signs all outgoing responses.
- **Deterministic Condition Boundary Enforcement:** Evaluates all 7 condition boundaries (`VALID_CONDITION`, `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `PROOF_REUSED`, `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, and `AMOUNT_OVERFLOW`) with fail-closed safety.
- **Replay Protection & Idempotency:** Tracks seen `proof_tx` references in-memory and caches task responses by `task_id`.

## Setup & Usage
1. Place `gatekeeper.wasm` and `gatekeeper_final.zkey` in the project root.
2. Run the service:
```bash
export AGENT_GAMES_HMAC_SECRET="your_hmac_secret"
npm install
npm start
