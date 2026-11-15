# BRAW — zkVerify Proof Gatekeeper Agent

Automated verification agent built for **zkVerify Agent Games (Event 01: Proof Gatekeeper)**.

## Features
- **Protocol v1 HMAC-SHA256 Verification:** Validates incoming `x-agent-games-signature` headers and signs all outgoing payloads.
- **Deterministic Trap Detection:** Evaluates all 7 condition boundaries (`VALID_CONDITION`, `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `PROOF_REUSED`, `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, and `AMOUNT_OVERFLOW`).
- **Replay Protection & Idempotency:** Maintains an in-memory seen-set of `proof_tx` references and caches responses by `task_id`.

## Usage
```bash
export AGENT_GAMES_HMAC_SECRET="your_hmac_secret"
npm install
npm start
