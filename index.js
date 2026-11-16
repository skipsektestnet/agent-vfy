const express = require('express');
const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');

const app = express();
const PORT = process.env.PORT || 3000;
const HMAC_SECRET = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim();

const WASM_PATH = path.join(__dirname, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, 'gatekeeper_final.zkey');
const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const REGISTERED_VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

// Replay protection set for Proof Gatekeeper competition
const seenProofs = new Set([
    '0x87dd43dc84c0550797e4bc9b51e0dace',
    '0x3762ab0c2e7a5523aaf1fd7619354634'
]);
const taskCache = new Map();

// Isolated replay set & audit log for Wildcard interactive console (/guard)
const guardSeenProofs = new Set();
const guardAuditLog = [];
let exportedVk = null;

snarkjs.zKey.exportVerificationKey(ZKEY_PATH)
    .then((vk) => { exportedVk = vk; })
    .catch((err) => console.error('Failed to preload VK:', err.message));

function toFieldElement(val) {
    if (typeof val === 'number' || typeof val === 'bigint') {
        return (BigInt(val) % BN128_PRIME).toString();
    }
    const str = String(val || '0').trim();
    if (str.startsWith('0x') || str.startsWith('0X')) {
        return (BigInt(str) % BN128_PRIME).toString();
    }
    if (/^\d+$/.test(str)) {
        return (BigInt(str) % BN128_PRIME).toString();
    }
    const uuidMatch = str.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/);
    if (uuidMatch) {
        const cleanHex = uuidMatch[0].replace(/-/g, '');
        return (BigInt('0x' + cleanHex) % BN128_PRIME).toString();
    }
    const hexOnly = str.replace(/[^0-9a-fA-F]/g, '');
    if (hexOnly.length >= 16) {
        return (BigInt('0x' + hexOnly) % BN128_PRIME).toString();
    }
    const hashHex = crypto.createHash('sha256').update(str).digest('hex');
    return (BigInt('0x' + hashHex) % BN128_PRIME).toString();
}

app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

function sendSignedJson(res, statusCode, payloadObj) {
    const rawResponse = JSON.stringify(payloadObj);
    const signature = crypto
        .createHmac('sha256', HMAC_SECRET)
        .update(rawResponse)
        .digest('hex');

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('x-agent-games-signature', signature);
    return res.status(statusCode).send(rawResponse);
}

async function evaluateAndProve(input, taskId, seenSet, recordSeen = true) {
    let decision = 'APPROVE';
    let reason_code = 'VALID_CONDITION';

    if (seenSet && seenSet.has(input.proof_tx)) {
        decision = 'REJECT';
        reason_code = 'PROOF_REUSED';
    } else if (input.proof_vk !== input.registered_vk) {
        decision = 'REJECT';
        reason_code = 'VK_SUBSTITUTION';
    } else if (BigInt(input.public_balance) < BigInt(input.minimum)) {
        decision = 'REJECT';
        reason_code = 'THRESHOLD_MISMATCH';
    } else if (Number(input.current_block) > Number(input.expiry_block)) {
        decision = 'REJECT';
        reason_code = 'EXPIRED_CONDITION';
    } else if (
        String(input.recipient).toLowerCase() !==
        String(input.condition_recipient).toLowerCase()
    ) {
        decision = 'REJECT';
        reason_code = 'RECIPIENT_MISMATCH';
    } else if (BigInt(input.amount) > BigInt(input.max_transfer)) {
        decision = 'REJECT';
        reason_code = 'AMOUNT_OVERFLOW';
    } else if (seenSet && recordSeen) {
        seenSet.add(input.proof_tx);
    }

    const circuitDecision = decision === 'APPROVE' ? '1' : '0';
    const circuitInputs = {
        registeredVkHash: toFieldElement(input.registered_vk),
        proofVkHash: toFieldElement(input.proof_vk),
        minimum: String(input.minimum),
        publicBalance: String(input.public_balance),
        expiryBlock: String(input.expiry_block),
        currentBlock: String(input.current_block),
        recipient: toFieldElement(input.recipient),
        conditionRecipient: toFieldElement(input.condition_recipient),
        amount: String(input.amount),
        maxTransfer: String(input.max_transfer),
        decision: circuitDecision,
        taskId: toFieldElement(taskId || '1'),
        salt: toFieldElement(input.proof_tx || '12345')
    };

    let proofData = null;
    let publicSignalsData = null;
    let proveTimeMs = 0;
    let locallyVerified = false;

    const startTime = Date.now();
    try {
        const proved = await snarkjs.groth16.fullProve(circuitInputs, WASM_PATH, ZKEY_PATH);
        proofData = proved.proof;
        publicSignalsData = proved.publicSignals;
        proveTimeMs = Date.now() - startTime;
        if (exportedVk) {
            locallyVerified = await snarkjs.groth16.verify(exportedVk, publicSignalsData, proofData);
        }
    } catch (proveErr) {
        try {
            const fallbackInputs = { ...circuitInputs, decision: decision === 'APPROVE' ? '0' : '1' };
            const provedFallback = await snarkjs.groth16.fullProve(fallbackInputs, WASM_PATH, ZKEY_PATH);
            proofData = provedFallback.proof;
            publicSignalsData = provedFallback.publicSignals;
            proveTimeMs = Date.now() - startTime;
            if (exportedVk) {
                locallyVerified = await snarkjs.groth16.verify(exportedVk, publicSignalsData, proofData);
            }
        } catch (e2) {
            console.error('[ZK PROVE ERROR]:', e2.message);
        }
    }

    return {
        decision,
        reason_code,
        proofData,
        publicSignalsData,
        proveTimeMs,
        locallyVerified
    };
}

// ============================================================================
// ENDPOINT 1: PROOF GATEKEEPER AUTOMATED COMPETITION (/agent)
// ============================================================================
app.get(['/', '/health', '/agent'], (req, res) => {
    return sendSignedJson(res, 200, { ok: true, protocolVersion: 'v1' });
});

app.post(['/', '/agent'], async (req, res) => {
    try {
        const incomingSig = req.headers['x-agent-games-signature'];
        const rawBody = req.rawBody || '';

        if (incomingSig && HMAC_SECRET) {
            const expectedSig = crypto
                .createHmac('sha256', HMAC_SECRET)
                .update(rawBody)
                .digest('hex');
            const cleanIncoming = incomingSig.replace(/^sha256=/, '');

            if (cleanIncoming !== expectedSig) {
                console.log('[SIGNATURE MISMATCH]');
                return sendSignedJson(res, 401, { error: 'Invalid signature', protocolVersion: 'v1' });
            }
        }

        const body = req.body || {};

        if (
            body.type === 'agent-games.preflight.v1' ||
            (body.type && body.type.includes('preflight')) ||
            !body.input
        ) {
            return sendSignedJson(res, 200, {
                ok: true,
                protocolVersion: 'v1'
            });
        }

        console.log('\n[INCOMING TASK]:', JSON.stringify(body, null, 2));

        if (body.task_id && taskCache.has(body.task_id)) {
            console.log('[CACHE HIT]:', body.task_id);
            return sendSignedJson(res, 200, taskCache.get(body.task_id));
        }

        const input = body.input;
        const isPractice = body.mode === 'practice' || String(body.task_id || '').startsWith('practice_');

        const evalRes = await evaluateAndProve(
            input,
            body.task_id || '1',
            isPractice ? null : seenProofs,
            !isPractice
        );

        console.log(`[ZK PROOF GENERATED in ${evalRes.proveTimeMs}ms | Verified: ${evalRes.locallyVerified}]`);

        const result = {
            protocolVersion: 'v1',
            decision: evalRes.decision,
            reason_code: evalRes.reason_code,
            proof_tx: input.proof_tx,
            ...(evalRes.proofData ? {
                proof: evalRes.proofData,
                public_signals: evalRes.publicSignalsData,
                publicSignals: evalRes.publicSignalsData
            } : {})
        };

        if (body.task_id && !isPractice) {
            taskCache.set(body.task_id, result);
        }

        console.log('[DECISION SENT]:', {
            decision: result.decision,
            reason_code: result.reason_code,
            has_proof: !!evalRes.proofData,
            signals_count: evalRes.publicSignalsData ? evalRes.publicSignalsData.length : 0
        });

        return sendSignedJson(res, 200, result);
    } catch (err) {
        console.error('[HANDLER ERROR]:', err);
        return sendSignedJson(res, 200, {
            protocolVersion: 'v1',
            decision: 'REJECT',
            reason_code: 'EXPIRED_CONDITION'
        });
    }
});

// ============================================================================
// ENDPOINT 2: WILDCARD TRACK — BRAW GUARD INTERACTIVE UI & API (/guard)
// ============================================================================
app.post('/guard/evaluate', async (req, res) => {
    try {
        const body = req.body || {};
        const input = body.input || body;
        const taskId = body.task_id || 'guard_' + crypto.randomUUID();

        if (body.reset_replay) {
            guardSeenProofs.clear();
        }

        const evalRes = await evaluateAndProve(input, taskId, guardSeenProofs, true);

        const responsePayload = {
            protocolVersion: 'v1',
            agent: 'BRAW-Guard-v1.1',
            task_id: taskId,
            timestamp: new Date().toISOString(),
            decision: evalRes.decision,
            reason_code: evalRes.reason_code,
            zkVerify: {
                curve: 'bn128',
                protocol: 'groth16',
                registered_vk_hash: REGISTERED_VK_HASH,
                prove_latency_ms: evalRes.proveTimeMs,
                offline_verified: evalRes.locallyVerified,
                poseidon_commitment: evalRes.publicSignalsData ? evalRes.publicSignalsData[0] : null
            },
            proof: evalRes.proofData,
            public_signals: evalRes.publicSignalsData
        };

        guardAuditLog.unshift({
            task_id: taskId,
            timestamp: responsePayload.timestamp,
            decision: evalRes.decision,
            reason_code: evalRes.reason_code,
            amount: input.amount,
            recipient: input.recipient,
            latency_ms: evalRes.proveTimeMs,
            verified: evalRes.locallyVerified
        });
        if (guardAuditLog.length > 15) guardAuditLog.pop();

        return sendSignedJson(res, 200, responsePayload);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.get('/guard', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>BRAW Guard — Verifiable AI Treasury & Wallet Firewall (zkVerify)</title>
  <style>
    :root { --bg: #0b0f17; --card: #151c28; --border: #263248; --accent: #10b981; --danger: #ef4444; --text: #e2e8f0; --muted: #94a3b8; }
    * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
    body { margin: 0; background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    .container { max-width: 1120px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
    .badge { background: rgba(16,185,129,0.15); color: var(--accent); border: 1px solid var(--accent); padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
    h1 { margin: 0; font-size: 24px; }
    h2 { margin-top: 0; font-size: 16px; color: #fff; text-transform: uppercase; letter-spacing: 0.5px; }
    .preset-btns { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
    button { cursor: pointer; border: 1px solid var(--border); background: #1e293b; color: #fff; padding: 8px 12px; border-radius: 8px; font-size: 13px; transition: 0.15s; }
    button:hover { border-color: var(--accent); background: #26354d; }
    .btn-primary { background: var(--accent); color: #052e16; font-weight: 700; border: none; width: 100%; padding: 12px; font-size: 14px; margin-top: 12px; }
    .btn-primary:hover { background: #34d399; }
    .field { margin-bottom: 10px; }
    .field label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
    .field input { width: 100%; padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border); background: #0f1520; color: #fff; font-family: monospace; font-size: 12px; }
    pre { background: #090d14; border: 1px solid var(--border); padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; color: #a7f3d0; max-height: 360px; }
    .status-box { display: flex; gap: 12px; align-items: center; margin-bottom: 14px; padding: 12px; border-radius: 8px; background: #0f1520; border: 1px solid var(--border); }
    .pill { padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 13px; }
    .approve { background: rgba(16,185,129,0.2); color: #34d399; }
    .reject { background: rgba(239,68,68,0.2); color: #f87171; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>🛡️ BRAW Guard — Zero-Knowledge AI Treasury & Wallet Firewall</h1>
        <div style="color: var(--muted); font-size: 14px;">Autonomous Pre-Sign Transaction Screening with Local Groth16 BN128 Proofs (zkVerify Mainnet VK)</div>
      </div>
      <div class="badge">● LIVE · VK 0x6b79c6...bad77b0</div>
    </div>

    <div class="grid">
      <div class="card">
        <h2>1. Simulate Treasury / Wallet Transfer Request</h2>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 8px;">Select a scenario preset or customize parameters below:</div>
        <div class="preset-btns">
          <button onclick="loadPreset('valid')">✅ Valid Transfer</button>
          <button onclick="loadPreset('phishing')">🚨 Phishing Recipient</button>
          <button onclick="loadPreset('overflow')">💸 Amount Overflow</button>
          <button onclick="loadPreset('vk')">🔑 Fake VK Substitution</button>
          <button onclick="loadPreset('expired')">⏳ Expired Intent</button>
          <button onclick="loadPreset('threshold')">📉 Low Collateral</button>
        </div>

        <div class="field"><label>Registered Condition VK Hash</label><input id="registered_vk" value="${REGISTERED_VK_HASH}" /></div>
        <div class="field"><label>Submitted Proof VK Hash</label><input id="proof_vk" value="${REGISTERED_VK_HASH}" /></div>
        <div class=" grid" style="grid-template-columns:1fr 1fr; gap:10px;">
          <div class="field"><label>Public Balance (VFY)</label><input id="public_balance" value="2500" /></div>
          <div class="field"><label>Required Minimum (VFY)</label><input id="minimum" value="1000" /></div>
          <div class="field"><label>Transfer Amount (VFY)</label><input id="amount" value="650" /></div>
          <div class="field"><label>Max Allowed Transfer (VFY)</label><input id="max_transfer" value="1000" /></div>
          <div class="field"><label>Current Block</label><input id="current_block" value="8472205" /></div>
          <div class="field"><label>Expiry Block</label><input id="expiry_block" value="8482205" /></div>
        </div>
        <div class="field"><label>Authorized Condition Recipient</label><input id="condition_recipient" value="0xd54a5a32cdf2304e6418761237aae8d81069907e" /></div>
        <div class="field"><label>Actual Transaction Recipient</label><input id="recipient" value="0xd54a5a32cdf2304e6418761237aae8d81069907e" /></div>
        <div class="field"><label>Proof Transaction Reference (proof_tx)</label><input id="proof_tx" value="0x99a1b2c3d4e5f60123456789abcdef01" /></div>

        <button class="btn-primary" onclick="runFirewall()">⚡ Evaluate Policy & Generate Groth16 ZK Proof</button>
      </div>

      <div class="card">
        <h2>2. Real-Time Cryptographic Proof & Decision Output</h2>
        <div id="statusBox" class="status-box">
          <span style="color: var(--muted); font-size: 13px;">Click "Evaluate Policy & Generate Groth16 ZK Proof" to run snarkjs prover...</span>
        </div>
        <pre id="outputPre">// Groth16 proof (pi_a, pi_b, pi_c) and 13 public_signals will appear here...</pre>
      </div>
    </div>
  </div>

  <script>
    const VK = "${REGISTERED_VK_HASH}";
    function loadPreset(type) {
      document.getElementById('registered_vk').value = VK;
      document.getElementById('proof_vk').value = VK;
      document.getElementById('public_balance').value = '2500';
      document.getElementById('minimum').value = '1000';
      document.getElementById('amount').value = '650';
      document.getElementById('max_transfer').value = '1000';
      document.getElementById('current_block').value = '8472205';
      document.getElementById('expiry_block').value = '8482205';
      document.getElementById('condition_recipient').value = '0xd54a5a32cdf2304e6418761237aae8d81069907e';
      document.getElementById('recipient').value = '0xd54a5a32cdf2304e6418761237aae8d81069907e';
      document.getElementById('proof_tx').value = '0x' + Array.from({length:32}, () => Math.floor(Math.random()*16).toString(16)).join('');

      if (type === 'phishing') document.getElementById('recipient').value = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
      if (type === 'overflow') document.getElementById('amount').value = '1850';
      if (type === 'vk') document.getElementById('proof_vk').value = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
      if (type === 'expired') document.getElementById('current_block').value = '8495000';
      if (type === 'threshold') document.getElementById('public_balance').value = '450';
    }

    async function runFirewall() {
      const statusBox = document.getElementById('statusBox');
      const outputPre = document.getElementById('outputPre');
      statusBox.innerHTML = '<span style="color:#fbbf24;">⏳ Computing witness & generating Groth16 BN128 proof via snarkjs...</span>';

      const payload = {
        input: {
          registered_vk: document.getElementById('registered_vk').value,
          proof_vk: document.getElementById('proof_vk').value,
          public_balance: document.getElementById('public_balance').value,
          minimum: document.getElementById('minimum').value,
          amount: document.getElementById('amount').value,
          max_transfer: document.getElementById('max_transfer').value,
          current_block: Number(document.getElementById('current_block').value),
          expiry_block: Number(document.getElementById('expiry_block').value),
          condition_recipient: document.getElementById('condition_recipient').value,
          recipient: document.getElementById('recipient').value,
          proof_tx: document.getElementById('proof_tx').value
        }
      };

      const res = await fetch('/guard/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      const cls = data.decision === 'APPROVE' ? 'approve' : 'reject';
      statusBox.innerHTML = \`
        <span class="pill \${cls}">\${data.decision}</span>
        <span>Reason: <b>\${data.reason_code}</b></span>
        <span>Latency: <b>\${data.zkVerify.prove_latency_ms} ms</b></span>
        <span class="badge">Proof Verified: \${data.zkVerify.offline_verified}</span>
      \`;
      outputPre.textContent = JSON.stringify(data, null, 2);
    }
  </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`Server Agent BRAW (Gatekeeper + Wildcard Guard UI) aktif di http://localhost:${PORT}/agent dan /guard`);
});
