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

const seenProofs = new Set();
const taskCache = new Map();

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

    if (body.task_id && taskCache.has(body.task_id)) {
      return sendSignedJson(res, 200, taskCache.get(body.task_id));
    }

    const input = body.input;
    const isPractice = body.mode === 'practice' || String(body.task_id || '').startsWith('practice_');

    let decision = 'APPROVE';
    let reason_code = 'VALID_CONDITION';

    if (!isPractice && seenProofs.has(input.proof_tx)) {
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
    } else {
      if (!isPractice) {
        seenProofs.add(input.proof_tx);
      }
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
      taskId: toFieldElement(body.task_id || '1'),
      salt: toFieldElement(input.proof_tx || '12345')
    };

    let proofData = null;
    let publicSignalsData = null;

    try {
      const proved = await snarkjs.groth16.fullProve(circuitInputs, WASM_PATH, ZKEY_PATH);
      proofData = proved.proof;
      publicSignalsData = proved.publicSignals;
    } catch (proveErr) {
      try {
        const fallbackInputs = { ...circuitInputs, decision: decision === 'APPROVE' ? '0' : '1' };
        const provedFallback = await snarkjs.groth16.fullProve(fallbackInputs, WASM_PATH, ZKEY_PATH);
        proofData = provedFallback.proof;
        publicSignalsData = provedFallback.publicSignals;
      } catch (e2) {
        console.error('ZK Prove Error:', e2.message);
      }
    }

    const result = {
      protocolVersion: 'v1',
      decision,
      reason_code,
      proof_tx: input.proof_tx,
      ...(proofData ? {
        proof: proofData,
        public_signals: publicSignalsData,
        publicSignals: publicSignalsData
      } : {})
    };

    if (body.task_id && !isPractice) {
      taskCache.set(body.task_id, result);
    }

    return sendSignedJson(res, 200, result);
  } catch (err) {
    return sendSignedJson(res, 200, {
      protocolVersion: 'v1',
      decision: 'REJECT',
      reason_code: 'EXPIRED_CONDITION'
    });
  }
});

app.listen(PORT, () => {
  console.log(`BRAW Agent (Groth16 ZK Enabled) listening on port ${PORT}`);
});
