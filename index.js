const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const HMAC_SECRET = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim();

const seenProofs = new Set();
const taskCache = new Map();

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

app.post(['/', '/agent'], (req, res) => {
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
      protocolVersion: 'v1',
      ...(body.nonce ? { nonce: body.nonce } : {}),
      ...(body.challenge ? { challenge: body.challenge } : {}),
      ...(body.task_id ? { task_id: body.task_id } : {})
    });
  }

  if (body.task_id && taskCache.has(body.task_id)) {
    return sendSignedJson(res, 200, taskCache.get(body.task_id));
  }

  const input = body.input;
  let decision = 'APPROVE';
  let reason_code = 'VALID_CONDITION';

  if (seenProofs.has(input.proof_tx)) {
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
    seenProofs.add(input.proof_tx);
  }

  const result = {
    protocolVersion: 'v1',
    decision,
    reason_code,
    proof_tx: input.proof_tx
  };

  if (body.task_id) {
    taskCache.set(body.task_id, result);
  }

  return sendSignedJson(res, 200, result);
});

app.listen(PORT, () => {
  console.log(`BRAW Agent listening on port ${PORT}`);
});
