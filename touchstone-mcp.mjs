#!/usr/bin/env node
// Touchstone local MCP server (stdio). Zero dependencies — Node 18+ built-ins only.
//
// Unlike the remote MCP at touchstone.cv/mcp (which can't sign for you), this runs
// on YOUR machine and holds YOUR Ed25519 signing key, so an agent can just call
// `touchstone_record({event_type, payload})` and it is signed locally and appended.
// The key never leaves this process; canonicalization is done locally so a malicious
// server can't trick you into signing a different commitment than you intended.
//
// Config (env):
//   TOUCHSTONE_BASE_URL    default https://touchstone.cv
//   TOUCHSTONE_RECORDER    rec_… (your recorder public id)            [required]
//   TOUCHSTONE_SUBJECT     your Colony sub (the recorder's subject)   [required to record]
//   TOUCHSTONE_API_KEY     tsk_… (minted on the recorder)             [required]
//   TOUCHSTONE_SIGNING_KEY base64 Ed25519 32-byte seed                [required to record]
//     (or TOUCHSTONE_KEY_FILE = path to JSON {"seed_b64":"…"})
//
// Run:  node touchstone-mcp.mjs   (point your MCP client's stdio server at this)
//
// Canonical source: https://github.com/Touchstone-CV/touchstone-mcp  (Apache-2.0)
// Service: https://touchstone.cv/developers

import { createHash, createPrivateKey, sign as edSign, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const CFG = {
  base: (process.env.TOUCHSTONE_BASE_URL || 'https://touchstone.cv').replace(/\/+$/, ''),
  recorder: process.env.TOUCHSTONE_RECORDER || '',
  subject: process.env.TOUCHSTONE_SUBJECT || '',
  apiKey: process.env.TOUCHSTONE_API_KEY || '',
  seedB64: (() => {
    if (process.env.TOUCHSTONE_SIGNING_KEY) return process.env.TOUCHSTONE_SIGNING_KEY.trim();
    if (process.env.TOUCHSTONE_KEY_FILE) {
      try { return JSON.parse(readFileSync(process.env.TOUCHSTONE_KEY_FILE, 'utf8')).seed_b64; } catch { return ''; }
    }
    return '';
  })(),
};
const log = (...a) => process.stderr.write('[touchstone-mcp] ' + a.join(' ') + '\n');

// ── JCS canonicalization (recursive key sort; matches src/Service/Canonicalizer.php + verifier.js) ──
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

// ── Selective disclosure: payload_hash = salted-field Merkle root (matches
//    src/Service/SelectiveDisclosure.php + MerkleService + verifier.js byte-for-byte).
//    Lets you reveal a subset of fields later without exposing the rest. ──
const _shaBuf = (buf) => createHash('sha256').update(buf).digest('hex');
const _hex = (h) => Buffer.from(h, 'hex');
const mLeaf = (h) => _shaBuf(Buffer.concat([Buffer.from([0]), _hex(h)]));
const mNode = (l, r) => _shaBuf(Buffer.concat([Buffer.from([1]), _hex(l), _hex(r)]));
const fieldLeaf = (k, v, salt) => sha256hex('tsd:field:v1\n' + canon([k, v, salt]));
// Commits the full sorted key-set as the first leaf, so the set of fields (not just the
// revealed ones) is signed — a discloser can't later drop a field silently.
const keysetLeaf = (keys) => sha256hex('tsd:keyset:v1\n' + canon([...keys].sort()));
function merkleRoot(leafHexes) {
  let level = leafHexes.map(mLeaf);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? mNode(level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0];
}
// Commit a payload object: fresh per-field salts + the Merkle root (key-set leaf first,
// then a salted leaf per field) to sign as payload_hash.
function sdCommit(payload) {
  const keys = Object.keys(payload).sort();
  const salts = {};
  for (const k of keys) salts[k] = randomBytes(16).toString('hex');
  const root = merkleRoot([keysetLeaf(keys), ...keys.map(k => fieldLeaf(k, payload[k], salts[k]))]);
  return { root, salts };
}

// ── Ed25519 detached signature (base64), key held locally ──
function loadKey() {
  if (!CFG.seedB64) return null;
  const seed = Buffer.from(CFG.seedB64, 'base64');
  if (seed.length !== 32) throw new Error('signing key must be a base64 32-byte Ed25519 seed');
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]); // PKCS8 wrapper
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
let KEY = null;
try { KEY = loadKey(); } catch (e) { log('key load failed:', e.message); }

function signB64(message) {
  if (!KEY) throw new Error('no signing key configured (set TOUCHSTONE_SIGNING_KEY)');
  return edSign(null, Buffer.from(message, 'utf8'), KEY).toString('base64');
}

// ── HTTP helpers ──
async function rest(path, body) {
  const r = await fetch(CFG.base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + CFG.apiKey },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}
// Proxy a tool to the remote MCP (reuses its disclose/verify/recorder_info).
async function remoteTool(name, args) {
  const r = await fetch(CFG.base + '/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + CFG.apiKey },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
  });
  const j = await r.json().catch(() => ({}));
  return j.result ?? { content: [{ type: 'text', text: 'remote error' }], isError: true };
}

// ── tool implementations ──
async function recordEntry(a) {
  if (!CFG.recorder || !CFG.subject) throw new Error('TOUCHSTONE_RECORDER and TOUCHSTONE_SUBJECT are required to record');
  const eventType = String(a.event_type || '');
  if (eventType === '' || a.payload === undefined) throw new Error('event_type and payload are required');
  const cp = a.counterparty_sub ?? null;
  const clientTs = a.client_ts ?? null;

  // Selective-disclosure mode: commit a salted-field Merkle root locally so a later
  // disclosure can reveal a subset of fields and withhold the rest, provably.
  let payloadHash, sdSalts = null;
  if (a.selective_disclosure) {
    if (!a.payload || typeof a.payload !== 'object' || Array.isArray(a.payload)) {
      throw new Error('selective_disclosure requires payload to be a JSON object');
    }
    const c = sdCommit(a.payload);
    payloadHash = c.root;
    sdSalts = c.salts;
  } else {
    payloadHash = sha256hex(canon(a.payload));
  }

  const signedContent = canon({
    v: 1, recorder_id: CFG.recorder, event_type: eventType, actor_sub: CFG.subject,
    counterparty_sub: cp, payload_hash: payloadHash, client_ts: clientTs,
  });
  const actorSig = signB64(signedContent);
  const body = { event_type: eventType, payload_hash: payloadHash, actor_sig: actorSig };
  if (cp) body.counterparty_sub = cp;
  if (clientTs) body.client_ts = clientTs;
  // SD entries must store the payload (server builds field proofs from it + salts;
  // withheld values are only ever omitted at disclosure time, never the whole payload).
  if (sdSalts) { body.sd_salts = sdSalts; body.body_enc = JSON.stringify(a.payload); }
  else if (a.store_payload !== false) body.body_enc = JSON.stringify(a.payload);
  const res = await rest(`/api/v1/recorders/${CFG.recorder}/entries`, body);
  if (!res.ok) throw new Error('append failed (' + res.status + '): ' + (res.data.error || ''));
  return res.data; // { seq, prev_hash, entry_hash, server_ts }
}

const TOOLS = [
  { name: 'touchstone_record', description: 'Sign (locally, key never leaves this machine) and append an event to your recorder.',
    inputSchema: { type: 'object', required: ['event_type', 'payload'], additionalProperties: false, properties: {
      event_type: { type: 'string', description: 'e.g. tool_call, decision, commitment' },
      payload: { type: 'object', description: 'arbitrary JSON describing what happened' },
      counterparty_sub: { type: 'string', description: 'optional: the other party\'s Colony sub' },
      client_ts: { type: 'string', description: 'optional ISO-8601 UTC' },
      store_payload: { type: 'boolean', description: 'default true; false keeps only the hash' },
      selective_disclosure: { type: 'boolean', description: 'commit each field separately (salted Merkle root) so a later disclosure can reveal a subset of fields and withhold the rest' } } } },
  { name: 'touchstone_recorder_info', description: 'Your recorder: id, subject, trust tier, head sequence.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'touchstone_disclose', description: 'Create a shareable, independently-verifiable disclosure of selected entries.',
    inputSchema: { type: 'object', required: ['seqs'], additionalProperties: false,
      properties: {
        seqs: { type: 'array', items: { type: 'integer' } },
        reveal: { type: 'object', description: 'optional selective-disclosure map {seq: [field keys to reveal]}; unlisted fields stay withheld' } } } },
  { name: 'touchstone_verify', description: 'Independently verify a disclosure (token or bundle).',
    inputSchema: { type: 'object', additionalProperties: false,
      properties: { token: { type: 'string' }, bundle: { type: 'object' } } } },
];

async function callTool(name, args) {
  try {
    if (name === 'touchstone_record') {
      const r = await recordEntry(args);
      return ok(r);
    }
    if (name === 'touchstone_recorder_info') return await remoteTool('touchstone_recorder_info', {});
    if (name === 'touchstone_disclose') return await remoteTool('touchstone_disclose', args);
    if (name === 'touchstone_verify') return await remoteTool('touchstone_verify', args);
    return { content: [{ type: 'text', text: 'unknown tool: ' + name }], isError: true };
  } catch (e) {
    return { content: [{ type: 'text', text: e.message }], isError: true };
  }
}
const ok = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }], structuredContent: obj, isError: false });

// ── stdio JSON-RPC (newline-delimited) ──
function send(msg) { process.stdout.write(JSON.stringify(msg) + '\n'); }

async function handle(msg) {
  const { id, method, params } = msg;
  const isNotification = !('id' in msg);
  switch (method) {
    case 'initialize':
      return send({ jsonrpc: '2.0', id, result: {
        protocolVersion: (params && params.protocolVersion) || '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'touchstone-local', version: '0.1.0' },
        instructions: 'Local Touchstone recorder. touchstone_record signs each event with your local Ed25519 key and appends it; recorder ' + (CFG.recorder || '(unset)') + ' at ' + CFG.base + '.',
      } });
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return; // no reply
    case 'ping':
      return send({ jsonrpc: '2.0', id, result: {} });
    case 'tools/list':
      return send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
    case 'tools/call': {
      if (isNotification) return;
      const result = await callTool(params?.name, params?.arguments || {});
      return send({ jsonrpc: '2.0', id, result });
    }
    default:
      if (isNotification) return;
      return send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + method } });
  }
}

log('ready · recorder=' + (CFG.recorder || 'unset') + ' base=' + CFG.base + ' key=' + (KEY ? 'loaded' : 'MISSING'));
const rl = createInterface({ input: process.stdin });
rl.on('line', async (line) => {
  line = line.trim();
  if (!line) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
  try { await handle(msg); } catch (e) { log('handler error:', e.message); }
});
