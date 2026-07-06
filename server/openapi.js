'use strict';
/**
 * OpenAPI 3.1 document for the /api/v1 sensor & scan surface.
 *
 * Request-body schemas are GENERATED from the exported Zod validators in
 * server/validation.js (single source of truth — no hand-maintained duplicate
 * of any request field). Zod 4's native z.toJSONSchema targets draft 2020-12,
 * which OpenAPI 3.1 embeds directly, so this needs no extra dependency.
 *
 * Response schemas are hand-authored with additionalProperties:true so the
 * spec never over-constrains the CLAUDE.md-protected API on benign additive
 * changes. The document is built once and cached; it is served from a cold
 * GET route (no impact on the gate hot path).
 */
const { z } = require('zod');
const validation = require('./validation');
const pkg = require('../package.json');

function requestSchema(schema) {
  // z.preprocess-wrapped fields can degrade under io:'input'; fall back to
  // io:'output' (typed but looser) rather than emitting a useless {}.
  const opts = { target: 'draft-2020-12', unrepresentable: 'any' };
  try {
    const out = z.toJSONSchema(schema, { ...opts, io: 'input' });
    if (out && out.properties && Object.keys(out.properties).length) return out;
  } catch (_) { /* fall through */ }
  try { return z.toJSONSchema(schema, { ...opts, io: 'output' }); } catch (_) { return { type: 'object' }; }
}

const openObject = (props) => ({ type: 'object', additionalProperties: true, properties: props });

const FINDING = openObject({
  type: { type: 'string' }, severity: { type: 'integer' }, score: { type: 'number' },
  confidence: { type: 'string' }, masked: { type: 'string' }, vendor: { type: 'string' }, vendorLabel: { type: 'string' },
});

const RESPONSES = {
  ErrorResponse: openObject({ error: { type: 'string' }, fields: { type: 'array', items: { type: 'string' } }, reason: { type: 'string' }, retryMs: { type: 'integer' } }),
  GateResponse: openObject({
    id: { type: 'string' }, decision: { type: 'string', enum: ['allow', 'block', 'redact', 'log'] },
    mode: { type: 'string' }, status: { type: 'string' }, riskScore: { type: 'integer' },
    findings: { type: 'array', items: FINDING }, categories: { type: 'array', items: { type: 'string' } },
    reasons: { type: 'array', items: { type: 'string' } }, tokenizedPrompt: { type: 'string' },
    releaseToken: { type: 'string' }, message: { type: 'string' },
  }),
  ScanFileResponse: openObject({ id: { type: 'string' }, decision: { type: 'string' }, status: { type: 'string' }, supported: { type: 'boolean' }, filename: { type: 'string' }, processor: { type: 'string' }, inspected: { type: 'boolean' }, ocrRequired: { type: 'boolean' }, findings: { type: 'array', items: FINDING } }),
  ScanResponseResult: openObject({ leaked: { type: 'boolean' }, decision: { type: 'string' }, status: { type: 'string' }, blocked: { type: 'boolean' }, findings: { type: 'array', items: FINDING }, categories: { type: 'array', items: { type: 'string' } }, redacted: { type: 'string' }, reasons: { type: 'array', items: { type: 'string' } } }),
  RehydrateResponse: openObject({ id: { type: 'string' }, text: { type: 'string' }, rehydrated: { type: 'boolean' }, reason: { type: 'string' } }),
  StatusResponse: openObject({ id: { type: 'string' }, status: { type: 'string' }, released: { type: 'boolean' } }),
  HeartbeatResponse: openObject({ id: { type: 'string' }, decision: { type: 'string' }, status: { type: 'string' }, failedChecks: { type: 'array', items: { type: 'string' } }, companions: { type: 'object', additionalProperties: { type: 'string', enum: ['active', 'stale', 'missing'] } } }),
  DiscoveryResponse: openObject({ status: { type: 'string' }, imported: { type: 'integer' }, observations: { type: 'integer' }, destinations: { type: 'array', items: openObject({ id: { type: 'string' }, destination: { type: 'string' }, observations: { type: 'integer' }, status: { type: 'string' } }) } }),
  DetectorList: { type: 'array', items: openObject({ id: { type: 'string' }, severity: { type: 'integer' }, severityLabel: { type: 'string' } }) },
  SensorPolicy: openObject({ enforcementMode: { type: 'string' }, blockMinSeverity: { type: 'integer' }, blockRiskScore: { type: 'integer' }, alwaysBlock: { type: 'array', items: { type: 'string' } } }),
  PolicyBundle: openObject({ version: { type: 'integer' }, issuedAt: { type: 'string' }, expiresAt: { type: 'string' }, signature: { type: 'string' } }),
  PubkeyResponse: openObject({ publicKey: { type: 'string' }, algorithm: { type: 'string' }, bundleVersion: { type: 'integer' } }),
};

const ERR = (desc) => ({ description: desc, content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } });
const OK = (ref, desc) => ({ description: desc, content: { 'application/json': { schema: { $ref: `#/components/schemas/${ref}` } } } });

// One entry per route. Errors reuse ErrorResponse.
const PATHS = [
  { method: 'post', path: '/api/v1/gate', op: 'gate', reqRef: 'GateRequest', ok: ['GateResponse', 'Decision recorded'], example: { prompt: 'Member SSN is 123-45-6789', destination: 'chatgpt.com', user: 'teller@cu.example' } },
  { method: 'post', path: '/api/v1/scan-file', op: 'scanFile', reqRef: 'ScanFileRequest', ok: ['ScanFileResponse', 'File scanned'], example: { filename: 'notes.txt', contentBase64: 'bWVtYmVyIFNTTiAxMjMtNDUtNjc4OQ==', destination: 'chatgpt.com' } },
  { method: 'post', path: '/api/v1/scan-response', op: 'scanResponse', reqRef: 'ScanResponseRequest', ok: ['ScanResponseResult', 'Model response scanned'], example: { text: 'here is the SSN 123-45-6789', destination: 'chatgpt.com' } },
  { method: 'post', path: '/api/v1/rehydrate', op: 'rehydrate', reqRef: 'RehydrateRequest', ok: ['RehydrateResponse', 'Token vault rehydrated'], releaseToken: true, example: { id: 'q_abc123' } },
  { method: 'post', path: '/api/v1/discovery', op: 'discovery', reqRef: 'DiscoveryRequest', ok: ['DiscoveryResponse', 'Sightings imported'], okCode: '202', example: { source: 'zscaler', sightings: [{ destination: 'chatgpt.com', user: 'teller@cu.example' }] } },
  { method: 'post', path: '/api/v1/heartbeat', op: 'heartbeat', reqRef: 'HeartbeatRequest', ok: ['HeartbeatResponse', 'Presence recorded'], example: { user: 'teller@cu.example', source: 'browser_extension' } },
  { method: 'get', path: '/api/v1/policy', op: 'getPolicy', ok: ['SensorPolicy', 'Sensor-safe policy'] },
  { method: 'get', path: '/api/v1/policy/bundle', op: 'getPolicyBundle', ok: ['PolicyBundle', 'Signed policy bundle'] },
  { method: 'get', path: '/api/v1/policy/pubkey', op: 'getPolicyPubkey', ok: ['PubkeyResponse', 'Policy-bundle public key'] },
  { method: 'get', path: '/api/v1/detectors', op: 'listDetectors', ok: ['DetectorList', 'Detector inventory'] },
  { method: 'get', path: '/api/v1/status/{id}', op: 'getStatus', ok: ['StatusResponse', 'Held-item status'], releaseToken: true, pathParam: 'id' },
];

const REQUEST_SCHEMAS = {
  GateRequest: () => requestSchema(validation.gateSchema),
  ScanFileRequest: () => requestSchema(validation.scanFileSchema),
  ScanResponseRequest: () => requestSchema(validation.scanResponseSchema),
  RehydrateRequest: () => requestSchema(validation.rehydrateSchema),
  DiscoveryRequest: () => requestSchema(validation.aiDiscoverySchema),
  HeartbeatRequest: () => requestSchema(validation.heartbeatSchema),
};

function buildPaths() {
  const paths = {};
  for (const r of PATHS) {
    const security = [{ IngestKey: [] }];
    if (r.releaseToken) security.push({ ReleaseToken: [] });
    const op = {
      operationId: r.op,
      tags: ['sensor-api'],
      security,
      responses: {
        [r.okCode || '200']: OK(r.ok[0], r.ok[1]),
        400: ERR('Invalid request body'),
        401: ERR('Missing or invalid ingest key'),
        403: ERR('Tenant/seat or release-token check failed'),
        404: ERR('Not found'),
        409: ERR('Conflict'),
        413: ERR('Payload too large'),
        429: ERR('Rate limited or key locked out'),
      },
    };
    if (r.pathParam) op.parameters = [{ name: r.pathParam, in: 'path', required: true, schema: { type: 'string' } }];
    if (r.reqRef) {
      op.requestBody = {
        required: true,
        content: { 'application/json': { schema: { $ref: `#/components/schemas/${r.reqRef}` }, ...(r.example ? { example: r.example } : {}) } },
      };
    }
    paths[r.path] = paths[r.path] || {};
    paths[r.path][r.method] = op;
  }
  return paths;
}

let _cache = null;
function document() {
  if (_cache) return _cache;
  const components = {
    securitySchemes: {
      IngestKey: { type: 'apiKey', in: 'header', name: 'x-api-key' },
      ReleaseToken: { type: 'apiKey', in: 'header', name: 'x-release-token' },
    },
    schemas: { ...RESPONSES },
  };
  for (const name of Object.keys(REQUEST_SCHEMAS)) components.schemas[name] = REQUEST_SCHEMAS[name]();
  _cache = {
    openapi: '3.1.0',
    info: { title: 'RedactWall Sensor & Scan API', version: pkg.version, description: 'On-device DLP gateway for AI prompts. Sensors authenticate with an ingest key; nothing but sanitized, masked findings is sent to the control plane.' },
    servers: [{ url: '/', description: 'This RedactWall instance' }],
    security: [{ IngestKey: [] }],
    tags: [{ name: 'sensor-api', description: 'Sensor ingestion and scan endpoints' }],
    paths: buildPaths(),
    components,
  };
  return _cache;
}

module.exports = { document, PATHS, REQUEST_SCHEMAS };
