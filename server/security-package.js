'use strict';
/**
 * Security trust package generator.
 *
 * This is the procurement/vendor-risk companion to the examiner evidence pack.
 * It emits control coverage, validation commands, and a bounded dependency
 * inventory without reading prompt bodies, secrets, raw audit details, or local
 * filesystem paths.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const SCHEMA_VERSION = 'redactwall.security-trust-package.v1';
const DEFAULT_LOCKFILE = path.join(__dirname, '..', 'package-lock.json');
const CONTROL_STATES = new Set(['verified', 'attention', 'missing']);
const SOC2_CONTROL_CRITERIA = Object.freeze({
  local_detection: ['CC6.7', 'CC8.1'],
  privacy_minimization: ['CC6.7'],
  audit_chain: ['CC7.2'],
  admin_mfa: ['CC6.1'],
  secure_sessions: ['CC6.1'],
  encrypted_retention: ['CC6.1'],
  default_deny_ai: ['CC6.6'],
  response_scanning: ['CC6.7'],
  required_sensors: ['CC7.1'],
  llm_gateway: ['CC6.6'],
  soc_handoff: ['CC7.3', 'CC7.4'],
});
const SOC2_CRITERIA_TITLES = Object.freeze({
  'CC6.1': 'Logical access controls and protection of data at rest',
  'CC6.6': 'Boundary protection against external threats',
  'CC6.7': 'Restriction of information transmission, movement, and removal',
  'CC7.1': 'Monitoring for configuration and vulnerability exposure',
  'CC7.2': 'Anomaly and security-event monitoring',
  'CC7.3': 'Security-event evaluation',
  'CC7.4': 'Security incident response',
  'CC8.1': 'Change management over system components',
});
const PRIVACY_CONTRACT = Object.freeze({
  rawPromptBodies: false,
  redactedPromptBodies: false,
  rawFindingValues: false,
  tokenVaultValues: false,
  secretsOrCredentials: false,
  rawAuditDetails: false,
  localFilePaths: false,
  rawUrls: false,
  packageLockPaths: false,
});

function safeText(value, fallback = '', limit = 160) {
  const text = String(value == null ? '' : value).trim();
  return (text || fallback).slice(0, limit);
}

function state(value) {
  return CONTROL_STATES.has(String(value || '')) ? String(value) : 'missing';
}

function boolState(ok, partial = false) {
  if (ok) return 'verified';
  return partial ? 'attention' : 'missing';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readJsonFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

function lockPackageName(packagePath) {
  const normalized = String(packagePath || '').replace(/\\/g, '/');
  const marker = 'node_modules/';
  const index = normalized.lastIndexOf(marker);
  if (index < 0) return '';
  return normalized.slice(index + marker.length);
}

function dependencySets(lockfile = {}) {
  const root = (lockfile.packages && lockfile.packages['']) || {};
  return {
    prod: new Set(Object.keys(root.dependencies || {})),
    dev: new Set(Object.keys(root.devDependencies || {})),
    optional: new Set(Object.keys(root.optionalDependencies || {})),
  };
}

function componentScope(name, info = {}, sets = dependencySets()) {
  if (info.optional) return 'optional';
  if (sets.prod.has(name)) return 'required';
  if (sets.optional.has(name)) return 'optional';
  if (sets.dev.has(name) || info.dev) return 'excluded';
  return 'required';
}

function packageUrl(name, version) {
  if (!name || !version) return null;
  const encoded = name.startsWith('@')
    ? `@${name.slice(1).split('/').map(encodeURIComponent).join('/')}`
    : encodeURIComponent(name);
  return `pkg:npm/${encoded}@${encodeURIComponent(version)}`;
}

function integrityHash(integrity) {
  const text = String(integrity || '');
  const match = text.match(/^(sha\d+)-(.+)$/i);
  if (!match) return [];
  return [{ alg: match[1].toUpperCase(), content: match[2].slice(0, 160) }];
}

function buildSbom({ lockfile = null, lockfilePath = DEFAULT_LOCKFILE, packageInfo = {} } = {}) {
  const parsed = lockfile || readJsonFile(lockfilePath);
  const packages = parsed.packages && typeof parsed.packages === 'object' ? parsed.packages : {};
  const sets = dependencySets(parsed);
  const components = Object.entries(packages)
    .filter(([packagePath, info]) => packagePath && info && typeof info === 'object')
    .map(([packagePath, info]) => {
      const name = lockPackageName(packagePath);
      if (!name || !info.version) return null;
      const component = {
        type: 'library',
        name,
        version: String(info.version),
        scope: componentScope(name, info, sets),
      };
      const purl = packageUrl(name, info.version);
      if (purl) component.purl = purl;
      if (typeof info.license === 'string' && info.license.trim()) {
        component.licenses = [{ license: { id: info.license.slice(0, 80) } }];
      }
      const hashes = integrityHash(info.integrity);
      if (hashes.length) component.hashes = hashes;
      return component;
    })
    .filter(Boolean)
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  const root = packages[''] || {};
  const prodDirect = [...sets.prod].sort();
  const devDirect = [...sets.dev].sort();
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:sha256:${sha256(JSON.stringify({ name: packageInfo.name || root.name, version: packageInfo.version || root.version, components }))}`,
    metadata: {
      component: {
        type: 'application',
        name: safeText(packageInfo.name || root.name || 'redactwall', 'redactwall', 80),
        version: safeText(packageInfo.version || root.version || '0.0.0', '0.0.0', 40),
      },
      lockfile: {
        format: 'npm-package-lock',
        lockfileVersion: parsed.lockfileVersion || null,
        sha256: sha256(JSON.stringify(parsed)),
      },
    },
    summary: {
      components: components.length,
      directProductionDependencies: prodDirect.length,
      directDevelopmentDependencies: devDirect.length,
      optionalComponents: components.filter((item) => item.scope === 'optional').length,
      developmentComponents: components.filter((item) => item.scope === 'excluded').length,
    },
    directDependencies: {
      production: prodDirect,
      development: devDirect,
    },
    components,
  };
}

function preflightControl(status, id) {
  const check = ((status && status.checks) || []).find((item) => item && item.id === id);
  return check ? { ok: check.ok === true, severity: check.severity || 'warning' } : { ok: false, severity: 'warning' };
}

// Assurance level per control: HOW the control is verified, not whether it is
// currently passing. Nothing is 'third-party-verified' until a real external
// audit or penetration test exists — the honest ceiling of this self-attested
// package (see docs/security/SECURITY_TRUST_PACKAGE.md).
const ASSURANCE = { SELF: 'self-attested', CI: 'ci-verified', THIRD_PARTY: 'third-party-verified' };
const CI_VERIFIED_CONTROLS = new Set(['local_detection', 'privacy_minimization', 'audit_chain', 'response_scanning', 'llm_gateway']);

function assuranceFor(id) {
  return CI_VERIFIED_CONTROLS.has(id) ? ASSURANCE.CI : ASSURANCE.SELF;
}

function control(id, label, status, detail, evidence = [], owner = 'security') {
  return {
    id,
    label,
    status: state(status),
    assurance: assuranceFor(id),
    owner,
    detail: safeText(detail, '', 260),
    evidence: (Array.isArray(evidence) ? evidence : [evidence]).filter(Boolean).map((item) => safeText(item, '', 180)).slice(0, 8),
    soc2Criteria: [...(SOC2_CONTROL_CRITERIA[id] || [])],
  };
}

function buildControls({ policy = {}, auditIntegrity = {}, preflight = {}, posture = {}, coverage = {}, env = {} } = {}) {
  const requiredSensors = new Set(Array.isArray(policy.requiredSensors) ? policy.requiredSensors : []);
  const coverageTotals = coverage && coverage.totals ? coverage.totals : {};
  const activeRequiredSensors = Number(coverageTotals.activeRequiredSensors) || 0;
  const requiredSensorCount = Number(coverageTotals.requiredSensors) || requiredSensors.size;
  const hardening = posture && posture.hardening ? posture.hardening : {};
  const mfa = preflightControl(preflight, 'admin_mfa');
  const secureCookie = preflightControl(preflight, 'secure_cookie');
  const sessionSecret = preflightControl(preflight, 'session_secret_strength');
  const dataKey = preflightControl(preflight, 'data_key_strength');
  const gatewayProof = (((hardening.mission || {}).proofLedger || {}).verified || 0) > 0
    || ((hardening.areas || []).some((area) => area && area.id === 'ai_gateway_enforcement' && area.state !== 'blocked'));
  return [
    control(
      'local_detection',
      'Local shared detection engine',
      'verified',
      'Browser, endpoint, MCP, proxy, and gateway paths use RedactWall detector outputs before outbound AI use.',
      ['Detector sync-check is part of review:ci', 'Evidence pack exports detector ids and masked findings only'],
      'security engineering',
    ),
    control(
      'privacy_minimization',
      'Prompt-body minimization',
      'verified',
      'Operational packages exclude raw prompts, redacted prompts, token vaults, raw findings, raw audit details, URLs, and local paths.',
      ['privacyContract.rawPromptBodies=false', 'security trust package excludes package-lock filesystem paths'],
      'privacy',
    ),
    control(
      'audit_chain',
      'Tamper-evident audit chain',
      boolState(auditIntegrity && auditIntegrity.ok, auditIntegrity && auditIntegrity.count),
      auditIntegrity && auditIntegrity.ok
        ? `${Number(auditIntegrity.count) || 0} audit entries verify as hash-chained.`
        : 'Audit chain is absent or did not verify in the current runtime evidence.',
      ['GET /api/audit', 'npm run review:ci includes audit-integrity regressions'],
      'compliance',
    ),
    control(
      'admin_mfa',
      'Security Admin MFA',
      boolState(mfa.ok),
      mfa.ok ? 'Security Admin TOTP MFA is configured.' : 'Production preflight requires ADMIN_TOTP_SECRET before startup can pass.',
      ['Production preflight check: admin_mfa'],
      'identity',
    ),
    control(
      'secure_sessions',
      'Secure admin sessions',
      boolState(secureCookie.ok && sessionSecret.ok, secureCookie.ok || sessionSecret.ok),
      secureCookie.ok && sessionSecret.ok
        ? 'Session secret strength and secure-cookie production posture are configured.'
        : 'Session secret and secure cookie posture need production preflight proof.',
      ['HMAC-signed sessions', 'CSRF token required on unsafe admin writes'],
      'identity',
    ),
    control(
      'encrypted_retention',
      'Encrypted retained approval data',
      boolState(dataKey.ok || env.REDACTWALL_DATA_KEY || env.PROMPTWALL_DATA_KEY || env.SENTINEL_DATA_KEY),
      'Held approval prompts use AES-256-GCM sealing when a stable data key is configured; no key means raw retention is refused.',
      ['REDACTWALL_DATA_KEY (PROMPTWALL_/SENTINEL_ aliases) preflight', 'server/crypto.js AES-256-GCM'],
      'privacy',
    ),
    control(
      'default_deny_ai',
      'Default-deny unknown AI apps',
      boolState(policy.blockUnapprovedAiDestinations),
      policy.blockUnapprovedAiDestinations
        ? 'Unreviewed AI destinations are blocked until governed, allowed, or explicitly blocked with a reason.'
        : 'Unknown AI destinations are not currently default-denied.',
      ['Policy: blockUnapprovedAiDestinations'],
      'security operations',
    ),
    control(
      'response_scanning',
      'AI response scanning',
      boolState(['flag', 'redact', 'block'].includes(String(policy.responseScanMode || ''))),
      `Response scan mode is ${safeText(policy.responseScanMode || 'unset', 'unset', 30)}.`,
      ['POST /api/v1/scan-response', 'AI LLM gateway response scan path'],
      'ai platform',
    ),
    control(
      'required_sensors',
      'Required sensor baseline',
      boolState(requiredSensors.has('browser_extension') && requiredSensors.has('endpoint_agent') && requiredSensors.has('mcp_guard'), requiredSensors.size),
      `${requiredSensors.size} required sensor${requiredSensors.size === 1 ? '' : 's'} configured; ${activeRequiredSensors}/${requiredSensorCount || requiredSensors.size} active in current coverage.`,
      ['Policy: requiredSensors', 'Coverage: activeRequiredSensors'],
      'endpoint operations',
    ),
    control(
      'llm_gateway',
      'Provider runtime AI gateway',
      boolState(gatewayProof),
      'Gateway path supports prompt gating, response scanning, model allowlisting, shared rate limits, and provider-native OpenAI, Anthropic, Gemini, and Bedrock Runtime routes.',
      ['node --test test/ai-llm-gateway.test.js', 'docs/deployment/AI_LLM_GATEWAY.md'],
      'ai platform',
    ),
    control(
      'soc_handoff',
      'SOC and reviewer handoff',
      boolState(String(env.SIEM_WEBHOOK_URL || '').startsWith('https://') || (policy.approvalRoutingRules || []).length, (policy.approvalRoutingRules || []).length),
      `${(policy.approvalRoutingRules || []).length} approval routing rule${(policy.approvalRoutingRules || []).length === 1 ? '' : 's'} configured; SIEM webhook ${String(env.SIEM_WEBHOOK_URL || '').startsWith('https://') ? 'configured' : 'not configured'}.`,
      ['SIEM package generator', 'Approval notification adapters'],
      'security operations',
    ),
  ];
}

function summarizeControls(controls) {
  const total = controls.length || 1;
  const verified = controls.filter((item) => item.status === 'verified').length;
  const attention = controls.filter((item) => item.status === 'attention').length;
  const missing = controls.filter((item) => item.status === 'missing').length;
  return {
    total,
    verified,
    attention,
    missing,
    percent: Math.round((verified / total) * 100),
    state: missing ? 'attention' : verified === total ? 'ready' : 'attention',
  };
}

function worstControlStatus(statuses) {
  if (statuses.includes('missing')) return 'missing';
  if (statuses.includes('attention')) return 'attention';
  return 'verified';
}

function soc2Readiness(controls) {
  const byCriterion = new Map();
  for (const item of controls) {
    for (const criterionId of item.soc2Criteria || []) {
      if (!byCriterion.has(criterionId)) byCriterion.set(criterionId, []);
      byCriterion.get(criterionId).push(item);
    }
  }
  const criteria = [...byCriterion.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([id, mapped]) => ({
      id,
      title: SOC2_CRITERIA_TITLES[id] || 'SOC 2 Trust Services Criteria',
      controls: mapped.map((item) => item.id),
      status: worstControlStatus(mapped.map((item) => item.status)),
    }));
  return {
    framework: 'SOC 2 Trust Services Criteria (2017), common criteria',
    criteria,
    summary: {
      criteria: criteria.length,
      verified: criteria.filter((item) => item.status === 'verified').length,
      attention: criteria.filter((item) => item.status === 'attention').length,
      missing: criteria.filter((item) => item.status === 'missing').length,
      note: 'Self-attested readiness mapping derived from package controls; not a SOC 2 report or audit opinion.',
    },
  };
}

function vulnerabilityPolicy(generatedAt) {
  return {
    patchSlas: [
      { severity: 'critical', patchWithin: '72 hours' },
      { severity: 'high', patchWithin: '7 days' },
      { severity: 'medium', patchWithin: '30 days' },
      { severity: 'low', patchWithin: '90 days' },
    ],
    scanning: {
      cadence: 'npm audit --omit=dev runs in CI on every push and pull request',
      pipeline: '.github/workflows/ci.yml dependency-audit step',
    },
    dependencyPolicy: {
      lockfilePinned: true,
      productionDependenciesAudited: true,
      inventory: 'CycloneDX dependency inventory included in this package under sbom',
    },
    lastValidatedAt: generatedAt,
  };
}

function dpaBaaPosture() {
  return {
    attestation: 'self-attested posture; agreements are executed per customer through sales',
    dataHandling: {
      deploymentModel: 'local-first customer silo; the control plane runs inside the customer environment',
      promptEgress: false,
      vendorTelemetry: false,
      dataResidency: 'determined by the operator hosting the deployment',
    },
    subProcessors: [],
    subProcessorNote: 'RedactWall introduces no sub-processors by default; self-hosted deployments add only the hosting and SIEM vendors they choose.',
    dpa: { offered: true, executedPerCustomer: true, contact: 'sales' },
    hipaaBaa: { available: true, executedPerCustomer: true, contact: 'sales' },
  };
}

function retainedRetentionDays(policy) {
  const days = Number(policy && policy.rawRetentionDays);
  if (!Number.isFinite(days)) return 30;
  return Math.max(0, Math.min(3650, Math.floor(days)));
}

function retentionLegalHold(policy = {}) {
  return {
    retention: {
      rawRetentionDays: retainedRetentionDays(policy),
      storeRawForApproval: policy.storeRawForApproval !== false,
      purge: 'Retained raw approval prompts and token vaults past rawRetentionDays are purged; each purge is recorded in the tamper-evident audit chain.',
      encryptionAtRest: 'Retained approval prompts are sealed with AES-256-GCM; without a stable data key, raw retention is refused.',
    },
    legalHold: {
      supported: false,
      note: 'No automated legal-hold flag exists today. Suspending retention purges requires operator action: export an evidence pack before the purge window and raise rawRetentionDays for the affected period.',
    },
  };
}

function validationCommands() {
  return [
    { id: 'review_ci', command: 'npm run review:ci', proves: 'Full repo gate: formatting, docs drift, AI domain coverage, native binding, Node tests, browser tests, sync-check, and detection eval.' },
    { id: 'setup_check', command: 'npm run setup:check -- --production --skip-install', proves: 'Production prerequisite and preflight visibility before deployment.' },
    { id: 'audit_integrity', command: 'node -e "const db=require(\'./server/db\'); console.log(db.verifyAuditChain())"', proves: 'Tamper-evident audit chain verifies against the current evidence database.' },
    { id: 'evidence_pack', command: 'npm run evidence:pack -- --zip', proves: 'Examiner package exports sanitized evidence without prompt bodies.' },
    { id: 'security_package', command: 'npm run security:package -- --zip', proves: 'Vendor-risk package exports controls, docs, and SBOM inventory without secrets.' },
  ];
}

function questionnaire(controls) {
  const byId = new Map(controls.map((item) => [item.id, item]));
  const answer = (id, yes, no) => byId.get(id) && byId.get(id).status === 'verified' ? yes : no;
  return [
    {
      question: 'Does RedactWall retain raw prompt bodies in vendor-risk exports?',
      answer: 'No. Security packages, SIEM packages, and examiner evidence packs omit raw prompts, redacted prompts, token vaults, raw findings, raw audit details, raw URLs, and local paths.',
      evidence: 'privacyContract',
    },
    {
      question: 'Can administrators prove audit integrity?',
      answer: answer('audit_chain', 'Yes. The current audit chain verified when this package was generated.', 'Partially. The package includes audit-chain status, but current runtime evidence did not prove a clean chain.'),
      evidence: 'controls.audit_chain',
    },
    {
      question: 'Are unknown AI destinations governed by default?',
      answer: answer('default_deny_ai', 'Yes. Unknown AI apps are default-denied until reviewed.', 'Not yet. Enable default-deny before production rollout.'),
      evidence: 'controls.default_deny_ai',
    },
    {
      question: 'Are AI model responses inspected before returning to users?',
      answer: answer('response_scanning', 'Yes. Response scan mode is configured and gateway response scanning is covered by tests.', 'Not fully. Configure response scan mode before relying on output controls.'),
      evidence: 'controls.response_scanning',
    },
    {
      question: 'Is there a dependency inventory for vendor review?',
      answer: 'Yes. The package includes a bounded CycloneDX-style dependency inventory generated from package-lock.json without local filesystem paths.',
      evidence: 'sbom',
    },
  ];
}

// Credit-union third-party due-diligence responses, mapped to the NCUA
// due-diligence letters (07-CU-13 Evaluating Third Party Relationships,
// 01-CU-20 Due Diligence Over Third Party Service Providers). Each response
// cites a control id or a runnable command — evidence pointers, not certification.
function dueDiligence(controls) {
  const byId = new Map(controls.map((item) => [item.id, item]));
  const cite = (id) => (byId.get(id) ? `controls.${id}` : id);
  return [
    { dimension: 'Data security & confidentiality of member NPI', ncuaReference: 'NCUA 07-CU-13; GLBA 12 CFR 748 App A', response: 'Detection runs on-device; operational packages exclude prompt bodies, secrets, token vaults, and raw findings. Held approval data is AES-256-GCM sealed.', evidence: [cite('privacy_minimization'), cite('encrypted_retention'), cite('local_detection')] },
    { dimension: 'Where member data flows (residency / egress)', ncuaReference: 'NCUA 07-CU-13; GLBA 501(b)', response: 'Prompts are scanned locally; only masked evidence and hashes leave the device. Remote semantic classification is off by default and HTTPS-enforced when explicitly enabled.', evidence: [cite('local_detection'), 'docs/security/SECURITY_WHITEPAPER.md'] },
    { dimension: 'Audit trail & monitoring', ncuaReference: 'NCUA 12 CFR 748; GLBA monitoring', response: 'Every decision is written to a tamper-evident SHA-256 hash-chained audit log; verifyAuditChain() proves integrity.', evidence: [cite('audit_chain'), 'node -e "console.log(require(\'./server/db\').verifyAuditChain())"'] },
    { dimension: 'Incident response & 72-hour reporting', ncuaReference: 'NCUA 12 CFR 748.1(c)', response: 'The examiner pack includes a 72-hour incident workflow keyed to detectedAt + 72h; the actual NCUA filing is performed by the credit union.', evidence: ['docs/security/INCIDENT_RESPONSE.md', 'controlMappings.incident_readiness'] },
    { dimension: 'Access control & administrator MFA', ncuaReference: 'NCUA 07-CU-13; GLBA access controls', response: 'Security Admin TOTP MFA and secure-cookie/session-secret posture are enforced by production preflight; raw reveal and approval release require password step-up.', evidence: [cite('admin_mfa'), cite('secure_sessions')] },
    { dimension: 'Sub-processors & subcontractors', ncuaReference: 'NCUA 07-CU-13 service-provider oversight', response: 'Local-first architecture ships with no default sub-processors; any per-customer sub-processor is disclosed and governed by an executed DPA/BAA.', evidence: ['dpaBaaPosture', 'legalTemplates'] },
    { dimension: 'Vulnerability & patch management', ncuaReference: 'NCUA 07-CU-13; FFIEC', response: 'Documented patch SLAs (critical 72h, high 7d, medium 30d, low 90d); npm audit runs in CI on every push.', evidence: ['vulnerabilityPolicy', 'npm audit'] },
    { dimension: 'Business continuity & recoverability', ncuaReference: 'NCUA resilience; GLBA availability', response: 'Backup verification and restore-drill tooling ship with the product; run them to attach current evidence to the examiner pack.', evidence: ['npm run backup:verify', 'npm run backup:drill'] },
    { dimension: 'Independent assurance (SOC 2 / penetration test)', ncuaReference: 'NCUA 07-CU-13', response: 'SOC 2 mappings are self-attested, not an audit opinion; no third-party penetration-test report exists yet. Per-control assurance levels are labeled; nothing is third-party-verified.', evidence: ['soc2Readiness', 'exclusions'] },
  ];
}

// SAMPLE contract templates. RedactWall ships text for procurement convenience
// only; it is non-binding and must be reviewed/executed by the customer's
// counsel (Decision 5 in PLANS/credit-union-tuning.md). Not legal advice.
function legalTemplates() {
  return {
    note: 'SAMPLE templates for procurement convenience only. Non-binding; review and execute with your legal counsel. RedactWall does not provide legal advice.',
    templates: [
      { label: 'Data Processing Addendum (DPA) — sample', path: 'docs/legal/DPA_TEMPLATE_SAMPLE.md' },
      { label: 'Business Associate Agreement (BAA) — sample', path: 'docs/legal/BAA_TEMPLATE_SAMPLE.md' },
      { label: 'GLBA service-provider flow-down clauses — sample', path: 'docs/legal/GLBA_FLOWDOWN_SAMPLE.md' },
    ],
  };
}

function docs() {
  return [
    { label: 'Deployment runbook', path: 'docs/deployment/DEPLOYMENT.md' },
    { label: 'AI LLM gateway', path: 'docs/deployment/AI_LLM_GATEWAY.md' },
    { label: 'Competitive alignment', path: 'docs/product/COMPETITIVE_ALIGNMENT.md' },
    { label: 'Managed extension deployment', path: 'docs/deployment/MANAGED_EXTENSION_DEPLOYMENT.md' },
    { label: 'Scheduled evidence packs', path: 'docs/deployment/EVIDENCE_PACK_TASK.md' },
    { label: 'Security whitepaper', path: 'docs/security/SECURITY_WHITEPAPER.md' },
    { label: 'Incident response runbook', path: 'docs/security/INCIDENT_RESPONSE.md' },
  ];
}

function limitations() {
  return [
    'This package is a self-attestation and procurement artifact; it is not a penetration-test report or compliance certification.',
    'Live production proof still requires customer-specific environment values, MFA enrollment, HTTPS/TLS, deployment topology, and backup/restore evidence.',
    'Dependency vulnerability status should be paired with a fresh npm audit or customer-approved SCA scan at release time.',
    'Marketplace-native SOC/SOAR app certification remains separate from the offline SIEM package.',
  ];
}

function trustPackage(input = {}) {
  const packageInfo = input.packageInfo || {};
  const sbom = input.sbom || buildSbom({
    lockfile: input.lockfile,
    lockfilePath: input.lockfilePath || DEFAULT_LOCKFILE,
    packageInfo,
  });
  const controls = buildControls(input);
  const controlCoverage = summarizeControls(controls);
  const generatedAt = input.generatedAt || new Date().toISOString();
  return {
    schemaVersion: SCHEMA_VERSION,
    generatedAt,
    product: {
      name: safeText(packageInfo.name || 'redactwall', 'redactwall', 80),
      version: safeText(packageInfo.version || '0.0.0', '0.0.0', 40),
      description: safeText(packageInfo.description || 'Inline DLP gateway for AI chat prompts.', '', 220),
      nodeEngine: safeText(packageInfo.engines && packageInfo.engines.node || '>=22', '>=22', 40),
      license: safeText(packageInfo.license || 'UNLICENSED', 'UNLICENSED', 80),
    },
    summary: {
      state: controlCoverage.state,
      controlCoverage,
      dependencyInventory: sbom.summary,
      privacy: 'metadata only; prompt bodies, secrets, token vaults, raw audit details, URLs, and local paths excluded',
    },
    privacyContract: { ...PRIVACY_CONTRACT },
    controls,
    soc2Readiness: soc2Readiness(controls),
    vulnerabilityPolicy: vulnerabilityPolicy(generatedAt),
    dpaBaaPosture: dpaBaaPosture(),
    retentionLegalHold: retentionLegalHold(input.policy || {}),
    validation: {
      generatedEvidence: input.validation && Array.isArray(input.validation.generatedEvidence) ? input.validation.generatedEvidence.slice(0, 20) : [],
      recommendedCommands: validationCommands(),
    },
    questionnaire: questionnaire(controls),
    dueDiligence: dueDiligence(controls),
    legalTemplates: legalTemplates(),
    sbom,
    documents: docs(),
    exclusions: limitations(),
  };
}

function readmePostureLines(pkg) {
  const soc2 = pkg.soc2Readiness.summary;
  const criticalSla = pkg.vulnerabilityPolicy.patchSlas.find((item) => item.severity === 'critical');
  const retention = pkg.retentionLegalHold.retention;
  return [
    `SOC 2 readiness: ${soc2.verified}/${soc2.criteria} mapped criteria verified (self-attested, not an audit opinion).`,
    `Vulnerability policy: critical patches within ${criticalSla ? criticalSla.patchWithin : 'defined SLA'}; npm audit runs in CI on every push.`,
    `Retention: raw approval retention ${retention.rawRetentionDays} days, AES-256-GCM sealed; automated legal hold: ${pkg.retentionLegalHold.legalHold.supported ? 'supported' : 'not supported (operator action required)'}.`,
    'DPA/BAA posture: local-first, no prompt egress, no default sub-processors; agreements executed per customer.',
  ];
}

function packageReadme(pkg) {
  return [
    '# RedactWall Security Trust Package',
    '',
    `Generated: ${pkg.generatedAt}`,
    `Product: ${pkg.product.name} ${pkg.product.version}`,
    '',
    'This package is intended for vendor-risk, procurement, and security review.',
    'It contains sanitized control coverage, validation commands, a dependency inventory,',
    'and documentation pointers. It does not contain prompt bodies, secrets, token vaults,',
    'raw finding values, raw audit details, local file paths, or raw URLs.',
    '',
    `Control coverage: ${pkg.summary.controlCoverage.verified}/${pkg.summary.controlCoverage.total} verified (${pkg.summary.controlCoverage.percent}%).`,
    `Dependency inventory: ${pkg.sbom.summary.components} components from package-lock.json.`,
    '',
    ...readmePostureLines(pkg),
    '',
    'Recommended validation:',
    ...pkg.validation.recommendedCommands.map((item) => `- ${item.command}`),
    '',
  ].join('\n');
}

function packageFiles(pkg) {
  return [
    { name: 'manifest.json', body: JSON.stringify({ schemaVersion: pkg.schemaVersion, generatedAt: pkg.generatedAt, product: pkg.product, summary: pkg.summary }, null, 2) },
    { name: 'security-trust-package.json', body: JSON.stringify(pkg, null, 2) },
    { name: 'sbom/cyclonedx.json', body: JSON.stringify(pkg.sbom, null, 2) },
    { name: 'README.md', body: packageReadme(pkg) },
  ];
}

function packageArchive(pkg) {
  const zip = new AdmZip();
  for (const file of packageFiles(pkg)) {
    zip.addFile(file.name, Buffer.from(`${file.body}\n`, 'utf8'));
  }
  return zip.toBuffer();
}

module.exports = {
  SCHEMA_VERSION,
  PRIVACY_CONTRACT,
  buildSbom,
  buildControls,
  summarizeControls,
  soc2Readiness,
  vulnerabilityPolicy,
  dpaBaaPosture,
  retentionLegalHold,
  trustPackage,
  packageFiles,
  packageArchive,
  packageReadme,
};
