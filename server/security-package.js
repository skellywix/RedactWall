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

const SCHEMA_VERSION = 'promptwall.security-trust-package.v1';
const DEFAULT_LOCKFILE = path.join(__dirname, '..', 'package-lock.json');
const CONTROL_STATES = new Set(['verified', 'attention', 'missing']);
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
        name: safeText(packageInfo.name || root.name || 'promptwall', 'promptwall', 80),
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

function control(id, label, status, detail, evidence = [], owner = 'security') {
  return {
    id,
    label,
    status: state(status),
    owner,
    detail: safeText(detail, '', 260),
    evidence: (Array.isArray(evidence) ? evidence : [evidence]).filter(Boolean).map((item) => safeText(item, '', 180)).slice(0, 8),
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
      'Browser, endpoint, MCP, proxy, and gateway paths use PromptWall detector outputs before outbound AI use.',
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
      boolState(dataKey.ok || env.SENTINEL_DATA_KEY || env.PROMPTWALL_DATA_KEY),
      'Held approval prompts use AES-256-GCM sealing when a stable data key is configured; no key means raw retention is refused.',
      ['SENTINEL_DATA_KEY/PROMPTWALL_DATA_KEY preflight', 'server/crypto.js AES-256-GCM'],
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
      ['node --test test/ai-llm-gateway.test.js', 'docs/AI_LLM_GATEWAY.md'],
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
      question: 'Does PromptWall retain raw prompt bodies in vendor-risk exports?',
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

function docs() {
  return [
    { label: 'Deployment runbook', path: 'docs/DEPLOYMENT.md' },
    { label: 'AI LLM gateway', path: 'docs/AI_LLM_GATEWAY.md' },
    { label: 'Competitive alignment', path: 'docs/COMPETITIVE_ALIGNMENT.md' },
    { label: 'Managed extension deployment', path: 'docs/MANAGED_EXTENSION_DEPLOYMENT.md' },
    { label: 'Scheduled evidence packs', path: 'docs/EVIDENCE_PACK_TASK.md' },
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
      name: safeText(packageInfo.name || 'promptwall', 'promptwall', 80),
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
    validation: {
      generatedEvidence: input.validation && Array.isArray(input.validation.generatedEvidence) ? input.validation.generatedEvidence.slice(0, 20) : [],
      recommendedCommands: validationCommands(),
    },
    questionnaire: questionnaire(controls),
    sbom,
    documents: docs(),
    exclusions: limitations(),
  };
}

function packageReadme(pkg) {
  return [
    '# PromptWall Security Trust Package',
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
  trustPackage,
  packageFiles,
  packageArchive,
  packageReadme,
};
