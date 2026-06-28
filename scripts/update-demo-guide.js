'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const START = '<!-- DEMO_GUIDE_CURRENT_STATE_START -->';
const END = '<!-- DEMO_GUIDE_CURRENT_STATE_END -->';
const GENERATED_DOCS = [
  'DEMO_INSTALL_GUIDE.md',
  'docs/SALES_DEMO_GUIDE.md',
  'docs/DEMO_TECHNICIAN_SETUP.md',
];
const SEMANTIC_CATEGORIES = ['SOURCE_CODE', 'LEGAL_CONTRACT', 'CREDENTIALS', 'CONFIDENTIAL_BUSINESS'];
const DEMO_COMMANDS = [
  'setup',
  'setup:prod',
  'setup:check',
  'start',
  'simulate',
  'fire-drill',
  'test',
  'test:browser',
  'test:browser-extension',
  'sync-check',
  'eval',
  'backup',
  'backup:verify',
  'backup:restore',
  'evidence:pack',
  'evidence:pack:zip',
  'evidence:pack:scheduled',
  'evidence:pack:install-task',
  'evidence:pack:run-linux',
  'evidence:pack:install-systemd',
  'package:extension',
  'release:extension:check',
  'package:endpoint-agent',
  'package:mcp-guard',
  'endpoint:check',
  'mcp:check',
  'docs:demo-guide',
  'docs:demo-guide:check',
];
const SENSOR_AND_DOC_PATHS = [
  ['server/app.js', 'Control plane, API, dashboard, policy, approval, audit'],
  ['server/routing.js', 'Customer-configurable approval owner and SLA routing rules'],
  ['server/notifiers.js', 'Sanitized approval workflow notification adapters'],
  ['server/workflow.js', 'Approval notification status and SLA escalation'],
  ['server/public/index.html', 'Admin dashboard shell'],
  ['detection-engine/detect.js', 'Shared detection engine source of truth'],
  ['sensors/browser-extension/manifest.json', 'Browser extension source manifest'],
  ['sensors/browser-extension/background.js', 'Browser install-health heartbeat and control-plane relay'],
  ['sensors/browser-extension/content.js', 'Browser send, paste, upload enforcement'],
  ['scripts/check-extension-release.js', 'Browser extension release-readiness gate'],
  ['docs/EXTENSION_RELEASE_CHECKLIST.md', 'Chrome, Edge, and Firefox release checklist'],
  ['sensors/endpoint-agent/agent.js', 'Local folder and file sensor'],
  ['sensors/endpoint-agent/write-handoff.js', 'Signed native upload-intent handoff writer'],
  ['scripts/check-endpoint-install.js', 'Endpoint install validation and heartbeat evidence'],
  ['sensors/mcp-guard/guard.js', 'MCP tool-output redaction reference'],
  ['sensors/mcp-guard/sdk.js', 'MCP connector SDK sanitization boundary'],
  ['sensors/mcp-guard/connectors/microsoft365.js', 'Microsoft 365 MCP file-content connector'],
  ['scripts/check-mcp-guard-install.js', 'MCP guard install validation and heartbeat evidence'],
  ['config/policy.json', 'Demo policy defaults'],
  ['DEMO_INSTALL_GUIDE.md', 'Demo guide hub'],
  ['docs/SALES_DEMO_GUIDE.md', 'Sales and client-facing demo script'],
  ['docs/DEMO_TECHNICIAN_SETUP.md', 'Demo machine setup and reset runbook'],
  ['docs/DEPLOYMENT.md', 'Native Node and Docker deployment reference'],
  ['docs/MANAGED_EXTENSION_DEPLOYMENT.md', 'Managed browser extension pilot reference'],
  ['docs/EVIDENCE_PACK_TASK.md', 'Examiner evidence pack scheduled task reference'],
  ['docs/APPROVAL_ROUTING.md', 'Approval owner and SLA routing reference'],
  ['docs/TECHNICIAN_DEPLOYMENT_GUIDE.md', 'Install-day production readiness runbook'],
  ['docs/AWS_SAAS_DEPLOYMENT.md', 'Customer-silo AWS deployment path'],
];

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), 'utf8'));
}

function exists(relativePath) {
  return fs.existsSync(path.join(ROOT, relativePath));
}

function docPath(relativePath) {
  return path.join(ROOT, relativePath);
}

function asciiText(value) {
  return String(value || '')
    .replace(/[^\x20-\x7E]/g, '-')
    .replace(/\s+/g, ' ')
    .trim();
}

function commandTable(pkg, names) {
  const rows = ['| Command | Current script |', '| --- | --- |'];
  for (const name of names) {
    const script = pkg.scripts[name];
    rows.push(`| \`npm run ${name}\` | \`${script || 'missing'}\` |`);
  }
  return rows.join('\n');
}

function fileTable(entries) {
  const rows = ['| Path | Demo role | Status |', '| --- | --- | --- |'];
  for (const [relativePath, role] of entries) {
    rows.push(`| \`${relativePath}\` | ${role} | ${exists(relativePath) ? 'Present' : 'Missing'} |`);
  }
  return rows.join('\n');
}

function detectEol(text) {
  const crlf = (text.match(/\r\n/g) || []).length;
  const lf = (text.match(/\n/g) || []).length - crlf;
  return crlf > lf ? '\r\n' : '\n';
}

function normalizeEol(text, eol) {
  return text.replace(/\r?\n/g, eol);
}

function sameContent(left, right) {
  return normalizeEol(left, '\n') === normalizeEol(right, '\n');
}

function joinInline(items) {
  return items.length ? items.map((item) => `\`${item}\``).join(', ') : '_None configured._';
}

function supportedFileTypes(processors) {
  const groups = [
    ['Text and config', Array.from(processors.TEXT_EXT).sort()],
    ['Office', Array.from(processors.OFFICE_EXT).sort()],
    ['PDF', Array.from(processors.PDF_EXT).sort()],
    ['Image OCR required', Array.from(processors.IMAGE_EXT).sort()],
  ];
  return groups.map(([label, values]) => `- ${label}: ${joinInline(values)}`).join('\n');
}

function normalizeManifestHost(entry) {
  return String(entry || '').replace(/^https?:\/\//, '').replace(/\/\*$/, '');
}

function uniqueSorted(items) {
  return [...new Set(items)].sort();
}

function contentScriptHosts(manifest) {
  const matches = (manifest.content_scripts || []).flatMap((script) => script.matches || []);
  return uniqueSorted(matches.map(normalizeManifestHost));
}

function localControlPlanePermissions(manifest) {
  return uniqueSorted((manifest.host_permissions || [])
    .filter((entry) => /^http:\/\/(localhost|127\.0\.0\.1)/.test(entry))
    .map(normalizeManifestHost));
}

function status(value) {
  return value ? 'enabled' : 'disabled';
}

function validateRequiredScripts(pkg, names) {
  const missing = names.filter((name) => !pkg.scripts[name]);
  if (missing.length) {
    throw new Error(`package.json is missing demo guide script reference(s): ${missing.join(', ')}`);
  }
}

function stalePathProblems(relativePath, guide) {
  const problems = [];
  const stalePatterns = [
    'promptsentinel-app\\promptsentinel',
    'promptsentinel-app/promptsentinel',
    'cd promptsentinel',
    '-SentinelUrl',
    '$env:SENTINEL_URL',
    '$env:SENTINEL_ENV_PATH',
  ];
  for (const pattern of stalePatterns) {
    if (guide.includes(pattern)) problems.push(`${relativePath}: stale path remains: ${pattern}`);
  }
  return problems;
}

function loadSnapshot() {
  const pkg = readJson('package.json');
  const policy = readJson('config/policy.json');
  const manifest = readJson('sensors/browser-extension/manifest.json');
  const detector = require(path.join(ROOT, 'detection-engine', 'detect'));
  const customDetectors = require(path.join(ROOT, 'server', 'custom-detectors'));
  const processors = require(path.join(ROOT, 'server', 'processors'));
  const templates = require(path.join(ROOT, 'server', 'templates'));
  validateRequiredScripts(pkg, DEMO_COMMANDS);

  const detectors = detector.listDetectors({ customDetectors: customDetectors.loadCustomDetectors() }).map((item) => item.id).sort();
  const semanticCategories = detectors.filter((id) => SEMANTIC_CATEGORIES.includes(id));
  const templateLabels = templates.list().map((item) => `${item.id} (${item.label})`).sort();
  return {
    pkg,
    policy,
    manifest,
    processors,
    detectors,
    semanticCategories,
    templateLabels,
    contentHosts: contentScriptHosts(manifest),
    localControlPlaneHosts: localControlPlanePermissions(manifest),
  };
}

function overviewTable(snapshot) {
  const { pkg, policy, manifest, detectors, semanticCategories, templateLabels, contentHosts, localControlPlaneHosts } = snapshot;
  return [
    '| Source | Current value |',
    '| --- | --- |',
    `| App package | \`${pkg.name}@${pkg.version}\` |`,
    `| Active repo folder | \`${pkg.name}\` |`,
    `| Server entrypoint | \`${pkg.main}\` |`,
    `| Browser extension | \`${asciiText(manifest.name)}\` version \`${manifest.version}\` |`,
    `| Default enforcement mode | \`${policy.enforcementMode}\` |`,
    `| Block thresholds | severity \`${policy.blockMinSeverity}\`, risk score \`${policy.blockRiskScore}\` |`,
    `| Raw approval retention | ${status(policy.storeRawForApproval)} for \`${policy.rawRetentionDays}\` day(s) |`,
    `| Governed destinations | ${joinInline(policy.governedDestinations || [])} |`,
    `| Browser content hosts | ${joinInline(contentHosts)} |`,
    `| Browser local control-plane permissions | ${joinInline(localControlPlaneHosts)} |`,
    `| Hard-stop entities | ${joinInline(policy.alwaysBlock || [])} |`,
    `| Detector inventory | ${detectors.length} detectors: ${joinInline(detectors)} |`,
    `| Semantic categories | ${joinInline(semanticCategories)} |`,
    `| Policy templates | ${joinInline(templateLabels)} |`,
  ].join('\n');
}

function generateSection() {
  const snapshot = loadSnapshot();
  const lines = [
    START,
    '## Current App Snapshot',
    '',
    'This section is generated from the app by `npm run docs:demo-guide`. Do not hand-edit between the markers. Run `npm run docs:demo-guide:check` before a client demo and in the review gate so the demo guides move with the product.',
    '',
    overviewTable(snapshot),
    '',
    '### Supported File Demo Types',
    '',
    supportedFileTypes(snapshot.processors),
    '',
    '### Demo And Verification Commands',
    '',
    commandTable(snapshot.pkg, DEMO_COMMANDS),
    '',
    '### Sensor And Evidence Paths',
    '',
    fileTable(SENSOR_AND_DOC_PATHS),
    END,
  ];
  return lines.join('\n');
}

function replaceGeneratedSection(relativePath, guide, section) {
  const startIndex = guide.indexOf(START);
  const endIndex = guide.indexOf(END);
  if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
    throw new Error(`Missing ${START} / ${END} markers in ${relativePath}`);
  }
  const fileEol = detectEol(guide);
  return `${guide.slice(0, startIndex)}${normalizeEol(section, fileEol)}${guide.slice(endIndex + END.length)}`;
}

function main() {
  const check = process.argv.includes('--check');
  const section = generateSection();
  const updates = [];
  const problems = [];

  for (const relativePath of GENERATED_DOCS) {
    const current = fs.readFileSync(docPath(relativePath), 'utf8');
    const next = replaceGeneratedSection(relativePath, current, section);
    updates.push({ relativePath, current, next });
    problems.push(...stalePathProblems(relativePath, next));
  }

  if (check) {
    for (const update of updates) {
      if (!sameContent(update.next, update.current)) {
        problems.push(`${update.relativePath}: generated current app snapshot is stale`);
      }
    }
    if (problems.length) {
      console.error('Demo guides check failed:');
      for (const problem of problems) console.error(`- ${problem}`);
      process.exit(1);
    }
    console.log('Demo guides are current.');
    return;
  }

  for (const update of updates) fs.writeFileSync(docPath(update.relativePath), update.next);
  if (problems.length) {
    console.error('Updated demo guides, but review these issue(s):');
    for (const problem of problems) console.error(`- ${problem}`);
    process.exit(1);
  }
  console.log('Updated demo guide current app snapshots.');
}

main();
