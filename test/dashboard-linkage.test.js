'use strict';
/** Dashboard frontend/backend linkage stays aligned for rendered controls and API contracts. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const AdmZip = require('adm-zip');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-dashboard-linkage-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-dashboard-linkage-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), process.env.REDACTWALL_POLICY_PATH);

const app = require('../server/app');
const db = require('../server/db');
const dataCrypto = require('../server/crypto');
const { listen } = require('./support/listen');

function readProjectFile(...parts) {
  return fs.readFileSync(path.join(__dirname, '..', ...parts), 'utf8');
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
  }
}

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port) {
  const res = await jsonFetch(port, '/api/login', {
    body: { user: 'admin', password: 'unit-pass' },
  });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  assert.match(cookie, /^redactwall_session=/);

  const csrfRes = await jsonFetch(port, '/api/csrf', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(csrfRes.status, 200);
  const { csrfToken } = await csrfRes.json();
  assert.match(csrfToken, /^[A-Za-z0-9_-]+$/);
  return { cookie, csrfToken };
}

async function createHeldPrompt(port, suffix, destination = 'chatgpt.com') {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: `Dashboard linkage QA member SSN 524-71-${suffix} before submission.`,
      user: `qa-${suffix}@example.test`,
      destination,
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'qa-org',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  assert.match(body.id, /^q_/);
  return body;
}

async function recordHeartbeat(port) {
  const res = await jsonFetch(port, '/api/v1/heartbeat', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      user: 'tech@example.test',
      orgId: 'qa-org',
      source: 'endpoint_agent',
      destination: 'endpoint-install',
      sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
      checks: [
        { id: 'endpoint_env_file', ok: true, detail: 'found' },
        { id: 'endpoint_file_flow_profiles', ok: true, detail: 'configured:2' },
        { id: 'endpoint_file_flow_profile_lending', ok: true, detail: 'configured directory' },
        { id: 'endpoint_file_flow_profile_call_center', ok: false, detail: 'missing directory' },
        { id: 'handoff_secret', ok: false, detail: 'missing 32-plus character handoff secret' },
      ],
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'sensor_heartbeat');
  return body;
}

async function createAllowedPrompt(port) {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Summarize the public product release checklist.',
      user: 'qa-allowed@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'qa-org',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'allow');
  return body;
}

function routePattern(route) {
  return route
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:id/g, "[^'\"`]+");
}

function assertRoute(serverSource, method, route) {
  assert.match(
    serverSource,
    new RegExp(`app\\.${method}\\(\\s*['"\`]${routePattern(route)}['"\`]`),
    `${method.toUpperCase()} ${route} is missing from server/app.js`,
  );
}

function assertHtmlId(source, id, fileLabel) {
  assert.match(source, new RegExp(`id=["']${id}["']`), `${fileLabel} is missing #${id}`);
}

function assertRenderedId(source, id) {
  assert.match(source, new RegExp(`id=["']${id}["']|#${id}\\b`), `dashboard.js does not render or reference #${id}`);
}

test('dashboard static controls, generated policy controls, and API routes stay wired', () => {
  const index = readProjectFile('server', 'public', 'index.html');
  const loginHtml = readProjectFile('server', 'public', 'login.html');
  const loginJs = readProjectFile('server', 'public', 'login.js');
  const dashboard = readProjectFile('server', 'public', 'dashboard.js');
  const siemPackageJs = readProjectFile('server', 'public', 'siem-package.js');
  const securityPackageJs = readProjectFile('server', 'public', 'security-package.js');
  const agenticMcpJs = readProjectFile('server', 'public', 'agentic-mcp.js');
  const threatGuardrailsJs = readProjectFile('server', 'public', 'ai-threat-guardrails.js');
  const operatorFlowJs = readProjectFile('server', 'public', 'operator-flow.js');
  const policyGuidesJs = readProjectFile('server', 'public', 'policy-guides.js');
  const policyImpactPreviewJs = readProjectFile('server', 'public', 'policy-impact-preview.js');
  const behaviorBaselinesJs = readProjectFile('server', 'public', 'behavior-baselines.js');
  const marketHardeningJs = readProjectFile('server', 'public', 'market-hardening.js');
  const competitiveReadinessJs = readProjectFile('server', 'public', 'competitive-readiness.js');
  const controlGraphJs = readProjectFile('server', 'public', 'control-graph.js');
  const leakPathMapJs = readProjectFile('server', 'public', 'leak-path-map.js');
  const coverageFileFlowJs = readProjectFile('server', 'public', 'coverage-file-flow.js');
  const decisionQualityJs = readProjectFile('server', 'public', 'decision-quality.js');
  const detectorFeedbackJs = readProjectFile('server', 'public', 'detector-feedback.js');
  const dashboardBundle = dashboard + siemPackageJs + securityPackageJs + agenticMcpJs + threatGuardrailsJs + operatorFlowJs + policyGuidesJs + policyImpactPreviewJs + behaviorBaselinesJs + marketHardeningJs + competitiveReadinessJs + controlGraphJs + leakPathMapJs + coverageFileFlowJs + decisionQualityJs + detectorFeedbackJs;
  const server = readProjectFile('server', 'app.js');

  assert.match(agenticMcpJs, /agentic-mcp-readiness/);
  assert.match(agenticMcpJs, /Connector Catalog/);
  assert.match(index, /\.agentic-mcp-readiness/);
  assert.match(index, /\.agentic-mcp-layout/);

  [
    'qBadge',
    'globalSearch',
    'logout',
    'banner',
    'stats',
    'queueCategoryFilter',
    'queueDestinationFilter',
    'queueList',
    'incidentDetail',
    'topEntities',
    'refreshQueue',
    'activityRows',
    'activityPager',
    'refreshCoverage',
    'coverageScore',
    'coveragePosture',
    'sensorMix',
    'fleetRows',
    'endpointAiToolRows',
    'endpointFileFlowRows',
    'governedRows',
    'shadowRows',
    'identityProvider',
    'identityTenant',
    'refreshIdentity',
    'identitySummary',
    'identityScimRows',
    'identityOidcRows',
    'identityEnvRows',
    'identityRoleRows',
    'identityValidation',
    'refreshLineage',
    'lineageSummary',
    'lineageUsers',
    'lineageUsersPager',
    'lineageDestinations',
    'lineageDestinationsPager',
    'lineageSensors',
    'lineageSensorsPager',
    'lineageCategories',
    'lineageCategoriesPager',
    'lineageChannels',
    'lineageChannelsPager',
    'lineageDecisions',
    'lineageDecisionsPager',
    'exportEvidence',
    'exportStatus',
    'integrity',
    'auditRows',
    'auditPager',
    'configurationStatus',
    'policyGuidedControls',
    'mcp_builder_pattern',
    'mcp_builder_decision',
    'addMcpToolRule',
    'route_builder_id',
    'route_builder_group',
    'addApprovalRoute',
    'policyBox',
    'liveTxt',
    'who',
    'hardeningMission',
    'marketHardeningSummary',
    'marketHardeningRows',
    'competitiveReadinessSummary',
    'competitiveReadinessRows',
    'operatorFlowSummary',
    'operatorFlowRows',
    'hardeningActionSummary',
    'hardeningActionQueue',
    'postureObjectiveSummary',
    'postureObjectives',
    'aiInventorySummary',
    'aiInventoryRows',
    'agenticMcpSummary',
    'agenticMcpRows',
    'threatGuardrailsSummary',
    'threatGuardrailsRows',
    'controlGraphSummary',
    'controlGraphMap',
    'leakMapSummary',
    'leakMapLens',
    'leakMapScenarios',
    'leakMapStage',
    'leakMapInspector',
    'hardeningReadinessSummary',
    'hardeningReadinessBoard',
    'postureSnapshotStatus',
    'sendPostureSnapshot',
    'siemPackageSummary',
    'siemPackageProfile',
    'downloadSiemPackage',
    'siemPackagePreview',
    'securityPackageSummary',
    'downloadSecurityPackage',
    'securityPackagePreview',
    'postureSegmentBar',
    'postureSegmentSummary',
    'postureSegmentSelect',
    'postureSegmentMatrix',
    'postureTrendSummary',
    'postureTrendChart',
    'controlOutcomeSummary',
    'controlOutcomeRows',
    'behaviorBaselineSummary',
    'behaviorBaselineRows',
    'decisionQualitySummary',
    'decisionQualityRows',
    'detectorFeedbackSummary',
    'detectorFeedbackRows',
  ].forEach((id) => assertHtmlId(index, id, 'index.html'));

  ['f', 'user', 'password', 'otp', 'oidc', 'err'].forEach((id) => {
    assertHtmlId(loginHtml, id, 'login.html');
    assert.match(loginJs, new RegExp(`\\b${id}\\b|['"]${id}['"]|#${id}\\b`), `login.js does not reference #${id}`);
  });

  [
    'discardPolicy',
    'testConfiguration',
    'policyImpactPreview',
    'savePolicy',
    'polSaved',
    'pol_sev',
    'pol_risk',
    'pol_retention',
    'pol_desktop_destination',
    'pol_block_unapproved_ai',
    'pol_response_scan_mode',
    'pol_governed_destinations',
    'pol_allowed_destinations',
    'pol_blocked_destinations',
    'pol_blocked_file_upload_destinations',
    'pol_blocked_browser_actions',
    'pol_mcp_allowed_tools',
    'pol_mcp_blocked_tools',
    'pol_mcp_approval_required_tools',
    'pol_required_sensors',
    'pol_desired_sensor_versions',
    'pol_approval_routing_rules',
    'scope_builder_id',
    'scope_builder_groups',
    'scope_builder_users',
    'scope_builder_destinations',
    'scope_builder_categories',
    'scope_builder_detectors',
    'scope_builder_mode',
    'scope_builder_severity',
    'scope_builder_risk',
    'scope_builder_reason',
    'addScopeRule',
    'exception_builder_id',
    'exception_builder_groups',
    'exception_builder_users',
    'exception_builder_destinations',
    'exception_builder_categories',
    'exception_builder_detectors',
    'exception_builder_hours',
    'exception_builder_owner_group',
    'exception_builder_reviewer_role',
    'exception_builder_review_hours',
    'exception_builder_reason',
    'addExceptionRule',
    'pol_policy_scopes',
    'pol_policy_exceptions',
    'runRetentionPurge',
  ].forEach((id) => assertRenderedId(dashboard, id));

  [
    ['get', '/api/login-options'],
    ['post', '/api/login'],
    ['get', '/api/csrf'],
    ['post', '/api/logout'],
    ['get', '/api/me'],
    ['get', '/api/queries'],
    ['get', '/api/queries/:id'],
    ['post', '/api/queries/:id/reveal'],
    ['post', '/api/queries/:id/approve'],
    ['post', '/api/queries/:id/deny'],
    ['get', '/api/stats'],
    ['get', '/api/metrics'],
    ['get', '/api/billing/seats'],
    ['get', '/api/preflight'],
    ['post', '/api/retention/purge'],
    ['get', '/api/coverage'],
    ['get', '/api/posture'],
    ['post', '/api/posture/actions'],
    ['post', '/api/posture/notify'],
    ['get', '/api/integrations/siem/package'],
    ['get', '/api/security/package'],
    ['post', '/api/v1/discovery'],
    ['get', '/api/lineage'],
    ['get', '/api/destinations/review'],
    ['post', '/api/destinations/review'],
    ['get', '/api/policy/templates'],
    ['put', '/api/policy/apply-template'],
    ['get', '/api/audit'],
    ['get', '/api/export/evidence'],
    ['get', '/api/policy'],
    ['post', '/api/policy/impact'],
    ['put', '/api/policy'],
  ].forEach(([method, route]) => assertRoute(server, method, route));

  [
    '/api/csrf',
    '/api/me',
    '/api/stats',
    '/api/billing/seats',
    '/api/queries?status=pending',
    '/api/queries?limit=200',
    '/api/destinations/review',
    '/api/coverage',
    '/api/posture?limit=5000',
    '/api/posture/actions',
    '/api/posture/notify',
    '/api/integrations/siem/package?profile=',
    '/api/security/package',
    '/api/identity/setup-guide',
    '/api/lineage?limit=1000',
    '/api/audit',
    '/api/export/evidence?queryLimit=1000&auditLimit=1000',
    '/api/policy',
    '/api/policy/impact?limit=1000',
    '/api/policy/templates',
    '/api/preflight',
    '/api/retention/purge',
    '/api/policy/apply-template',
    '/api/logout',
  ].forEach((endpoint) => {
    assert.ok(dashboardBundle.includes(endpoint), `dashboard browser scripts no longer call ${endpoint}`);
  });
  assert.ok(dashboard.includes('seatLimitValid'), 'dashboard.js no longer surfaces invalid SaaS seat-limit configuration');
  assert.ok(dashboard.includes('Seat config'), 'dashboard.js no longer labels invalid SaaS seat-limit configuration');
  assert.ok(dashboard.includes('hardening-runbook'), 'dashboard.js no longer renders hardening remediation runbooks');
  assert.ok(dashboard.includes('hardening-mission'), 'dashboard.js no longer renders the guided hardening mission');
  assert.ok(dashboard.includes('renderOperatorFlow'), 'dashboard.js no longer renders the operator flow');
  assert.ok(operatorFlowJs.includes('RedactWallOperatorFlow'), 'operator-flow.js no longer exports the operator flow renderer');
  assert.ok(operatorFlowJs.includes('operator-flow-card'), 'operator-flow.js no longer renders operator flow cards');
  assert.ok(operatorFlowJs.includes('data-flow-target'), 'operator-flow.js no longer exposes section jump targets');
  assert.ok(policyGuidesJs.includes('addApprovalRoute'), 'policy-guides.js no longer renders approval route builder behavior');
  assert.ok(policyGuidesJs.includes('addMcpToolRule'), 'policy-guides.js no longer renders MCP builder behavior');
  assert.ok(policyGuidesJs.includes('pol_approval_routing_rules'), 'policy-guides.js no longer writes approval routing rules');
  assert.ok(policyGuidesJs.includes('pol_mcp_approval_required_tools'), 'policy-guides.js no longer writes MCP approval tools');
  assert.ok(policyImpactPreviewJs.includes('RedactWallPolicyImpact'), 'policy-impact-preview.js no longer exports the policy impact renderer');
  assert.ok(index.includes('<script src="/policy-impact-preview.js" defer></script>'), 'index.html no longer loads the policy impact renderer');
  assert.ok(behaviorBaselinesJs.includes('RedactWallBehaviorBaselines'), 'behavior-baselines.js no longer exports the behavior baseline renderer');
  assert.ok(behaviorBaselinesJs.includes('behavior-baseline-row'), 'behavior-baselines.js no longer renders behavior baseline rows');
  assert.ok(dashboard.includes('renderBehaviorBaselines'), 'dashboard.js no longer renders behavior baselines');
  assert.ok(operatorFlowJs.includes('Behavior baselines'), 'operator-flow.js no longer includes behavior baseline triage');
  assert.ok(dashboard.includes('action-row'), 'dashboard.js no longer renders the hardening action queue');
  assert.ok(dashboard.includes('ai-inventory-row'), 'dashboard.js no longer renders AI app inventory rows');
  assert.ok(dashboard.includes('ai-inventory-risk'), 'dashboard.js no longer renders AI inventory risk tiers');
  assert.ok(dashboard.includes('renderAgenticMcp'), 'dashboard.js no longer renders Agentic MCP control posture');
  assert.ok(agenticMcpJs.includes('agentic-mcp-row'), 'agentic-mcp.js no longer renders MCP agent/tool rows');
  assert.ok(agenticMcpJs.includes('RedactWallAgenticMcp'), 'agentic-mcp.js no longer exports the MCP renderer');
  assert.ok(agenticMcpJs.includes('connectorRegistry'), 'agentic-mcp.js no longer renders connector registry posture');
  assert.ok(agenticMcpJs.includes('Connectors'), 'agentic-mcp.js no longer exposes connector profiles');
  assert.ok(dashboard.includes('renderThreatGuardrails'), 'dashboard.js no longer renders AI threat guardrails');
  assert.ok(threatGuardrailsJs.includes('threat-guardrail-row'), 'ai-threat-guardrails.js no longer renders threat guardrail rows');
  assert.ok(threatGuardrailsJs.includes('RedactWallThreatGuardrails'), 'ai-threat-guardrails.js no longer exports the threat renderer');
  assert.ok(dashboard.includes('renderControlGraph'), 'dashboard.js no longer renders the AI control graph');
  assert.ok(controlGraphJs.includes('RedactWallControlGraph'), 'control-graph.js no longer exports the AI control graph renderer');
  assert.ok(controlGraphJs.includes('control-graph-node'), 'control-graph.js no longer renders control graph nodes');
  assert.ok(controlGraphJs.includes('control-graph-edge'), 'control-graph.js no longer renders control graph links');
  assert.ok(dashboard.includes('renderLeakPathMap'), 'dashboard.js no longer renders the AI leak path map');
  assert.ok(leakPathMapJs.includes('RedactWallLeakPathMap'), 'leak-path-map.js no longer exports the leak path map renderer');
  assert.ok(leakPathMapJs.includes('leakMap'), 'leak-path-map.js no longer reads the posture leakMap contract');
  assert.ok(leakPathMapJs.includes('leak-node'), 'leak-path-map.js no longer renders leak map nodes');
  assert.ok(leakPathMapJs.includes('data-leak-edge'), 'leak-path-map.js no longer renders clickable leak edges');
  assert.ok(leakPathMapJs.includes('data-leak-filter'), 'leak-path-map.js no longer exposes exposure filters');
  assert.ok(leakPathMapJs.includes('data-leak-category'), 'leak-path-map.js no longer exposes data-type filters');
  assert.ok(leakPathMapJs.includes('prefers-reduced-motion'), 'leak-path-map.js no longer respects reduced motion');
  assert.ok(leakPathMapJs.includes('leak-wall'), 'leak-path-map.js no longer draws the RedactWall barrier');
  assert.ok(dashboard.includes('MCP Tool Governance'), 'dashboard.js no longer exposes MCP tool governance policy');
  assert.ok(dashboard.includes('mission-proof-ledger'), 'dashboard.js no longer renders the mission proof ledger');
  assert.ok(dashboard.includes('hardening-proof-ledger'), 'dashboard.js no longer renders hardening proof rows');
  assert.ok(dashboard.includes('data-copy-command'), 'dashboard.js no longer exposes copyable hardening commands');
  assert.ok(dashboard.includes('data-action-workflow'), 'dashboard.js no longer exposes action workflow controls');
  assert.ok(dashboard.includes('workflowPatchFor'), 'dashboard.js no longer posts action workflow updates');
  assert.ok(dashboard.includes('renderPostureSegments'), 'dashboard.js no longer renders posture segment comparisons');
  assert.ok(dashboard.includes('data-posture-segment'), 'dashboard.js no longer exposes posture segment filters');
  assert.ok(dashboard.includes('renderSiemPackage'), 'dashboard.js no longer renders SIEM package previews');
  assert.ok(dashboard.includes('downloadSiemPackage'), 'dashboard.js no longer downloads SIEM packages');
  assert.ok(siemPackageJs.includes('siem-profile-row'), 'siem-package.js no longer renders SIEM profile rows');
  assert.ok(dashboard.includes('renderSecurityPackage'), 'dashboard.js no longer renders security trust package previews');
  assert.ok(dashboard.includes('downloadSecurityPackage'), 'dashboard.js no longer downloads security trust packages');
  assert.ok(securityPackageJs.includes('RedactWallSecurityPackage'), 'security-package.js no longer exports the trust package renderer');
  assert.ok(securityPackageJs.includes('trust-control-row'), 'security-package.js no longer renders trust control rows');
  assert.ok(index.includes('trust-package-board'), 'index.html no longer styles the security trust package board');
  assert.ok(index.includes('<script src="/security-package.js" defer></script>'), 'index.html no longer loads the security package renderer');
  assert.ok(competitiveReadinessJs.includes('competitiveReadiness'), 'competitive-readiness.js no longer renders competitive readiness');
  assert.ok(competitiveReadinessJs.includes('competitive-readiness-board'), 'competitive-readiness.js no longer renders readiness cards');
  assert.ok(competitiveReadinessJs.includes('/api/posture?limit=5000'), 'competitive-readiness.js no longer fetches posture readiness');
  assert.ok(marketHardeningJs.includes('competitiveFocus'), 'market-hardening.js no longer reads the competitive focus contract');
  assert.ok(marketHardeningJs.includes('market-hardening-card'), 'market-hardening.js no longer renders the market hardening cards');
  assert.ok(marketHardeningJs.includes('/api/posture?limit=5000'), 'market-hardening.js no longer fetches posture focus');
  assert.ok(coverageFileFlowJs.includes('endpointFileFlowProfiles'), 'coverage-file-flow.js no longer reads endpoint file-flow profiles');
  assert.ok(coverageFileFlowJs.includes('Local path: not reported'), 'coverage-file-flow.js no longer labels path redaction');
  assert.ok(decisionQualityJs.includes('decisionQuality'), 'decision-quality.js no longer reads decision quality posture');
  assert.ok(decisionQualityJs.includes('RedactWallDecisionQuality'), 'decision-quality.js no longer exports the decision quality renderer');
  assert.ok(detectorFeedbackJs.includes('/api/detector-feedback/report'), 'detector-feedback.js no longer fetches detector feedback');
  assert.ok(detectorFeedbackJs.includes('RedactWallDetectorFeedback'), 'detector-feedback.js no longer exports the feedback renderer');
  assert.ok(detectorFeedbackJs.includes('Held-out Eval'), 'detector-feedback.js no longer renders held-out eval quality proof');
  assert.ok(detectorFeedbackJs.includes('quality'), 'detector-feedback.js no longer reads detector quality proof');
  assert.ok(index.includes('ai-inventory-grid'), 'index.html no longer styles the AI app inventory grid');
  assert.ok(index.includes('ai-inventory-risk'), 'index.html no longer styles AI inventory risk tiers');
  assert.ok(index.includes('agentic-mcp-board'), 'index.html no longer styles Agentic MCP control');
  assert.ok(index.includes('agentic-mcp-policy-row'), 'index.html no longer styles MCP policy rows');
  assert.ok(index.includes('AI Threat Guardrails'), 'index.html no longer exposes the AI threat guardrails section');
  assert.ok(index.includes('segment-lens'), 'index.html no longer styles the posture segment lens');
  assert.ok(index.includes('control-graph-lanes'), 'index.html no longer styles AI control graph lanes');
  assert.ok(index.includes('control-graph-edge'), 'index.html no longer styles AI control graph edges');
  assert.ok(index.includes('leak-map-stage'), 'index.html no longer styles the leak path map stage');
  assert.ok(index.includes('leak-wall'), 'index.html no longer styles the RedactWall barrier');
  assert.ok(index.includes('leak-edge'), 'index.html no longer styles leak map edges');
  assert.ok(index.includes('leak-inspector-grid'), 'index.html no longer styles the leak map inspector');
  assert.ok(index.includes('<script src="/leak-path-map.js" defer></script>'), 'index.html no longer loads the leak path map renderer');
  assert.ok(index.includes('action-queue'), 'index.html no longer styles the hardening action queue');
  assert.ok(index.includes('action-workflow-pill'), 'index.html no longer styles action workflow state');
  assert.ok(index.includes('hardening-step'), 'index.html no longer styles hardening remediation steps');
  assert.ok(index.includes('proof-row'), 'index.html no longer styles proof ledger rows');
  assert.ok(index.includes('mission-lane'), 'index.html no longer styles hardening mission lanes');
  assert.ok(index.includes('market-hardening-board'), 'index.html no longer styles market hardening lanes');
  assert.ok(index.includes('operator-flow-board'), 'index.html no longer styles the operator flow board');
  assert.ok(index.includes('siem-package-board'), 'index.html no longer styles SIEM package board');
  assert.ok(index.includes('<script src="/siem-package.js" defer></script>'), 'index.html no longer loads the SIEM package renderer');
  assert.ok(index.includes('<script src="/agentic-mcp.js" defer></script>'), 'index.html no longer loads the Agentic MCP renderer');
  assert.ok(index.includes('<script src="/ai-threat-guardrails.js" defer></script>'), 'index.html no longer loads the threat guardrails renderer');
  assert.ok(index.includes('<script src="/operator-flow.js" defer></script>'), 'index.html no longer loads the operator flow renderer');
  assert.ok(index.includes('<script src="/policy-guides.js" defer></script>'), 'index.html no longer loads the policy guide renderer');
  assert.ok(index.includes('<script src="/behavior-baselines.js" defer></script>'), 'index.html no longer loads the behavior baseline renderer');
  assert.ok(index.includes('<script src="/market-hardening.js" defer></script>'), 'index.html no longer loads the market hardening renderer');
  assert.ok(index.includes('<script src="/competitive-readiness.js" defer></script>'), 'index.html no longer loads the competitive readiness renderer');
  assert.ok(index.includes('<script src="/control-graph.js" defer></script>'), 'index.html no longer loads the control graph renderer');
  assert.ok(index.includes('<script src="/coverage-file-flow.js" defer></script>'), 'index.html no longer loads the endpoint file-flow renderer');
  assert.ok(index.includes('<script src="/decision-quality.js" defer></script>'), 'index.html no longer loads the decision quality renderer');
  assert.ok(index.includes('<script src="/detector-feedback.js" defer></script>'), 'index.html no longer loads the detector feedback renderer');
});

test('dashboard-backed API actions accept the payloads built by forms and buttons', async () => withServer(async (port) => {
  const loginOptions = await jsonFetch(port, '/api/login-options', { method: 'GET' });
  assert.strictEqual(loginOptions.status, 200);

  const { cookie, csrfToken } = await login(port);
  const headers = { cookie, 'x-csrf-token': csrfToken };

  const reveal = await createHeldPrompt(port, '9043', 'chatgpt.com');
  const approve = await createHeldPrompt(port, '9044', 'claude.ai');
  const deny = await createHeldPrompt(port, '9045', 'gemini.google.com');
  await createAllowedPrompt(port);
  await recordHeartbeat(port);

  for (const apiPath of [
    '/api/me',
    '/api/stats',
    '/api/metrics',
    '/api/billing/seats',
    '/api/preflight',
    '/api/coverage',
    '/api/posture?limit=5000',
    '/api/detector-feedback/report?queryLimit=1000&feedbackLimit=1000',
    '/api/integrations/siem/package?profile=all',
    '/api/lineage?limit=1000',
    '/api/identity/setup-guide?provider=okta&tenantId=acme.okta.com',
    '/api/audit',
    '/api/policy',
    '/api/policy/templates',
  ]) {
    const res = await jsonFetch(port, apiPath, { method: 'GET', headers: { cookie } });
    assert.strictEqual(res.status, 200, `${apiPath} should be reachable from dashboard session`);
  }
  const coverageBody = await (await jsonFetch(port, '/api/coverage', { method: 'GET', headers: { cookie } })).json();
  assert.deepStrictEqual(coverageBody.endpointFileFlowProfiles.map((profile) => [profile.id, profile.state, profile.user]), [
    ['call_center', 'attention', 'tech@example.test'],
    ['lending', 'covered', 'tech@example.test'],
  ]);
  assert.strictEqual(JSON.stringify(coverageBody.endpointFileFlowProfiles).includes('C:\\'), false);

  const feedbackBody = await (await jsonFetch(port, '/api/detector-feedback/report?queryLimit=1000&feedbackLimit=1000', { method: 'GET', headers: { cookie } })).json();
  assert.ok(feedbackBody.quality && feedbackBody.quality.summary && feedbackBody.quality.summary.floorsMet);
  assert.strictEqual(JSON.stringify(feedbackBody.quality).includes('Leadership has decided'), false);

  const queue = await jsonFetch(port, '/api/queries?status=pending', { method: 'GET', headers: { cookie } });
  assert.strictEqual(queue.status, 200);
  const queued = await queue.json();
  assert.ok(queued.length >= 3);
  const revealQueueRow = queued.find((row) => row.id === reveal.id);
  assert.ok(revealQueueRow);
  assert.strictEqual(revealQueueRow.rawRetained, true);
  assert.strictEqual(revealQueueRow._rawPrompt, undefined);

  const detail = await jsonFetch(port, `/api/queries/${reveal.id}`, { method: 'GET', headers: { cookie } });
  assert.strictEqual(detail.status, 200);
  const detailBody = await detail.json();
  assert.strictEqual(detailBody.rawRetained, true);
  assert.strictEqual(detailBody._rawPrompt, undefined);

  const revealRes = await jsonFetch(port, `/api/queries/${reveal.id}/reveal`, {
    headers,
    body: { password: 'unit-pass' },
  });
  assert.strictEqual(revealRes.status, 200);
  const revealBody = await revealRes.json();
  assert.match(revealBody.rawPrompt, /524-71-9043/);
  assert.strictEqual(revealBody.rawRetained, true);
  assert.strictEqual(revealBody.rawDiffersFromRedacted, true);

  const retainedPreview = 'Debug this deploy script. Here is the AWS key [SECRET_KEY] and secret we use.';
  const retainedPreviewRow = db.createQuery({
    status: 'pending',
    user: 'redacted-api@example.test',
    destination: 'claude.ai',
    source: 'api',
    channel: 'submit',
    redactedPrompt: retainedPreview,
    findings: [{ type: 'SECRET_KEY', severity: 4, score: 0.95, masked: 'AK***EF' }],
    categories: [],
    entityCounts: { SECRET_KEY: 1 },
    riskScore: 30,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    reasons: ['client-redacted test fixture'],
    _rawPrompt: dataCrypto.seal(retainedPreview),
  });
  assert.ok(retainedPreviewRow._rawPrompt);
  const retainedPreviewRevealRes = await jsonFetch(port, `/api/queries/${retainedPreviewRow.id}/reveal`, {
    headers,
    body: { password: 'unit-pass' },
  });
  assert.strictEqual(retainedPreviewRevealRes.status, 200);
  const retainedPreviewReveal = await retainedPreviewRevealRes.json();
  assert.strictEqual(retainedPreviewReveal.rawPrompt, retainedPreview);
  assert.strictEqual(retainedPreviewReveal.rawRetained, true);
  assert.strictEqual(retainedPreviewReveal.rawDiffersFromRedacted, false);

  const approveRes = await jsonFetch(port, `/api/queries/${approve.id}/approve`, {
    headers,
    body: { note: 'dashboard linkage approve', password: 'unit-pass' },
  });
  assert.strictEqual(approveRes.status, 200);
  assert.strictEqual((await approveRes.json()).status, 'approved');

  const denyRes = await jsonFetch(port, `/api/queries/${deny.id}/deny`, {
    headers,
    body: { note: 'dashboard linkage deny' },
  });
  assert.strictEqual(denyRes.status, 200);
  assert.strictEqual((await denyRes.json()).status, 'denied');

  const policyRes = await jsonFetch(port, '/api/policy', { method: 'GET', headers: { cookie } });
  assert.strictEqual(policyRes.status, 200);
  const p = await policyRes.json();
  const savePayload = {
    enforcementMode: p.enforcementMode,
    blockMinSeverity: p.blockMinSeverity,
    blockRiskScore: p.blockRiskScore,
    rawRetentionDays: p.rawRetentionDays ?? 30,
    desktopCollectorDestination: p.desktopCollectorDestination || 'Desktop AI',
    requiredSensors: p.requiredSensors || ['browser_extension', 'endpoint_agent', 'mcp_guard'],
    desiredSensorVersions: p.desiredSensorVersions || {},
    approvalRoutingRules: p.approvalRoutingRules || [],
    policyScopes: p.policyScopes || [],
    policyExceptions: p.policyExceptions || [],
    governedDestinations: p.governedDestinations || [],
    allowedDestinations: p.allowedDestinations || [],
    blockedDestinations: p.blockedDestinations || [],
    blockedFileUploadDestinations: p.blockedFileUploadDestinations || [],
    blockedBrowserActions: p.blockedBrowserActions || [],
    blockUnapprovedAiDestinations: p.blockUnapprovedAiDestinations !== false,
    responseScanMode: p.responseScanMode || 'flag',
  };
  const savePolicy = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers,
    body: savePayload,
  });
  assert.strictEqual(savePolicy.status, 200);

  const impact = await jsonFetch(port, '/api/policy/impact?limit=1000', {
    headers,
    body: { ...savePayload, blockedDestinations: ['chatgpt.com'] },
  });
  assert.strictEqual(impact.status, 200);
  const impactBody = await impact.json();
  assert.ok(impactBody.summary.sampleSize >= 3);
  assert.ok(impactBody.summary.newlyBlocked >= 1);
  assert.strictEqual(impactBody.privacy.promptBodiesIncluded, false);
  assert.strictEqual(JSON.stringify(impactBody).includes('524-71-9043'), false);

  const templates = await jsonFetch(port, '/api/policy/templates', { method: 'GET', headers: { cookie } });
  assert.strictEqual(templates.status, 200);
  const templateList = await templates.json();
  assert.ok(templateList.some((item) => item.id === 'baseline'));
  const applyTemplate = await jsonFetch(port, '/api/policy/apply-template', {
    method: 'PUT',
    headers,
    body: { id: 'baseline' },
  });
  assert.strictEqual(applyTemplate.status, 200);

  const destinationReview = await jsonFetch(port, '/api/destinations/review', {
    headers,
    body: { destination: 'example-ai.test', decision: 'block', reason: 'dashboard_linkage_test' },
  });
  assert.strictEqual(destinationReview.status, 200);
  assert.strictEqual((await destinationReview.json()).decision, 'block');

  const purge = await jsonFetch(port, '/api/retention/purge', { headers });
  assert.strictEqual(purge.status, 200);
  assert.strictEqual(typeof (await purge.json()).purged, 'number');

  const actionUpdate = await jsonFetch(port, '/api/posture/actions', {
    headers,
    body: {
      id: 'mission:ai_gateway_enforcement:gateway_required_sensor',
      status: 'assigned',
      owner: 'security_admin',
      note: 'dashboard_linkage',
    },
  });
  assert.strictEqual(actionUpdate.status, 200);
  const actionUpdateBody = await actionUpdate.json();
  assert.strictEqual(actionUpdateBody.action.status, 'assigned');
  assert.ok(actionUpdateBody.audit && actionUpdateBody.audit.hash);

  const updatedPosture = await jsonFetch(port, '/api/posture?limit=5000', { method: 'GET', headers: { cookie } });
  assert.strictEqual(updatedPosture.status, 200);
  const updatedPostureBody = await updatedPosture.json();
  const assignedAction = updatedPostureBody.actionQueue.find((item) => item.id === 'mission:ai_gateway_enforcement:gateway_required_sensor');
  assert.ok(assignedAction);
  assert.strictEqual(assignedAction.workflowStatus, 'assigned');
  assert.strictEqual(assignedAction.workflowOwner, 'security_admin');
  assert.ok(updatedPostureBody.segments && updatedPostureBody.segments.matrix.some((item) => item.id === 'org:qa-org'));
  assert.ok(updatedPostureBody.competitiveReadiness && updatedPostureBody.competitiveReadiness.summary);
  assert.ok(updatedPostureBody.behaviorBaselines && updatedPostureBody.behaviorBaselines.summary);
  assert.strictEqual(updatedPostureBody.behaviorBaselines.privacy, 'metadata only; prompt bodies excluded');
  assert.ok(updatedPostureBody.behaviorBaselines.dimensions.length >= 1);
  assert.ok(updatedPostureBody.behaviorBaselines.playbook.every((item, index) => item.priority === index + 1));
  assert.ok(updatedPostureBody.competitiveReadiness.matrix.some((item) => item.id === 'desktop_file_flow'));
  assert.ok(updatedPostureBody.competitiveReadiness.matrix.some((item) => item.id === 'behavior_anomaly_baselines'));
  assert.ok(updatedPostureBody.competitiveReadiness.matrix.some((item) => item.id === 'soc_compliance_handoff'));
  assert.strictEqual(JSON.stringify(updatedPostureBody.competitiveReadiness).includes('524-71-9043'), false);
  assert.strictEqual(JSON.stringify(updatedPostureBody.behaviorBaselines).includes('524-71-9043'), false);
  assert.ok(updatedPostureBody.competitiveFocus && updatedPostureBody.competitiveFocus.summary);
  assert.ok(updatedPostureBody.competitiveFocus.lanes.some((item) => item.id === 'continuous_shadow_ai_discovery'));
  assert.ok(updatedPostureBody.competitiveFocus.lanes.some((item) => item.id === 'mcp_saas_connector_coverage'));
  assert.ok(updatedPostureBody.competitiveFocus.lanes.some((item) => item.id === 'detection_quality_proof'));
  assert.ok(updatedPostureBody.agenticMcp && updatedPostureBody.agenticMcp.connectorRegistry);
  assert.strictEqual(updatedPostureBody.agenticMcp.connectorRegistry.summary.shipped >= 6, true);
  assert.strictEqual(updatedPostureBody.agenticMcp.connectorRegistry.summary.profileTemplates, 0);
  assert.strictEqual(updatedPostureBody.agenticMcp.connectorRegistry.summary.nextConnector, 'none');
  assert.ok(updatedPostureBody.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'microsoft365' && item.stage === 'shipped'));
  assert.ok(updatedPostureBody.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'google_drive' && item.stage === 'shipped'));
  assert.ok(updatedPostureBody.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'slack' && item.stage === 'shipped'));
  assert.ok(updatedPostureBody.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'teams' && item.stage === 'shipped'));
  assert.ok(updatedPostureBody.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'jira_confluence' && item.stage === 'shipped'));
  assert.ok(updatedPostureBody.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'database_readonly' && item.stage === 'shipped'));
  assert.strictEqual(JSON.stringify(updatedPostureBody.competitiveFocus).includes('524-71-9043'), false);
  assert.ok(updatedPostureBody.decisionQuality && updatedPostureBody.decisionQuality.summary);
  assert.ok(updatedPostureBody.decisionQuality.cards.some((item) => item.id === 'approval_sla'));
  assert.strictEqual(JSON.stringify(updatedPostureBody.decisionQuality).includes('524-71-9043'), false);
  assert.ok(updatedPostureBody.detectionQuality && updatedPostureBody.detectionQuality.summary.floorsMet);
  assert.strictEqual(JSON.stringify(updatedPostureBody.detectionQuality).includes('Leadership has decided'), false);

  const scimUser = db.saveScimUser({ userName: 'qa-9043@example.test', active: true });
  db.saveScimGroup({
    displayName: 'RedactWall Lending',
    members: [{ value: scimUser.id, display: scimUser.userName }],
  });
  const segmentedPosture = await jsonFetch(port, '/api/posture?limit=5000&segment=group:redactwall-lending', { method: 'GET', headers: { cookie } });
  assert.strictEqual(segmentedPosture.status, 200);
  const segmentedPostureBody = await segmentedPosture.json();
  assert.strictEqual(segmentedPostureBody.segments.active.label, 'RedactWall Lending');
  assert.strictEqual(segmentedPostureBody.segments.summary.selectedId, 'group:redactwall-lending');
  assert.strictEqual(segmentedPostureBody.summary.events, 1);
  assert.strictEqual(segmentedPostureBody.summary.pending, 1);
  assert.strictEqual(JSON.stringify(segmentedPostureBody).includes('524-71-9043'), false);

  const evidence = await jsonFetch(port, '/api/export/evidence?queryLimit=1000&auditLimit=1000', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(evidence.status, 200);
  const evidenceBody = await evidence.json();
  assert.ok(Array.isArray(evidenceBody.queries));
  assert.ok(evidenceBody.auditIntegrity && evidenceBody.auditIntegrity.ok);
  assert.ok(evidenceBody.posture && evidenceBody.posture.summary);
  assert.ok(evidenceBody.posture.hardening && Array.isArray(evidenceBody.posture.hardening.areas));
  assert.ok(evidenceBody.posture.behaviorBaselines && Array.isArray(evidenceBody.posture.behaviorBaselines.dimensions));
  assert.ok(evidenceBody.posture.competitiveReadiness && Array.isArray(evidenceBody.posture.competitiveReadiness.matrix));
  assert.ok(evidenceBody.posture.competitiveFocus && Array.isArray(evidenceBody.posture.competitiveFocus.lanes));
  assert.ok(evidenceBody.posture.decisionQuality && Array.isArray(evidenceBody.posture.decisionQuality.cards));
  assert.ok(evidenceBody.posture.detectionQuality && evidenceBody.posture.detectionQuality.summary.floorsMet);
  assert.ok(evidenceBody.posture.actionQueue.some((item) => item.workflowStatus === 'assigned'));
  assert.strictEqual(JSON.stringify(evidenceBody.posture).includes('524-71-9043'), false);

  const postureNotify = await jsonFetch(port, '/api/posture/notify', {
    headers,
  });
  assert.strictEqual(postureNotify.status, 202);
  const postureNotifyBody = await postureNotify.json();
  assert.strictEqual(postureNotifyBody.sent, false);
  assert.strictEqual(postureNotifyBody.reason, 'disabled');
  assert.ok(postureNotifyBody.posture && postureNotifyBody.posture.state);

  const siemPackageRes = await jsonFetch(port, '/api/integrations/siem/package?profile=splunk', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(siemPackageRes.status, 200);
  const siemPackageBody = await siemPackageRes.json();
  assert.strictEqual(siemPackageBody.profiles[0].id, 'splunk');
  assert.strictEqual(JSON.stringify(siemPackageBody).includes('524-71-9043'), false);
  assert.ok(siemPackageBody.profiles[0].savedSearches.some((item) => item.spl.includes('redactwall:security')));

  const siemDownload = await jsonFetch(port, '/api/integrations/siem/package?profile=splunk&download=1', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(siemDownload.status, 200);
  assert.match(siemDownload.headers.get('content-disposition') || '', /redactwall-siem-splunk-package\.json/);

  const siemZip = await jsonFetch(port, '/api/integrations/siem/package?profile=splunk&format=zip', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(siemZip.status, 200);
  assert.match(siemZip.headers.get('content-type') || '', /application\/zip/);
  assert.match(siemZip.headers.get('content-disposition') || '', /redactwall-siem-splunk-package\.zip/);
  const zip = new AdmZip(Buffer.from(await siemZip.arrayBuffer()));
  const entries = zip.getEntries().map((entry) => entry.entryName);
  assert.ok(entries.includes('manifest.json'));
  assert.ok(entries.includes('profiles/splunk/splunk-saved-searches.json'));
  assert.strictEqual(zip.readAsText('manifest.json').includes('524-71-9043'), false);

  const badSiemPackage = await jsonFetch(port, '/api/integrations/siem/package?profile=member-524-71-9043', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(badSiemPackage.status, 400);
  const badSiemBody = await badSiemPackage.json();
  assert.strictEqual(badSiemBody.error, 'unsupported_profile');
  assert.strictEqual(JSON.stringify(badSiemBody).includes('524-71-9043'), false);

  const securityPackageRes = await jsonFetch(port, '/api/security/package', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(securityPackageRes.status, 200);
  const securityPackageBody = await securityPackageRes.json();
  assert.strictEqual(securityPackageBody.schemaVersion, 'redactwall.security-trust-package.v1');
  assert.ok(securityPackageBody.summary.controlCoverage.total >= 8);
  assert.ok(securityPackageBody.sbom.summary.components >= 1);
  assert.ok(securityPackageBody.controls.some((item) => item.id === 'audit_chain'));
  assert.strictEqual(JSON.stringify(securityPackageBody).includes('524-71-9043'), false);

  const securityPackageJsonDownload = await jsonFetch(port, '/api/security/package?download=1', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(securityPackageJsonDownload.status, 200);
  assert.match(securityPackageJsonDownload.headers.get('content-disposition') || '', /redactwall-security-trust-package\.json/);

  const securityPackageZip = await jsonFetch(port, '/api/security/package?format=zip', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(securityPackageZip.status, 200);
  assert.match(securityPackageZip.headers.get('content-type') || '', /application\/zip/);
  assert.match(securityPackageZip.headers.get('content-disposition') || '', /redactwall-security-trust-package\.zip/);
  const securityZip = new AdmZip(Buffer.from(await securityPackageZip.arrayBuffer()));
  const securityEntries = securityZip.getEntries().map((entry) => entry.entryName);
  assert.ok(securityEntries.includes('manifest.json'));
  assert.ok(securityEntries.includes('security-trust-package.json'));
  assert.ok(securityEntries.includes('sbom/cyclonedx.json'));
  assert.strictEqual(securityZip.readAsText('security-trust-package.json').includes('524-71-9043'), false);

  const logout = await jsonFetch(port, '/api/logout', { headers });
  assert.strictEqual(logout.status, 200);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.REDACTWALL_POLICY_PATH); } catch {}
});
