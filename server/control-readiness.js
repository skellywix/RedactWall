'use strict';
/**
 * Competitive hardening readiness.
 *
 * This module is intentionally pure and privacy-preserving: it scores deployment
 * posture from policy, coverage, environment shape, and sanitized event metadata.
 * It never emits prompt bodies, token vaults, secrets, or raw finding values.
 */
const coverage = require('./coverage');
const notifiers = require('./notifiers');
const { outboundHttpsUrl } = require('./url-policy');

const BLOCKED_STATUSES = new Set([
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'action_blocked',
  'injection_blocked',
  'file_blocked_unscanned',
  'ocr_required',
  'response_flagged',
  'response_blocked',
  'seat_limit_blocked',
]);
const REDACTED_STATUSES = new Set(['redacted', 'response_redacted']);
const ACTION_LABELS = {
  paste: 'Paste',
  drop: 'Drop',
  copy: 'Copy',
  download: 'Download',
};
const PLAYBOOK_STATUSES = new Set(['done', 'next', 'todo']);
const PROOF_STATUSES = new Set(['verified', 'attention', 'missing']);

function n(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function bound(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(n(value))));
}

function safeText(value, fallback = 'unknown', limit = 160) {
  const text = String(value || '').trim();
  return (text || fallback).slice(0, limit);
}

function unique(items = [], limit = 8) {
  return [...new Set(items.map((item) => safeText(item, '', 160)).filter(Boolean))].slice(0, limit);
}

function playbookStep(step = {}) {
  const status = PLAYBOOK_STATUSES.has(String(step.status || '')) ? String(step.status) : 'todo';
  return {
    id: safeText(step.id, 'step', 80),
    label: safeText(step.label, 'Remediation step', 120),
    status,
    detail: safeText(step.detail, 'Follow the operator runbook', 240),
    command: safeText(step.command, '', 240),
    validation: safeText(step.validation, '', 240),
    targetTab: safeText(step.targetTab, 'coverage', 40),
  };
}

function proofItem(item = {}) {
  const status = PROOF_STATUSES.has(String(item.status || '')) ? String(item.status) : 'missing';
  return {
    id: safeText(item.id, 'proof', 80),
    label: safeText(item.label, 'Evidence item', 120),
    status,
    detail: safeText(item.detail, 'Awaiting sanitized evidence', 240),
    evidenceAt: item.evidenceAt ? safeText(item.evidenceAt, null, 80) : null,
    source: safeText(item.source, 'control', 80),
    action: safeText(item.action, 'Review', 80),
    targetTab: safeText(item.targetTab, 'coverage', 40),
  };
}

function proofItems(items = []) {
  return (Array.isArray(items) ? items : []).slice(0, 8).map(proofItem);
}

function proofSummary(proofs = []) {
  const rows = Array.isArray(proofs) ? proofs : [];
  const verified = rows.filter((item) => item.status === 'verified').length;
  const attention = rows.filter((item) => item.status === 'attention').length;
  const missing = rows.filter((item) => item.status === 'missing').length;
  const total = rows.length;
  return {
    verified,
    attention,
    missing,
    total,
    percent: total ? bound((verified / total) * 100) : 0,
  };
}

function remediationSteps(steps = []) {
  let nextAssigned = false;
  return steps.slice(0, 6).map((step) => {
    const done = !!(step && step.done);
    const status = done ? 'done' : nextAssigned ? 'todo' : 'next';
    if (!done) nextAssigned = true;
    return playbookStep({ ...step, status });
  });
}

function add(points, condition) {
  return condition ? points : 0;
}

function stateFor(score, hasCriticalGap = false) {
  if (score >= 90) return 'ready';
  if (hasCriticalGap && score < 35) return 'blocked';
  return 'attention';
}

function statusFor(state) {
  return state === 'ready' ? 'online' : state === 'blocked' ? 'error' : 'warning';
}

function readinessArea({
  id,
  label,
  description,
  score,
  evidence,
  gaps,
  action,
  targetTab,
  owner,
    source,
    location,
    critical,
    playbook,
    proofs,
  }) {
  const bounded = bound(score);
  const state = stateFor(bounded, critical);
  const safeProofs = proofItems(proofs);
  return {
    id,
    label,
    description: safeText(description, 'readiness check', 240),
    score: bounded,
    state,
    status: statusFor(state),
    evidence: unique(evidence, 8),
    gaps: unique(gaps, 8),
    action: safeText(action, 'Open', 80),
    targetTab: safeText(targetTab, 'policy', 40),
    owner: safeText(owner, 'security', 80),
    source: safeText(source, 'policy', 80),
    location: safeText(location, 'RedactWall control plane', 120),
    proofs: safeProofs,
    proofLedger: proofSummary(safeProofs),
    playbook: remediationSteps(playbook),
  };
}

function proofLedgerForAreas(areas = []) {
  const proofs = [];
  for (const area of areas) {
    for (const proof of area.proofs || []) {
      proofs.push({
        ...proof,
        areaId: safeText(area.id, 'area', 80),
        areaLabel: safeText(area.label, 'Readiness area', 120),
        areaState: safeText(area.state, 'attention', 40),
        areaScore: bound(area.score),
      });
    }
  }
  const summary = proofSummary(proofs);
  const current = proofs.find((proof) => proof.status !== 'verified') || null;
  return {
    ...summary,
    current: current ? {
      id: `${current.areaId}:${safeText(current.id, 'proof', 80)}`,
      areaId: current.areaId,
      areaLabel: current.areaLabel,
      areaState: current.areaState,
      areaScore: current.areaScore,
      label: safeText(current.label, 'Evidence item', 120),
      status: safeText(current.status, 'missing', 40),
      detail: safeText(current.detail, 'Awaiting sanitized evidence', 240),
      evidenceAt: current.evidenceAt || null,
      source: safeText(current.source, 'control', 80),
      action: safeText(current.action, 'Review', 80),
      targetTab: safeText(current.targetTab, 'coverage', 40),
    } : null,
  };
}

function missionCurrentStep(step, area) {
  return {
    id: `${safeText(area.id, 'area', 80)}:${safeText(step.id, 'step', 80)}`,
    areaId: safeText(area.id, 'area', 80),
    areaLabel: safeText(area.label, 'Readiness area', 120),
    areaState: safeText(area.state, 'attention', 40),
    areaScore: bound(area.score),
    label: safeText(step.label, 'Remediation step', 120),
    status: safeText(step.status, 'todo', 40),
    detail: safeText(step.detail, 'Follow the operator runbook', 240),
    command: safeText(step.command, '', 240),
    validation: safeText(step.validation, '', 240),
    targetTab: safeText(step.targetTab || area.targetTab, 'coverage', 40),
    owner: safeText(area.owner, 'security', 80),
    source: safeText(area.source, 'control', 80),
  };
}

function missionLane(area) {
  const steps = Array.isArray(area && area.playbook) ? area.playbook : [];
  const done = steps.filter((step) => step.status === 'done').length;
  const next = steps.find((step) => step.status === 'next') || steps.find((step) => step.status === 'todo') || null;
  return {
    id: safeText(area && area.id, 'area', 80),
    label: safeText(area && area.label, 'Readiness area', 120),
    state: safeText(area && area.state, 'attention', 40),
    status: safeText(area && area.status, 'warning', 40),
    score: bound(area && area.score),
    owner: safeText(area && area.owner, 'security', 80),
    source: safeText(area && area.source, 'control', 80),
    targetTab: safeText(area && area.targetTab, 'coverage', 40),
    done,
    total: steps.length,
    nextStep: next ? safeText(next.label, 'Remediation step', 120) : 'Complete',
  };
}

function missionForAreas(areas = []) {
  const lanes = areas.map(missionLane);
  const steps = [];
  for (const area of areas) {
    for (const step of area.playbook || []) steps.push(missionCurrentStep(step, area));
  }
  const validSteps = steps;
  const done = validSteps.filter((step) => step.status === 'done').length;
  const open = validSteps.filter((step) => step.status !== 'done');
  const current = open.find((step) => step.status === 'next') || open[0] || null;
  const percent = validSteps.length ? bound((done / validSteps.length) * 100) : 0;
  return {
    title: 'Hardening mission',
    state: areas.every((area) => area.state === 'ready') ? 'ready'
      : areas.some((area) => area.state === 'blocked') ? 'blocked'
        : 'attention',
    status: statusFor(areas.every((area) => area.state === 'ready') ? 'ready'
      : areas.some((area) => area.state === 'blocked') ? 'blocked'
        : 'attention'),
    progress: {
      done,
      total: validSteps.length,
      open: open.length,
      percent,
    },
    current,
    proofLedger: proofLedgerForAreas(areas),
    lanes,
    summary: {
      readyAreas: areas.filter((area) => area.state === 'ready').length,
      blockedAreas: areas.filter((area) => area.state === 'blocked').length,
      attentionAreas: areas.filter((area) => area.state === 'attention').length,
      totalAreas: areas.length,
    },
  };
}

function latestTimestamp(rows = []) {
  let latest = null;
  for (const row of Array.isArray(rows) ? rows : []) {
    const value = row && row.createdAt ? String(row.createdAt) : '';
    if (value && (!latest || value > latest)) latest = value;
  }
  return latest || null;
}

function sensorBySource(report, source) {
  return ((report && report.sensors) || []).find((sensor) => sensor.source === source) || null;
}

function requiredSources(report, policy = {}) {
  const fromReport = ((report && report.sensors) || []).filter((sensor) => sensor.required).map((sensor) => sensor.source);
  const fromPolicy = Array.isArray(policy.requiredSensors) ? policy.requiredSensors : [];
  return new Set([...fromReport, ...fromPolicy].map((source) => safeText(source, '', 80)).filter(Boolean));
}

function statusControlled(row) {
  return BLOCKED_STATUSES.has(String(row && row.status || '')) || REDACTED_STATUSES.has(String(row && row.status || ''));
}

function gatewayReadiness({ rows, policy, coverageReport }) {
  const required = requiredSources(coverageReport, policy).has('proxy');
  const proxySensor = sensorBySource(coverageReport, 'proxy');
  const proxyRows = rows.filter((row) => row && row.source === 'proxy');
  const observed = n(proxySensor && proxySensor.events) || proxyRows.length;
  const controlled = proxyRows.filter(statusControlled).length;
  const awaitedRelease = proxyRows.some((row) => ['pending', 'approved', 'denied'].includes(String(row.status || '')));
  const monitorOnly = proxyRows.some((row) => row.status === 'proxy_observed') && !controlled && !awaitedRelease;
  const defaultDeny = policy.blockUnapprovedAiDestinations !== false;
  const responseScan = ['flag', 'redact', 'block'].includes(String(policy.responseScanMode || ''));
  const governed = Array.isArray(policy.governedDestinations) && policy.governedDestinations.length > 0;
  const blockedDestinations = Array.isArray(policy.blockedDestinations) && policy.blockedDestinations.length > 0;
  const proxyLastSeen = latestTimestamp(proxyRows) || (proxySensor && proxySensor.lastSeen) || null;
  const score = add(18, required)
    + add(22, observed)
    + add(25, controlled || awaitedRelease)
    + add(15, defaultDeny)
    + add(10, responseScan)
    + add(10, governed || blockedDestinations);
  const evidence = [
    required && 'Proxy is listed as a required sensor',
    observed && `${observed} proxy events observed`,
    controlled && `${controlled} proxy events controlled`,
    awaitedRelease && 'Proxy path has approval/release evidence',
    defaultDeny && 'Default-deny for unapproved AI destinations is active',
    responseScan && `AI response scanning is ${safeText(policy.responseScanMode, 'configured', 30)}`,
    governed && `${policy.governedDestinations.length} governed AI destinations configured`,
    'Provider runtime adapters ship for OpenAI-compatible, Anthropic, Gemini, and Bedrock',
  ];
  const gaps = [
    !required && 'Add proxy to required sensors for production gateway proof',
    !observed && 'Connect the production AI gateway or ICAP bridge',
    monitorOnly && 'Proxy lab is monitor-only; add block/hold enforcement evidence',
    observed && !controlled && !awaitedRelease && 'Record a proxy block, redact, or approval hold',
    !defaultDeny && 'Enable default-deny for unapproved AI destinations',
    !responseScan && 'Enable response scanning for prompt and model-output parity',
    !governed && !blockedDestinations && 'Seed governed or blocked AI destinations',
  ];
  const playbook = [
    {
      id: 'gateway_provider_runtime_coverage',
      label: 'Verify provider runtime coverage',
      done: true,
      detail: 'Keep direct Bedrock Runtime, Gemini native, Anthropic Messages, and OpenAI-compatible paths covered by the enforced gateway.',
      command: 'node --test test/ai-llm-gateway.test.js',
      validation: 'Gateway tests pass for Bedrock Converse, InvokeModel, Gemini, Anthropic, and OpenAI-compatible shapes.',
      targetTab: 'monitor',
    },
    {
      id: 'gateway_required_sensor',
      label: 'Require the proxy sensor',
      done: required,
      detail: 'Make the production AI gateway a required control so coverage cannot read as healthy without it.',
      command: 'Configuration > Required sensors: browser_extension, endpoint_agent, mcp_guard, proxy',
      validation: 'Open Coverage and verify Network proxy is required.',
      targetTab: 'policy',
    },
    {
      id: 'gateway_observe_traffic',
      label: 'Prove AI gateway traffic',
      done: !!observed,
      detail: 'Run a sanitized proxy smoke so RedactWall can see app-to-AI traffic before it leaves the network path.',
      command: 'npm run proxy:lab -- --sample --redactwall http://127.0.0.1:4000',
      validation: 'Command Center shows proxy events and Coverage marks Network proxy observed.',
      targetTab: 'coverage',
    },
    {
      id: 'gateway_inline_enforcement',
      label: 'Record block, redact, or hold evidence',
      done: !!(controlled || awaitedRelease),
      detail: 'Move beyond monitor-only visibility: deploy the fail-closed ICAP bridge (npm run icap:bridge) or the AI gateway on the network path so inline block/hold decisions produce evidence.',
      command: 'npm run icap:bridge',
      validation: 'A proxy event lands as pending, denied, destination_blocked, redacted, or approved.',
      targetTab: 'lineage',
    },
    {
      id: 'gateway_default_deny_response_scan',
      label: 'Enable default-deny and response scan',
      done: !!(defaultDeny && responseScan),
      detail: 'Keep unapproved AI destinations blocked by default and scan model responses with prompt-side parity.',
      command: 'Configuration > enable blockUnapprovedAiDestinations and responseScanMode',
      validation: 'Unapproved AI smoke records destination_blocked and response scanning is flag, redact, or block.',
      targetTab: 'policy',
    },
    {
      id: 'gateway_destination_catalog',
      label: 'Seed governed or blocked AI destinations',
      done: !!(governed || blockedDestinations),
      detail: 'Declare the sanctioned AI destination catalog and known shadow AI blocklist for examiner-ready scope.',
      command: 'Configuration > governedDestinations and blockedDestinations',
      validation: 'Coverage shows governed or blocked AI destinations configured.',
      targetTab: 'policy',
    },
  ];
  const proofs = [
    {
      id: 'gateway_provider_runtime_coverage',
      label: 'Provider runtime adapters covered',
      status: 'verified',
      detail: 'OpenAI-compatible, Anthropic Messages, Gemini native, and Bedrock Runtime paths are covered by gateway tests.',
      evidenceAt: null,
      source: 'gateway',
      action: 'Review gateway docs',
      targetTab: 'monitor',
    },
    {
      id: 'gateway_required_sensor',
      label: 'Proxy required in deployment baseline',
      status: required ? 'verified' : 'missing',
      detail: required ? 'Network proxy must report before coverage can read healthy.' : 'Production gateway is optional in the current required-sensor baseline.',
      evidenceAt: proxyLastSeen,
      source: 'policy',
      action: 'Require proxy sensor',
      targetTab: 'policy',
    },
    {
      id: 'gateway_traffic_observed',
      label: 'AI gateway traffic observed',
      status: observed ? 'verified' : 'missing',
      detail: observed ? `${observed} proxy event${observed === 1 ? '' : 's'} observed from sanitized metadata.` : 'No proxy events have reached the control plane.',
      evidenceAt: proxyLastSeen,
      source: 'proxy',
      action: 'Run proxy smoke',
      targetTab: 'coverage',
    },
    {
      id: 'gateway_inline_control',
      label: 'Inline block, redact, or hold proven',
      status: controlled || awaitedRelease ? 'verified' : monitorOnly ? 'attention' : 'missing',
      detail: controlled || awaitedRelease
        ? `${controlled || 0} controlled proxy event${controlled === 1 ? '' : 's'} plus approval/release evidence.`
        : monitorOnly ? 'Proxy visibility is present, but enforcement is monitor-only.' : 'No proxy block, redact, or hold evidence exists yet.',
      evidenceAt: proxyLastSeen,
      source: 'proxy',
      action: 'Prove inline enforcement',
      targetTab: 'lineage',
    },
    {
      id: 'gateway_default_deny_response',
      label: 'Default-deny and response scan active',
      status: defaultDeny && responseScan ? 'verified' : defaultDeny || responseScan ? 'attention' : 'missing',
      detail: defaultDeny && responseScan
        ? `Default-deny is active and response scanning is ${safeText(policy.responseScanMode, 'configured', 30)}.`
        : 'Prompt-side controls need default-deny plus response scanning parity.',
      evidenceAt: null,
      source: 'policy',
      action: 'Enable gateway policy parity',
      targetTab: 'policy',
    },
    {
      id: 'gateway_destination_scope',
      label: 'Sanctioned or blocked AI destination scope set',
      status: governed || blockedDestinations ? 'verified' : 'missing',
      detail: governed || blockedDestinations
        ? `${(policy.governedDestinations || []).length} governed and ${(policy.blockedDestinations || []).length} blocked AI destination${((policy.governedDestinations || []).length + (policy.blockedDestinations || []).length) === 1 ? '' : 's'} configured.`
        : 'No governed or blocked AI destination catalog is configured.',
      evidenceAt: null,
      source: 'policy',
      action: 'Seed AI destination catalog',
      targetTab: 'policy',
    },
  ];
  return readinessArea({
    id: 'ai_gateway_enforcement',
    label: 'AI Gateway Enforcement',
    description: 'Production proxy path proves AI traffic is intercepted, policy-gated, and release-aware.',
    score,
    evidence,
    gaps,
    action: gaps.length ? 'Open coverage' : 'Inspect lineage',
    targetTab: gaps.length ? 'coverage' : 'lineage',
    owner: 'network security',
    source: 'proxy',
    location: 'Proxy, ICAP bridge, and AI destination controls',
    critical: !observed,
    playbook,
    proofs,
  });
}

function browserActionsConfigured(policy = {}) {
  const actions = new Set();
  for (const rule of policy.blockedBrowserActions || []) {
    if (rule && rule.enabled !== false && rule.action) actions.add(String(rule.action));
  }
  return [...actions];
}

function desktopReadiness({ policy, coverageReport }) {
  const required = requiredSources(coverageReport, policy).has('endpoint_agent');
  const endpoint = sensorBySource(coverageReport, 'endpoint_agent');
  const observed = n(endpoint && endpoint.events);
  const installHealth = endpoint && endpoint.installHealth;
  const failedChecks = Array.isArray(installHealth && installHealth.failedChecks) ? installHealth.failedChecks : [];
  const handoffGap = failedChecks.some((id) => /handoff|upload|clipboard/i.test(id));
  const desktopCollector = (coverageReport && coverageReport.desktopCollector) || {};
  const protectedUploads = n(desktopCollector.events);
  const fileUploadControls = Array.isArray(policy.blockedFileUploadDestinations) && policy.blockedFileUploadDestinations.length > 0;
  const actions = browserActionsConfigured(policy);
  const endpointInventories = n(coverageReport && coverageReport.totals && coverageReport.totals.endpointAiInventoryReports);
  const unapprovedTools = n(coverageReport && coverageReport.totals && coverageReport.totals.endpointAiToolUnapproved);
  const endpointLastSeen = (endpoint && endpoint.lastSeen) || null;
  const desktopLastSeen = desktopCollector.lastSeen || endpointLastSeen;
  let score = add(15, required)
    + add(15, observed)
    + add(25, protectedUploads)
    + add(15, fileUploadControls)
    + add(10, actions.length)
    + add(15, endpointInventories)
    + add(5, installHealth && installHealth.state !== 'attention');
  if (handoffGap) score -= 12;
  if (unapprovedTools) score -= Math.min(15, unapprovedTools * 5);
  const evidence = [
    required && 'Endpoint agent is listed as a required sensor',
    observed && `${observed} endpoint events observed`,
    protectedUploads && `${protectedUploads} protected desktop upload events`,
    fileUploadControls && `${policy.blockedFileUploadDestinations.length} file-upload destinations configured`,
    actions.length && `Browser action controls: ${actions.map((action) => ACTION_LABELS[action] || action).join(', ')}`,
    endpointInventories && `${endpointInventories} endpoint AI inventory heartbeat${endpointInventories === 1 ? '' : 's'}`,
    installHealth && installHealth.state !== 'attention' && 'Latest endpoint install-health checks are passing',
  ];
  const gaps = [
    !required && 'Keep endpoint agent in required sensors',
    !observed && 'Roll out endpoint agent heartbeat and file-flow telemetry',
    !protectedUploads && 'Capture protected desktop upload evidence from native handoff',
    !fileUploadControls && 'Configure blocked file-upload destinations',
    !actions.length && 'Add paste/drop/copy/download browser action controls',
    !endpointInventories && 'Enable endpoint AI tool inventory heartbeat',
    handoffGap && 'Resolve endpoint handoff, upload, or clipboard install checks',
    unapprovedTools && `Review ${unapprovedTools} unapproved local AI tool${unapprovedTools === 1 ? '' : 's'}`,
  ];
  const playbook = [
    {
      id: 'desktop_required_sensor',
      label: 'Require the endpoint agent',
      done: required,
      detail: 'Keep desktop and file-flow protection in the required deployment baseline.',
      command: 'Configuration > Required sensors: endpoint_agent',
      validation: 'Coverage marks Endpoint agent as required.',
      targetTab: 'policy',
    },
    {
      id: 'desktop_install_health',
      label: 'Prove endpoint heartbeat and install health',
      done: !!(observed && installHealth && installHealth.state !== 'attention' && !handoffGap),
      detail: 'Verify the Windows collector can report health without exposing file contents.',
      command: 'npm run endpoint:check -- --emit-heartbeat --require-desktop-collector --json',
      validation: 'Coverage shows Endpoint agent online with install checks passing.',
      targetTab: 'coverage',
    },
    {
      id: 'desktop_protected_upload',
      label: 'Capture protected upload evidence',
      done: !!protectedUploads,
      detail: 'Exercise the native handoff path for dragged files and desktop AI uploads.',
      command: 'npm run desktop:collect -- --file <path> --destination "Desktop AI" --wait --json',
      validation: 'Coverage > Desktop collector shows protected upload events.',
      targetTab: 'coverage',
    },
    {
      id: 'desktop_action_controls',
      label: 'Enforce file and clipboard controls',
      done: !!(fileUploadControls && actions.length),
      detail: 'Apply the same policy to browser upload, paste, drop, copy, and download actions.',
      command: 'Configuration > blocked file upload destinations and blocked browser actions',
      validation: 'Command Center control outcomes include File upload or Browser action.',
      targetTab: 'policy',
    },
    {
      id: 'desktop_ai_inventory',
      label: 'Review endpoint AI tool inventory',
      done: !!(endpointInventories && !unapprovedTools),
      detail: 'Track approved and unapproved local AI tools so shadow desktop usage is visible.',
      command: 'npm run endpoint:check -- --emit-heartbeat --json',
      validation: 'Coverage > Endpoint AI Tools shows approved tools only.',
      targetTab: 'coverage',
    },
  ];
  const endpointHealthProven = !!(observed && installHealth && installHealth.state !== 'attention' && !handoffGap);
  const proofs = [
    {
      id: 'desktop_required_sensor',
      label: 'Endpoint agent required in deployment baseline',
      status: required ? 'verified' : 'missing',
      detail: required ? 'Endpoint agent must report before coverage can read healthy.' : 'Endpoint agent is optional in the current required-sensor baseline.',
      evidenceAt: endpointLastSeen,
      source: 'policy',
      action: 'Require endpoint agent',
      targetTab: 'policy',
    },
    {
      id: 'desktop_endpoint_health',
      label: 'Endpoint heartbeat and install health proven',
      status: endpointHealthProven ? 'verified' : observed || installHealth ? 'attention' : 'missing',
      detail: endpointHealthProven
        ? 'Latest endpoint heartbeat includes passing install-health checks.'
        : observed || installHealth ? `${failedChecks.length} install-health check${failedChecks.length === 1 ? '' : 's'} need attention.` : 'No endpoint heartbeat or install-health evidence exists yet.',
      evidenceAt: endpointLastSeen,
      source: 'endpoint_agent',
      action: 'Run endpoint health check',
      targetTab: 'coverage',
    },
    {
      id: 'desktop_protected_upload',
      label: 'Protected desktop upload captured',
      status: protectedUploads ? 'verified' : 'missing',
      detail: protectedUploads ? `${protectedUploads} protected desktop upload event${protectedUploads === 1 ? '' : 's'} recorded.` : 'No native handoff or desktop AI upload evidence exists yet.',
      evidenceAt: desktopLastSeen,
      source: 'endpoint_agent',
      action: 'Capture protected upload',
      targetTab: 'coverage',
    },
    {
      id: 'desktop_action_controls',
      label: 'File and clipboard action controls configured',
      status: fileUploadControls && actions.length ? 'verified' : fileUploadControls || actions.length ? 'attention' : 'missing',
      detail: fileUploadControls && actions.length
        ? `File-upload controls plus ${actions.length} browser action control${actions.length === 1 ? '' : 's'} configured.`
        : 'Configure both file-upload destinations and paste/drop/copy/download controls.',
      evidenceAt: null,
      source: 'policy',
      action: 'Configure action controls',
      targetTab: 'policy',
    },
    {
      id: 'desktop_ai_inventory',
      label: 'Endpoint AI tool inventory clean',
      status: endpointInventories && !unapprovedTools ? 'verified' : endpointInventories ? 'attention' : 'missing',
      detail: endpointInventories
        ? `${endpointInventories} inventory heartbeat${endpointInventories === 1 ? '' : 's'} with ${unapprovedTools} unapproved local AI tool${unapprovedTools === 1 ? '' : 's'}.`
        : 'Endpoint AI tool inventory heartbeat has not reported yet.',
      evidenceAt: endpointLastSeen,
      source: 'endpoint_agent',
      action: 'Review endpoint AI inventory',
      targetTab: 'coverage',
    },
  ];
  return readinessArea({
    id: 'desktop_file_flow',
    label: 'Desktop File-Flow Coverage',
    description: 'Desktop AI apps, file uploads, clipboard actions, and local AI tools are governed from the same policy.',
    score,
    evidence,
    gaps,
    action: gaps.length ? 'Open coverage' : 'Inspect policy',
    targetTab: gaps.length ? 'coverage' : 'policy',
    owner: 'endpoint engineering',
    source: 'endpoint_agent',
    location: 'Endpoint agent, protected upload, clipboard, and AI tool inventory',
    critical: !observed,
    playbook,
    proofs,
  });
}

function assetDiscoveryReadiness({ policy, coverageReport }) {
  const totals = (coverageReport && coverageReport.totals) || {};
  const governedTotal = n(totals.governedDestinations);
  const governedActive = n(totals.governedActive);
  const shadowEvents = n(totals.shadowEvents);
  const unresolvedShadow = n(totals.unresolvedShadowDestinations);
  const endpointInventories = n(totals.endpointAiInventoryReports);
  const unapprovedTools = n(totals.endpointAiToolUnapproved);
  const defaultDeny = policy.blockUnapprovedAiDestinations !== false;
  const browser = sensorBySource(coverageReport, 'browser_extension');
  const endpoint = sensorBySource(coverageReport, 'endpoint_agent');
  const proxy = sensorBySource(coverageReport, 'proxy');
  const discoverySources = [browser, endpoint, proxy].filter((sensor) => n(sensor && sensor.events)).length;
  const catalogRows = [
    ...((coverageReport && coverageReport.governedDestinations) || []),
    ...((coverageReport && coverageReport.shadowDestinations) || []),
    ...((coverageReport && coverageReport.ungovernedDestinations) || []),
  ];
  // Only real row timestamps count as evidence. Falling back to generatedAt
  // (now) or a synthetic 1970 stamp fabricated proof dates that changed every
  // request; latestTimestamp already returns null when nothing real is present.
  const catalogLastSeen = latestTimestamp(catalogRows.map((row) => ({ createdAt: row.lastSeen || '' })));
  let score = add(20, governedTotal)
    + add(15, governedActive)
    + add(15, discoverySources >= 2 || shadowEvents)
    + add(20, !unresolvedShadow)
    + add(15, endpointInventories)
    + add(10, defaultDeny)
    + add(5, catalogRows.length);
  if (unapprovedTools) score -= Math.min(15, unapprovedTools * 5);
  const evidence = [
    governedTotal && `${governedTotal} governed AI destination${governedTotal === 1 ? '' : 's'} cataloged`,
    governedActive && `${governedActive} governed AI destination${governedActive === 1 ? '' : 's'} observed`,
    discoverySources && `${discoverySources} AI discovery source${discoverySources === 1 ? '' : 's'} active`,
    shadowEvents && `${shadowEvents} shadow AI sighting${shadowEvents === 1 ? '' : 's'} captured`,
    !unresolvedShadow && 'No unresolved shadow AI destinations',
    endpointInventories && `${endpointInventories} endpoint AI inventory heartbeat${endpointInventories === 1 ? '' : 's'}`,
    defaultDeny && 'Default-deny protects unknown AI destinations',
  ];
  const gaps = [
    !governedTotal && 'Seed the sanctioned AI app risk catalog',
    !governedActive && 'Generate live usage against at least one governed AI app',
    !(discoverySources >= 2 || shadowEvents) && 'Collect AI discovery from browser, endpoint, or proxy paths',
    unresolvedShadow && `Review ${unresolvedShadow} unresolved shadow AI destination${unresolvedShadow === 1 ? '' : 's'}`,
    !endpointInventories && 'Enable endpoint AI tool inventory heartbeat',
    unapprovedTools && `Resolve ${unapprovedTools} unapproved local AI tool${unapprovedTools === 1 ? '' : 's'}`,
    !defaultDeny && 'Enable default-deny for unknown AI destinations',
  ];
  const playbook = [
    {
      id: 'asset_catalog_seeded',
      label: 'Seed AI app risk catalog',
      done: !!governedTotal,
      detail: 'Maintain a sanctioned AI destination registry so usage can be compared against a known risk catalog.',
      command: 'Configuration > governedDestinations',
      validation: 'AI App Inventory shows sanctioned apps with risk tiers.',
      targetTab: 'policy',
    },
    {
      id: 'asset_discovery_sources',
      label: 'Activate discovery sources',
      done: !!(discoverySources >= 2 || shadowEvents),
      detail: 'Use browser, endpoint, and gateway telemetry to discover AI usage across human and local-tool paths.',
      command: 'Run browser, endpoint, and proxy smoke events',
      validation: 'AI App Inventory shows observed sanctioned, shadow, or endpoint AI assets.',
      targetTab: 'coverage',
    },
    {
      id: 'asset_shadow_review',
      label: 'Review shadow AI destinations',
      done: unresolvedShadow === 0,
      detail: 'Classify every discovered shadow AI destination as governed, allowed, or blocked.',
      command: 'AI App Inventory > Review destination',
      validation: 'Coverage reports zero unresolved shadow AI destinations.',
      targetTab: 'coverage',
    },
    {
      id: 'asset_endpoint_inventory',
      label: 'Inventory local AI tools',
      done: !!(endpointInventories && !unapprovedTools),
      detail: 'Detect approved and unapproved desktop AI apps and code assistants from endpoint heartbeats.',
      command: 'npm run endpoint:check -- --emit-heartbeat --json',
      validation: 'Endpoint AI Tools shows no unapproved local AI tools.',
      targetTab: 'coverage',
    },
    {
      id: 'asset_default_deny',
      label: 'Default-deny unknown AI apps',
      done: !!defaultDeny,
      detail: 'Keep newly discovered AI destinations blocked until reviewed.',
      command: 'Configuration > Block unapproved AI destinations',
      validation: 'Unreviewed AI destination smoke records destination_blocked.',
      targetTab: 'policy',
    },
  ];
  const proofs = [
    {
      id: 'asset_catalog_seeded',
      label: 'Sanctioned AI app catalog exists',
      status: governedTotal ? 'verified' : 'missing',
      detail: governedTotal ? `${governedTotal} governed AI destination${governedTotal === 1 ? '' : 's'} configured.` : 'No governed AI destinations are configured.',
      evidenceAt: catalogLastSeen,
      source: 'policy',
      action: 'Seed catalog',
      targetTab: 'policy',
    },
    {
      id: 'asset_discovery_active',
      label: 'AI discovery sources active',
      status: discoverySources >= 2 || shadowEvents ? 'verified' : discoverySources ? 'attention' : 'missing',
      detail: discoverySources >= 2 || shadowEvents ? `${discoverySources} discovery source${discoverySources === 1 ? '' : 's'} active.` : 'AI discovery coverage needs browser, endpoint, or proxy evidence.',
      evidenceAt: catalogLastSeen,
      source: 'coverage',
      action: 'Run discovery smoke',
      targetTab: 'coverage',
    },
    {
      id: 'asset_shadow_review',
      label: 'Shadow AI review queue clear',
      status: unresolvedShadow ? 'attention' : 'verified',
      detail: unresolvedShadow ? `${unresolvedShadow} shadow AI destination${unresolvedShadow === 1 ? '' : 's'} await review.` : 'Every discovered shadow AI destination is reviewed or absent.',
      evidenceAt: catalogLastSeen,
      source: 'coverage',
      action: 'Review shadow AI',
      targetTab: 'coverage',
    },
    {
      id: 'asset_endpoint_inventory',
      label: 'Endpoint AI inventory clean',
      status: endpointInventories && !unapprovedTools ? 'verified' : endpointInventories ? 'attention' : 'missing',
      detail: endpointInventories ? `${endpointInventories} endpoint inventory heartbeat${endpointInventories === 1 ? '' : 's'} with ${unapprovedTools} unapproved tool${unapprovedTools === 1 ? '' : 's'}.` : 'No endpoint AI inventory heartbeat has reported.',
      evidenceAt: endpoint && endpoint.lastSeen,
      source: 'endpoint_agent',
      action: 'Review local AI tools',
      targetTab: 'coverage',
    },
    {
      id: 'asset_default_deny',
      label: 'Unknown AI apps default-denied',
      status: defaultDeny ? 'verified' : 'missing',
      detail: defaultDeny ? 'Default-deny is active for unreviewed AI destinations.' : 'Unknown AI destinations are not default-denied.',
      evidenceAt: null,
      source: 'policy',
      action: 'Enable default-deny',
      targetTab: 'policy',
    },
  ];
  return readinessArea({
    id: 'ai_asset_discovery',
    label: 'AI Asset Discovery',
    description: 'Continuously inventory AI apps, local tools, and shadow AI with risk-aware review state.',
    score,
    evidence,
    gaps,
    action: gaps.length ? 'Open inventory' : 'Inspect inventory',
    targetTab: gaps.length ? 'coverage' : 'monitor',
    owner: 'security operations',
    source: 'coverage',
    location: 'Browser, endpoint, proxy, and AI app risk catalog',
    critical: !governedTotal && !discoverySources,
    playbook,
    proofs,
  });
}

function mcpAgentReadiness({ rows, policy, coverageReport }) {
  const required = requiredSources(coverageReport, policy).has('mcp_guard');
  const mcp = sensorBySource(coverageReport, 'mcp_guard');
  const observed = n(mcp && mcp.events);
  const mcpRows = rows.filter((row) => row && row.source === 'mcp_guard');
  const docRows = mcpRows.filter((row) => row.channel === 'mcp_doc' || row.channel === 'ai_response');
  const toolPolicyRows = mcpRows.filter((row) => row.channel === 'mcp_tool' || row.status === 'action_blocked');
  const controlled = mcpRows.filter(statusControlled).length;
  const redactedDocs = docRows.filter((row) => REDACTED_STATUSES.has(String(row.status || '')) || statusControlled(row)).length;
  const toolRegistry = [
    ...((policy && policy.mcpAllowedTools) || []),
    ...((policy && policy.mcpBlockedTools) || []),
    ...((policy && policy.mcpApprovalRequiredTools) || []),
  ];
  const scopedMcpPolicy = ((policy && policy.policyScopes) || []).some((rule) => rule && rule.enabled !== false && Array.isArray(rule.sources) && rule.sources.includes('mcp_guard'));
  const responseScan = ['flag', 'redact', 'block'].includes(String(policy.responseScanMode || ''));
  const currentVersion = !mcp || !mcp.events || mcp.versionHealth === 'current';
  const mcpLastSeen = latestTimestamp(mcpRows) || (mcp && mcp.lastSeen) || null;
  let score = add(18, required)
    + add(20, observed)
    + add(22, controlled || redactedDocs)
    + add(18, toolRegistry.length || scopedMcpPolicy)
    + add(12, responseScan)
    + add(10, currentVersion);
  if (!observed) score = Math.min(score, 30);
  const evidence = [
    required && 'MCP guard is listed as a required sensor',
    observed && `${observed} MCP event${observed === 1 ? '' : 's'} observed`,
    controlled && `${controlled} MCP event${controlled === 1 ? '' : 's'} controlled`,
    redactedDocs && `${redactedDocs} MCP document or response path${redactedDocs === 1 ? '' : 's'} redacted or blocked`,
    toolRegistry.length && `${toolRegistry.length} MCP tool registry rule${toolRegistry.length === 1 ? '' : 's'} configured`,
    scopedMcpPolicy && 'Scoped policy exists for MCP guard traffic',
    responseScan && `AI response scanning is ${safeText(policy.responseScanMode, 'configured', 30)}`,
  ];
  const gaps = [
    !required && 'Add MCP guard to required sensors',
    !observed && 'Run MCP guard through a document/tool call smoke',
    observed && !controlled && !redactedDocs && 'Prove MCP redaction, block, or response-scan control',
    !toolRegistry.length && !scopedMcpPolicy && 'Define MCP allowed, blocked, or approval-required tool policy',
    !responseScan && 'Enable response scanning for agent outputs',
    !currentVersion && 'Update MCP guard to the desired sensor version',
  ];
  const playbook = [
    {
      id: 'mcp_required_sensor',
      label: 'Require MCP guard',
      done: required,
      detail: 'Make MCP guard a required deployment sensor for agent and connector coverage.',
      command: 'Configuration > Required sensors: mcp_guard',
      validation: 'Coverage marks MCP guard as required.',
      targetTab: 'policy',
    },
    {
      id: 'mcp_tool_smoke',
      label: 'Run MCP tool smoke',
      done: !!observed,
      detail: 'Exercise a connector/tool result so the guard proves visibility before model access.',
      command: 'node sensors/mcp-guard/guard.js',
      validation: 'AI Command Center records MCP guard activity without raw document text.',
      targetTab: 'coverage',
    },
    {
      id: 'mcp_redaction_control',
      label: 'Prove MCP redaction or block',
      done: !!(controlled || redactedDocs),
      detail: 'Show sensitive tool output is redacted or withheld before reaching the model.',
      command: 'node --test test/mcp-guard.test.js',
      validation: 'MCP guard tests prove blocked tool execution and pre-model redaction.',
      targetTab: 'lineage',
    },
    {
      id: 'mcp_tool_registry',
      label: 'Define MCP tool registry',
      done: !!(toolRegistry.length || scopedMcpPolicy),
      detail: 'Declare allowed, blocked, or approval-required tools so agents cannot call arbitrary connectors.',
      command: 'Configuration > MCP Tool Governance',
      validation: 'Disallowed MCP tool wrapper returns BLOCKED before handler execution.',
      targetTab: 'policy',
    },
    {
      id: 'mcp_response_scan',
      label: 'Scan agent outputs',
      done: !!responseScan,
      detail: 'Keep agent responses under the same response scanning controls as human AI chat.',
      command: 'Configuration > AI response scan mode',
      validation: 'Response scan records flag, redact, or block outcomes.',
      targetTab: 'policy',
    },
  ];
  const proofs = [
    {
      id: 'mcp_required_sensor',
      label: 'MCP guard required in deployment baseline',
      status: required ? 'verified' : 'missing',
      detail: required ? 'MCP guard must report before coverage can read healthy.' : 'MCP guard is optional in the current required-sensor baseline.',
      evidenceAt: mcpLastSeen,
      source: 'policy',
      action: 'Require MCP guard',
      targetTab: 'policy',
    },
    {
      id: 'mcp_activity_observed',
      label: 'MCP or agent activity observed',
      status: observed ? 'verified' : 'missing',
      detail: observed ? `${observed} MCP event${observed === 1 ? '' : 's'} observed.` : 'No MCP guard events have reached the control plane.',
      evidenceAt: mcpLastSeen,
      source: 'mcp_guard',
      action: 'Run MCP smoke',
      targetTab: 'coverage',
    },
    {
      id: 'mcp_output_control',
      label: 'Pre-model redaction or block proven',
      status: controlled || redactedDocs ? 'verified' : observed ? 'attention' : 'missing',
      detail: controlled || redactedDocs ? `${controlled || redactedDocs} MCP control event${(controlled || redactedDocs) === 1 ? '' : 's'} recorded.` : 'MCP visibility exists, but redaction or block proof is missing.',
      evidenceAt: mcpLastSeen,
      source: 'mcp_guard',
      action: 'Prove MCP control',
      targetTab: 'lineage',
    },
    {
      id: 'mcp_tool_registry',
      label: 'MCP tool registry configured',
      status: toolRegistry.length || scopedMcpPolicy ? 'verified' : 'missing',
      detail: toolRegistry.length ? `${toolRegistry.length} MCP tool policy rule${toolRegistry.length === 1 ? '' : 's'} configured.` : scopedMcpPolicy ? 'Scoped policy applies to MCP guard traffic.' : 'No MCP tool allow/block/approval registry is configured.',
      evidenceAt: null,
      source: 'policy',
      action: 'Configure MCP tools',
      targetTab: 'policy',
    },
    {
      id: 'mcp_response_scan',
      label: 'Agent output response scan active',
      status: responseScan ? 'verified' : 'missing',
      detail: responseScan ? `Response scanning is ${safeText(policy.responseScanMode, 'configured', 30)}.` : 'Agent outputs are not covered by response scanning.',
      evidenceAt: null,
      source: 'policy',
      action: 'Enable response scan',
      targetTab: 'policy',
    },
  ];
  return readinessArea({
    id: 'mcp_agent_gateway',
    label: 'MCP / Agent Gateway',
    description: 'Agent tool calls are visible, policy-scoped, and redacted or blocked before model access.',
    score,
    evidence,
    gaps,
    action: gaps.length ? 'Open policy' : 'Inspect lineage',
    targetTab: gaps.length ? 'policy' : 'lineage',
    owner: 'ai platform',
    source: 'mcp_guard',
    location: 'MCP clients, connectors, tool registry, and agent outputs',
    critical: !observed,
    playbook,
    proofs,
  });
}

function configuredApprovalChannelTypes(env) {
  return unique(notifiers.configuredChannels(env).map((channel) => channel.type || channel.name || 'channel'), 8);
}

function socReadiness({ policy, auditIntegrity, env, postureFeedSupported }) {
  const siemConfigured = !!outboundHttpsUrl(env.SIEM_WEBHOOK_URL);
  const approvalChannels = configuredApprovalChannelTypes(env);
  const routingRules = Array.isArray(policy.approvalRoutingRules) ? policy.approvalRoutingRules.filter((rule) => rule && rule.enabled !== false).length : 0;
  const auditOk = auditIntegrity && auditIntegrity.ok === true;
  const auditCount = n(auditIntegrity && auditIntegrity.count);
  const score = add(35, siemConfigured)
    + add(20, postureFeedSupported)
    + add(15, approvalChannels.length)
    + add(15, routingRules)
    + add(15, auditOk);
  const evidence = [
    siemConfigured && 'SIEM webhook is configured with an HTTPS URL',
    postureFeedSupported && 'Sanitized posture snapshot feed is available',
    approvalChannels.length && `Approval workflow channels: ${approvalChannels.join(', ')}`,
    routingRules && `${routingRules} enabled approval routing rule${routingRules === 1 ? '' : 's'}`,
    auditOk && `${auditCount} audit entries verified`,
  ];
  const gaps = [
    !siemConfigured && 'Configure SIEM_WEBHOOK_URL for SOC posture snapshots',
    !approvalChannels.length && 'Configure Slack, Teams, Jira, Linear, SMTP, or webhook approval notifications',
    !routingRules && 'Add owner and SLA routing rules for approvals',
    !auditOk && 'Repair audit-chain verification before examiner export',
  ];
  const playbook = [
    {
      id: 'soc_siem_webhook',
      label: 'Configure SIEM posture webhook',
      done: siemConfigured,
      detail: 'Send only sanitized posture metadata to the SOC so prompt bodies and secrets stay local.',
      command: 'Set SIEM_WEBHOOK_URL=https://... and SIEM_WEBHOOK_TOKEN=<token>',
      validation: 'AI Command Center > Send SOC snapshot returns SENT.',
      targetTab: 'audit',
    },
    {
      id: 'soc_posture_snapshot',
      label: 'Send a sanitized SOC snapshot',
      done: !!(siemConfigured && postureFeedSupported),
      detail: 'Exercise the posture feed after gateway and endpoint evidence change.',
      command: 'POST /api/posture/notify from an authenticated Security Admin session',
      validation: 'SIEM/SOAR receives redactwall.posture_snapshot without prompt text.',
      targetTab: 'audit',
    },
    {
      id: 'soc_approval_channels',
      label: 'Wire approval workflow channels',
      done: !!approvalChannels.length,
      detail: 'Route held prompts to the operational systems approvers already watch.',
      command: 'Configure Slack, Teams, Jira, Linear, SMTP, or approval webhook environment variables',
      validation: 'A held prompt notification records sent or partial channel status.',
      targetTab: 'policy',
    },
    {
      id: 'soc_routing_rules',
      label: 'Add owner and SLA routing rules',
      done: !!routingRules,
      detail: 'Give every high-risk hold an accountable owner, role, group, and response window.',
      command: 'Configuration > approvalRoutingRules with owner group, reviewer role, and SLA minutes',
      validation: 'Queue incidents show assigned group or role and SLA due time.',
      targetTab: 'policy',
    },
    {
      id: 'soc_audit_chain',
      label: 'Verify examiner audit chain',
      done: !!auditOk,
      detail: 'Keep exports examiner-ready by proving the hash chain before evidence leaves the system.',
      command: 'Open Evidence > Audit Integrity or export the evidence pack',
      validation: 'Audit Log verifies the hash chain and evidence export includes integrity status.',
      targetTab: 'audit',
    },
  ];
  const proofs = [
    {
      id: 'soc_siem_webhook',
      label: 'SIEM/SOAR posture webhook configured',
      status: siemConfigured ? 'verified' : 'missing',
      detail: siemConfigured ? 'Outbound posture webhook uses an HTTPS URL.' : 'SIEM_WEBHOOK_URL is not configured with an outbound HTTPS URL.',
      evidenceAt: null,
      source: 'siem',
      action: 'Configure SIEM webhook',
      targetTab: 'audit',
    },
    {
      id: 'soc_posture_snapshot',
      label: 'Sanitized posture snapshot can be sent',
      status: siemConfigured && postureFeedSupported ? 'verified' : postureFeedSupported ? 'attention' : 'missing',
      detail: siemConfigured && postureFeedSupported
        ? 'SOC snapshot path is configured and emits sanitized posture metadata.'
        : postureFeedSupported ? 'Snapshot feed exists, but no SOC destination is configured.' : 'Posture snapshot endpoint is not available.',
      evidenceAt: null,
      source: 'posture',
      action: 'Send SOC snapshot',
      targetTab: 'audit',
    },
    {
      id: 'soc_approval_channels',
      label: 'Approval workflow channels wired',
      status: approvalChannels.length ? 'verified' : 'missing',
      detail: approvalChannels.length ? `Approval channels configured: ${approvalChannels.join(', ')}.` : 'No Slack, Teams, Jira, Linear, SMTP, or webhook approval channel is configured.',
      evidenceAt: null,
      source: 'workflow',
      action: 'Configure approval channels',
      targetTab: 'policy',
    },
    {
      id: 'soc_routing_rules',
      label: 'Owner and SLA routing rules active',
      status: routingRules ? 'verified' : 'missing',
      detail: routingRules ? `${routingRules} enabled approval routing rule${routingRules === 1 ? '' : 's'} assign owner and SLA.` : 'No enabled approval routing rules assign owner and SLA.',
      evidenceAt: null,
      source: 'policy',
      action: 'Add routing rules',
      targetTab: 'policy',
    },
    {
      id: 'soc_audit_chain',
      label: 'Examiner audit chain verified',
      status: auditOk ? 'verified' : auditCount ? 'attention' : 'missing',
      detail: auditOk ? `${auditCount} audit entries verified in the hash chain.` : auditCount ? `${auditCount} audit entries exist, but chain verification needs attention.` : 'No verified audit-chain evidence is available.',
      evidenceAt: null,
      source: 'audit',
      action: 'Verify audit chain',
      targetTab: 'audit',
    },
  ];
  return readinessArea({
    id: 'soc_posture_feed',
    label: 'SOC Posture Feed',
    description: 'Security operations can receive sanitized posture snapshots, workflow routes, and audit-proof status.',
    score,
    evidence,
    gaps,
    action: gaps.length ? 'Open audit' : 'Open audit',
    targetTab: 'audit',
    owner: 'security operations',
    source: 'siem',
    location: 'SIEM/SOAR webhook, approval channels, and evidence export',
    critical: !siemConfigured && !auditOk,
    playbook,
    proofs,
  });
}

function summarize({
  rows = [],
  policy = {},
  coverageReport = null,
  auditIntegrity = null,
  env = process.env,
  postureFeedSupported = true,
} = {}) {
  const cleanRows = Array.isArray(rows) ? rows : [];
  const report = coverageReport || coverage.summarize(cleanRows, policy);
  const areas = [
    gatewayReadiness({ rows: cleanRows, policy, coverageReport: report }),
    assetDiscoveryReadiness({ policy, coverageReport: report }),
    mcpAgentReadiness({ rows: cleanRows, policy, coverageReport: report }),
  ];
  const score = areas.length ? bound(areas.reduce((sum, area) => sum + area.score, 0) / areas.length) : 0;
  const state = areas.every((area) => area.state === 'ready') ? 'ready'
    : areas.some((area) => area.state === 'blocked') ? 'blocked'
      : 'attention';
  return {
    generatedAt: new Date().toISOString(),
    score,
    state,
    status: statusFor(state),
    summary: {
      ready: areas.filter((area) => area.state === 'ready').length,
      attention: areas.filter((area) => area.state === 'attention').length,
      blocked: areas.filter((area) => area.state === 'blocked').length,
      total: areas.length,
    },
    areas,
    proofLedger: proofLedgerForAreas(areas),
    mission: missionForAreas(areas),
    nextActions: areas
      .filter((area) => area.gaps.length)
      .map((area, index) => ({
        id: area.id,
        label: area.label,
        action: (area.playbook.find((step) => step.status === 'next') || {}).label || area.gaps[0],
        detail: area.gaps[0],
        targetTab: area.targetTab,
        priority: index + 1,
      })),
  };
}

module.exports = {
  summarize,
  gatewayReadiness,
  assetDiscoveryReadiness,
  mcpAgentReadiness,
  desktopReadiness,
  socReadiness,
  BLOCKED_STATUSES,
  REDACTED_STATUSES,
};
