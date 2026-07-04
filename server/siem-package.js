'use strict';
/**
 * Offline SIEM/SOAR package generator.
 *
 * The package is a deployment artifact, not a sender. It emits mappings,
 * sample sanitized events, searches, and setup checklists without reading
 * secrets or calling any external SOC/SIEM endpoint.
 */
const AdmZip = require('adm-zip');
const alerts = require('./alerts');

const SUPPORTED_PROFILES = Object.freeze(['splunk', 'sentinel', 'chronicle', 'servicenow']);
const DEFAULT_PROFILE = 'all';

const DOCS = Object.freeze({
  splunk: [
    'https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/get-data-with-http-event-collector/format-events-for-http-event-collector',
  ],
  sentinel: [
    'https://learn.microsoft.com/en-us/azure/sentinel/data-transformation',
    'https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog',
  ],
  chronicle: [
    'https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview',
    'https://docs.cloud.google.com/chronicle/docs/ingestion/data-types',
  ],
  servicenow: [
    'https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html',
  ],
});

const SAMPLE_SECURITY_QUERY = Object.freeze({
  id: 'q_demo_security_001',
  createdAt: '2026-07-04T12:00:00.000Z',
  status: 'pending',
  mode: 'block',
  user: 'analyst@example.test',
  orgId: 'cu-demo',
  source: 'browser_extension',
  channel: 'submit',
  sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
  destination: 'chatgpt.com',
  riskScore: 74,
  maxSeverity: 4,
  maxSeverityLabel: 'critical',
  findings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '***-**-1234' }],
  categories: ['PII'],
  reasons: ['Hard-stop entity present: US_SSN'],
  assignedGroup: 'compliance',
  assignedRole: 'approver',
  workflowReason: 'detector:US_SSN',
  slaDueAt: '2026-07-04T16:00:00.000Z',
  notificationStatus: 'not_configured',
});

const SAMPLE_POSTURE_REPORT = Object.freeze({
  generatedAt: '2026-07-04T12:00:00.000Z',
  windowDays: 7,
  summary: {
    events: 42,
    sensitiveEvents: 12,
    blocked: 7,
    redacted: 4,
    pending: 3,
    controlRate: 0.86,
    shadowEvents: 9,
    unresolvedShadowDestinations: 2,
    activeRequiredSensors: 3,
    requiredSensors: 3,
  },
  segments: {
    summary: { total: 5, attention: 2, critical: 1 },
  },
  hardening: {
    score: 86,
    state: 'attention',
    summary: { ready: 5, attention: 2, blocked: 0, total: 7 },
    mission: {
      state: 'attention',
      progress: { percent: 72, open: 2 },
      current: { areaLabel: 'SOC Integration Pack', label: 'Install saved searches' },
      proofLedger: { verified: 8, attention: 2, missing: 1, total: 11, percent: 73 },
    },
    areas: [{
      id: 'soc_integration_pack',
      label: 'SOC Integration Pack',
      score: 82,
      state: 'attention',
      status: 'review',
      owner: 'security',
      source: 'command_center',
      evidence: ['Sanitized posture feed enabled'],
      gaps: ['Install SIEM saved searches'],
      playbook: [{ status: 'next', label: 'Import SIEM package' }],
      proofLedger: { verified: 1, attention: 1, missing: 0, total: 2 },
    }],
  },
  aiInventory: {
    summary: {
      sanctioned: 4,
      unsanctioned: 2,
      shadow: 2,
      localTools: 3,
      unapprovedLocalTools: 1,
      activeDestinations: 8,
      totalEvents: 42,
      highRiskAssets: 2,
    },
  },
  threatGuardrails: {
    summary: {
      events: 6,
      detections: 8,
      activeRules: 4,
      promptInjection: 1,
      sensitiveDisclosure: 3,
      unsafeOutput: 1,
      agentActions: 1,
      shadowAi: 2,
      unscannedContent: 0,
    },
  },
  actionQueue: [{
    id: 'mission:soc_integration_pack:saved_searches',
    severity: 'warning',
    category: 'soc_integration',
    workflowStatus: 'open',
    workflowProofState: 'proof_pending',
  }],
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function epochSeconds(iso) {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
}

function sampleEvents() {
  const securityEvent = alerts.sanitizedAlert(clone(SAMPLE_SECURITY_QUERY), { action: 'BLOCKED' });
  const postureEvent = alerts.sanitizedPostureAlert(clone(SAMPLE_POSTURE_REPORT), {
    action: 'POSTURE_FEED',
    automatic: true,
    trigger: 'BLOCKED',
  });
  return { securityEvent, postureEvent };
}

function privacyContract() {
  return {
    rawPromptBodies: false,
    redactedPromptBodies: false,
    rawFindingValues: false,
    tokenVaultValues: false,
    secretsOrCredentials: false,
    rawUrlsOrFilePaths: false,
    sampleData: 'Synthetic .test users, placeholder destinations, masked detector values, and aggregate posture only.',
  };
}

function commonFields() {
  return [
    { promptwall: 'eventType', meaning: 'promptwall.security_event or promptwall.posture_snapshot' },
    { promptwall: 'action', meaning: 'PromptWall action such as BLOCKED, SENSOR_VERSION_GAP, or POSTURE_FEED' },
    { promptwall: 'queryId', meaning: 'PromptWall evidence id for security events' },
    { promptwall: 'user', meaning: 'Managed user id or configured user label' },
    { promptwall: 'orgId', meaning: 'Managed tenant or organization id' },
    { promptwall: 'source', meaning: 'Sensor surface such as browser_extension, endpoint_agent, mcp_guard, proxy, or api' },
    { promptwall: 'destination', meaning: 'Host-only AI destination label' },
    { promptwall: 'riskScore', meaning: 'PromptWall bounded risk score' },
    { promptwall: 'maxSeverityLabel', meaning: 'Highest detector severity label' },
    { promptwall: 'findings[].type', meaning: 'Detector id only, without raw value' },
    { promptwall: 'findings[].masked', meaning: 'Masked sample value when available' },
    { promptwall: 'workflow.assignedGroup', meaning: 'Review queue or owner group' },
    { promptwall: 'workflow.slaDueAt', meaning: 'Reviewer SLA timestamp' },
    { promptwall: 'summary.*', meaning: 'Aggregate posture counters for posture snapshots' },
    { promptwall: 'hardening.*', meaning: 'Aggregate hardening state and proof counts' },
    { promptwall: 'aiInventory.*', meaning: 'Aggregate AI asset counts' },
    { promptwall: 'threatGuardrails.*', meaning: 'Aggregate AI threat guardrail counts for posture snapshots' },
  ];
}

function splunkProfile(samples) {
  const { securityEvent, postureEvent } = samples;
  return {
    id: 'splunk',
    label: 'Splunk HEC Pack',
    target: 'Splunk Enterprise or Splunk Cloud Platform HTTP Event Collector',
    docs: DOCS.splunk,
    transport: {
      method: 'POST',
      endpointPath: '/services/collector/event',
      authHeaderPattern: 'Authorization: Splunk <hec-token>',
      sourcetypes: ['promptwall:security', 'promptwall:posture'],
      recommendedIndex: 'promptwall',
    },
    fieldMappings: commonFields().map((field) => ({
      ...field,
      splunk: `event.${field.promptwall}`,
    })),
    savedSearches: [
      {
        name: 'PromptWall high-risk AI DLP events',
        spl: 'index=promptwall sourcetype=promptwall:security eventType=promptwall.security_event (status=pending OR maxSeverity>=4 OR riskScore>=70) | stats count max(riskScore) as maxRisk values(findings{}.type) as detectors by user,destination,workflow.assignedGroup,status | sort - maxRisk',
      },
      {
        name: 'PromptWall shadow AI posture',
        spl: 'index=promptwall sourcetype=promptwall:posture eventType=promptwall.posture_snapshot | timechart span=1h max(summary.unresolvedShadowDestinations) as unresolvedShadow max(aiInventory.highRiskAssets) as highRiskAssets',
      },
      {
        name: 'PromptWall AI threat guardrails',
        spl: 'index=promptwall sourcetype=promptwall:posture eventType=promptwall.posture_snapshot | timechart span=1h max(threatGuardrails.promptInjection) as promptInjection max(threatGuardrails.unsafeOutput) as unsafeOutput max(threatGuardrails.agentActions) as agentActions max(threatGuardrails.sensitiveDisclosure) as sensitiveDisclosure',
      },
      {
        name: 'PromptWall reviewer SLA queue',
        spl: 'index=promptwall sourcetype=promptwall:security eventType=promptwall.security_event workflow.slaDueAt=* | stats count values(status) as status by workflow.assignedGroup,workflow.assignedRole,workflow.slaDueAt',
      },
    ],
    dashboardPanels: [
      { title: 'Blocked AI submissions by destination', search: 'index=promptwall sourcetype=promptwall:security status=pending | top destination limit=10' },
      { title: 'AI threat guardrails', search: 'index=promptwall sourcetype=promptwall:posture | timechart span=1d max(threatGuardrails.promptInjection) as promptInjection max(threatGuardrails.unsafeOutput) as unsafeOutput max(threatGuardrails.agentActions) as agentActions' },
      { title: 'Posture score over time', search: 'index=promptwall sourcetype=promptwall:posture | timechart span=1d max(hardening.score) as score' },
    ],
    samplePayloads: [
      {
        name: 'security-event-hec',
        payload: {
          time: epochSeconds(securityEvent.createdAt),
          host: 'promptwall.local',
          source: 'promptwall',
          sourcetype: 'promptwall:security',
          index: 'promptwall',
          event: securityEvent,
        },
      },
      {
        name: 'posture-snapshot-hec',
        payload: {
          time: epochSeconds(postureEvent.generatedAt),
          host: 'promptwall.local',
          source: 'promptwall',
          sourcetype: 'promptwall:posture',
          index: 'promptwall',
          event: postureEvent,
        },
      },
    ],
    setupChecklist: [
      'Create a dedicated PromptWall HEC token scoped to the promptwall index.',
      'Route promptwall:security and promptwall:posture sourcetypes into a restricted security index.',
      'Import saved searches and dashboard panels from this package.',
      'Validate that no raw prompt, raw finding value, token vault, URL path, or file path fields are indexed.',
    ],
  };
}

function sentinelProfile(samples) {
  const { securityEvent, postureEvent } = samples;
  return {
    id: 'sentinel',
    label: 'Microsoft Sentinel Pack',
    target: 'Microsoft Sentinel custom table or CommonSecurityLog normalization',
    docs: DOCS.sentinel,
    transport: {
      ingestion: 'Azure Monitor Logs ingestion API with a data collection rule',
      customTable: 'PromptWall_CL',
      streamName: 'Custom-PromptWall_CL',
      transformHint: 'Use a DCR transform to keep the sanitized PromptWall schema or project normalized CommonSecurityLog columns.',
    },
    fieldMappings: [
      { promptwall: 'eventType', sentinel: 'EventType_s', commonSecurityLog: 'DeviceEventClassID' },
      { promptwall: 'action', sentinel: 'Action_s', commonSecurityLog: 'DeviceAction' },
      { promptwall: 'user', sentinel: 'User_s', commonSecurityLog: 'SourceUserName' },
      { promptwall: 'destination', sentinel: 'Destination_s', commonSecurityLog: 'DestinationHostName' },
      { promptwall: 'riskScore', sentinel: 'RiskScore_d', commonSecurityLog: 'FlexNumber1' },
      { promptwall: 'maxSeverityLabel', sentinel: 'Severity_s', commonSecurityLog: 'LogSeverity' },
      { promptwall: 'workflow.assignedGroup', sentinel: 'AssignedGroup_s', commonSecurityLog: 'FlexString1' },
      { promptwall: 'summary.unresolvedShadowDestinations', sentinel: 'UnresolvedShadowDestinations_d', commonSecurityLog: 'FlexNumber2' },
      { promptwall: 'threatGuardrails.promptInjection', sentinel: 'PromptInjection_d', commonSecurityLog: 'FlexNumber3' },
      { promptwall: 'threatGuardrails.unsafeOutput', sentinel: 'UnsafeOutput_d', commonSecurityLog: 'FlexNumber4' },
      { promptwall: 'threatGuardrails.agentActions', sentinel: 'AgentActions_d', commonSecurityLog: 'FlexNumber5' },
      { promptwall: 'threatGuardrails.sensitiveDisclosure', sentinel: 'SensitiveDisclosure_d', commonSecurityLog: 'FlexNumber6' },
    ],
    transformKql: [
      'source',
      '| extend EventType_s=tostring(eventType), Action_s=tostring(action), User_s=tostring(user), Destination_s=tostring(destination)',
      '| extend RiskScore_d=todouble(riskScore), Severity_s=tostring(maxSeverityLabel), AssignedGroup_s=tostring(workflow.assignedGroup)',
      '| extend PromptInjection_d=todouble(threatGuardrails.promptInjection), UnsafeOutput_d=todouble(threatGuardrails.unsafeOutput), AgentActions_d=todouble(threatGuardrails.agentActions), SensitiveDisclosure_d=todouble(threatGuardrails.sensitiveDisclosure)',
      '| project-away rawPrompt, redactedPrompt, tokenVault, rawFindingValue',
    ].join('\n'),
    savedSearches: [
      {
        name: 'PromptWall blocked AI data-loss attempts',
        kql: 'PromptWall_CL | where EventType_s == "promptwall.security_event" and (Status_s == "pending" or RiskScore_d >= 70 or Severity_s == "critical") | summarize Events=count(), MaxRisk=max(RiskScore_d), Detectors=make_set(Findings_s, 10) by User_s, Destination_s, AssignedGroup_s | order by MaxRisk desc',
      },
      {
        name: 'PromptWall posture drift',
        kql: 'PromptWall_CL | where EventType_s == "promptwall.posture_snapshot" | summarize Score=max(HardeningScore_d), Shadow=max(UnresolvedShadowDestinations_d), HighRiskAssets=max(HighRiskAssets_d) by bin(TimeGenerated, 1h)',
      },
      {
        name: 'PromptWall AI threat guardrails',
        kql: 'PromptWall_CL | where EventType_s == "promptwall.posture_snapshot" | summarize PromptInjection=max(PromptInjection_d), UnsafeOutput=max(UnsafeOutput_d), AgentActions=max(AgentActions_d), SensitiveDisclosure=max(SensitiveDisclosure_d) by bin(TimeGenerated, 1h)',
      },
    ],
    workbookPanels: [
      { title: 'PromptWall DLP decisions', kql: 'PromptWall_CL | summarize count() by Action_s, Destination_s' },
      { title: 'AI threat guardrails', kql: 'PromptWall_CL | where EventType_s == "promptwall.posture_snapshot" | project TimeGenerated, PromptInjection_d, UnsafeOutput_d, AgentActions_d, SensitiveDisclosure_d' },
      { title: 'Segments needing review', kql: 'PromptWall_CL | where PostureSegmentAttention_d > 0 | project TimeGenerated, PostureSegmentAttention_d, PostureSegmentCritical_d' },
    ],
    samplePayloads: [
      { name: 'security-event-log-ingestion', payload: securityEvent },
      { name: 'posture-snapshot-log-ingestion', payload: postureEvent },
    ],
    setupChecklist: [
      'Create the PromptWall_CL custom table or a DCR path that maps into CommonSecurityLog.',
      'Apply the transform to drop any unexpected raw prompt, token vault, URL path, or file path columns.',
      'Create analytics rules from the saved KQL searches.',
      'Limit workspace access to SOC roles allowed to view sanitized PromptWall metadata.',
    ],
  };
}

function chronicleProfile(samples) {
  const { securityEvent, postureEvent } = samples;
  return {
    id: 'chronicle',
    label: 'Google Security Operations UDM Pack',
    target: 'Google Security Operations custom ingestion with UDM mapping',
    docs: DOCS.chronicle,
    transport: {
      ingestion: 'Forward sanitized JSON through the chosen Google SecOps ingestion method.',
      parserFamily: 'Custom JSON to UDM',
      productName: 'PromptWall',
      vendorName: 'PromptWall',
    },
    fieldMappings: [
      { promptwall: 'eventType', udm: 'metadata.product_event_type' },
      { promptwall: 'source', udm: 'metadata.product_log_id' },
      { promptwall: 'user', udm: 'principal.user.userid' },
      { promptwall: 'orgId', udm: 'principal.group.group_display_name' },
      { promptwall: 'destination', udm: 'target.application' },
      { promptwall: 'action', udm: 'security_result.action' },
      { promptwall: 'maxSeverityLabel', udm: 'security_result.severity' },
      { promptwall: 'findings[].type', udm: 'security_result.rule_name' },
      { promptwall: 'workflow.assignedGroup', udm: 'about.labels[promptwall_assigned_group]' },
      { promptwall: 'summary.*', udm: 'about.labels[promptwall_posture_*]' },
    ],
    detections: [
      {
        name: 'PromptWall critical AI exfiltration attempt',
        udmSearch: 'metadata.vendor_name = "PromptWall" metadata.product_event_type = "promptwall.security_event" security_result.action = "BLOCK"',
      },
      {
        name: 'PromptWall unresolved shadow AI posture',
        udmSearch: 'metadata.vendor_name = "PromptWall" metadata.product_event_type = "promptwall.posture_snapshot" about.labels.key = "promptwall_unresolved_shadow"',
      },
    ],
    samplePayloads: [
      {
        name: 'security-event-udm',
        payload: {
          metadata: {
            event_timestamp: securityEvent.createdAt,
            event_type: 'NETWORK_HTTP',
            vendor_name: 'PromptWall',
            product_name: 'PromptWall',
            product_event_type: securityEvent.eventType,
          },
          principal: {
            user: { userid: securityEvent.user },
            group: { group_display_name: securityEvent.orgId },
          },
          target: { application: securityEvent.destination },
          security_result: [{
            action: 'BLOCK',
            severity: 'HIGH',
            rule_name: 'US_SSN',
            category: ['DATA_EXFILTRATION'],
          }],
          about: {
            labels: [
              { key: 'promptwall_query_id', value: securityEvent.queryId },
              { key: 'promptwall_assigned_group', value: securityEvent.workflow.assignedGroup },
            ],
          },
        },
      },
      {
        name: 'posture-snapshot-json',
        payload: postureEvent,
      },
    ],
    setupChecklist: [
      'Register PromptWall as a custom JSON source in Google Security Operations.',
      'Map security events into UDM security_result and principal/target attributes.',
      'Map posture snapshots into metadata and about.labels for dashboarding.',
      'Verify the parser never maps prompt bodies, raw findings, token vaults, URL paths, or file paths.',
    ],
  };
}

function servicenowProfile(samples) {
  const { securityEvent, postureEvent } = samples;
  return {
    id: 'servicenow',
    label: 'ServiceNow Incident Pack',
    target: 'ServiceNow Table API incident creation or SOAR workflow intake',
    docs: DOCS.servicenow,
    transport: {
      method: 'POST',
      endpointPath: '/api/now/table/incident',
      table: 'incident',
      auth: 'Use a customer-managed ServiceNow integration credential outside PromptWall.',
    },
    fieldMappings: [
      { promptwall: 'queryId', servicenow: 'correlation_id' },
      { promptwall: 'destination', servicenow: 'short_description' },
      { promptwall: 'riskScore', servicenow: 'urgency' },
      { promptwall: 'maxSeverityLabel', servicenow: 'impact' },
      { promptwall: 'workflow.assignedGroup', servicenow: 'assignment_group' },
      { promptwall: 'findings[].type', servicenow: 'work_notes' },
      { promptwall: 'summary.*', servicenow: 'description' },
    ],
    incidentTemplates: [
      {
        name: 'Blocked high-risk AI prompt',
        record: {
          short_description: 'PromptWall blocked high-risk AI submission to chatgpt.com',
          description: 'PromptWall blocked an AI submission before egress. Review sanitized detector labels, risk score, destination host, and approval SLA in PromptWall.',
          category: 'security',
          subcategory: 'data_loss_prevention',
          impact: '2',
          urgency: '2',
          correlation_id: securityEvent.queryId,
          work_notes: 'Detector labels: US_SSN. Masked value only: ***-**-1234. Raw prompt was not included.',
        },
      },
      {
        name: 'AI posture attention',
        record: {
          short_description: 'PromptWall AI posture requires SOC review',
          description: `Hardening score ${postureEvent.hardening.score}; unresolved shadow destinations ${postureEvent.summary.unresolvedShadowDestinations}; high-risk AI assets ${postureEvent.aiInventory.highRiskAssets}.`,
          category: 'security',
          subcategory: 'governance',
          impact: '3',
          urgency: '3',
          correlation_id: 'promptwall-posture-20260704T120000Z',
          work_notes: 'Aggregate posture snapshot only. No prompt body, token vault, raw URL, or file path included.',
        },
      },
    ],
    setupChecklist: [
      'Create a ServiceNow integration user and restrict it to incident creation or SOAR intake.',
      'Use correlation_id for dedupe against PromptWall query ids or posture snapshot ids.',
      'Keep assignment_group mapping customer-local; this package only names sanitized PromptWall owner groups.',
      'Confirm incident work notes never receive prompt bodies, raw findings, token vaults, URL paths, or file paths.',
    ],
  };
}

const BUILDERS = Object.freeze({
  splunk: splunkProfile,
  sentinel: sentinelProfile,
  chronicle: chronicleProfile,
  servicenow: servicenowProfile,
});

function jsonBody(value) {
  return JSON.stringify(value, null, 2) + '\n';
}

function markdownList(items = []) {
  return (Array.isArray(items) ? items : []).map((item) => `- ${item}`).join('\n');
}

function profileArtifactFiles(profile) {
  const base = `profiles/${profile.id}`;
  const files = [
    { path: `${base}/profile.json`, body: jsonBody(profile), contentType: 'application/json' },
    { path: `${base}/field-mappings.json`, body: jsonBody(profile.fieldMappings || []), contentType: 'application/json' },
    { path: `${base}/sample-payloads.json`, body: jsonBody(profile.samplePayloads || []), contentType: 'application/json' },
    {
      path: `${base}/setup-checklist.md`,
      body: `# ${profile.label || profile.id} Setup Checklist\n\n${markdownList(profile.setupChecklist || [])}\n`,
      contentType: 'text/markdown',
    },
  ];
  if (profile.id === 'splunk') {
    files.push(
      { path: `${base}/splunk-saved-searches.json`, body: jsonBody(profile.savedSearches || []), contentType: 'application/json' },
      { path: `${base}/splunk-dashboard-panels.json`, body: jsonBody(profile.dashboardPanels || []), contentType: 'application/json' },
    );
  } else if (profile.id === 'sentinel') {
    files.push(
      { path: `${base}/sentinel-dcr-transform.kql`, body: `${profile.transformKql || ''}\n`, contentType: 'text/plain' },
      { path: `${base}/sentinel-analytics-rules.json`, body: jsonBody(profile.savedSearches || []), contentType: 'application/json' },
      { path: `${base}/sentinel-workbook-panels.json`, body: jsonBody(profile.workbookPanels || []), contentType: 'application/json' },
    );
  } else if (profile.id === 'chronicle') {
    files.push(
      { path: `${base}/chronicle-udm-mapping.json`, body: jsonBody(profile.fieldMappings || []), contentType: 'application/json' },
      { path: `${base}/chronicle-detections.json`, body: jsonBody(profile.detections || []), contentType: 'application/json' },
    );
  } else if (profile.id === 'servicenow') {
    files.push(
      { path: `${base}/servicenow-incident-templates.json`, body: jsonBody(profile.incidentTemplates || []), contentType: 'application/json' },
    );
  }
  return files;
}

function packageReadme(pkg) {
  const profileLines = (pkg.profiles || []).map((profile) => (
    `- ${profile.label || profile.id}: ${(profile.setupChecklist || [])[0] || 'Import the included sanitized artifacts.'}`
  ));
  return [
    '# PromptWall SOC Integration Package',
    '',
    `Generated: ${pkg.generatedAt}`,
    `Requested profile: ${pkg.requestedProfile}`,
    '',
    '## Contents',
    '',
    markdownList((pkg.files || []).map((file) => file.path)),
    '',
    '## Profiles',
    '',
    profileLines.join('\n'),
    '',
    '## Privacy Contract',
    '',
    'This offline package contains synthetic samples, field mappings, searches, dashboards, and setup checklists only.',
    'It does not include prompt bodies, token vaults, raw detector values, secrets, URL paths, file paths, or live customer data.',
    '',
  ].join('\n');
}

function packageFiles(pkg) {
  const files = [];
  for (const profile of pkg.profiles || []) files.push(...profileArtifactFiles(profile));
  const manifest = {
    schemaVersion: pkg.schemaVersion,
    generatedAt: pkg.generatedAt,
    requestedProfile: pkg.requestedProfile,
    supportedProfiles: pkg.supportedProfiles,
    summary: pkg.summary,
    privacy: pkg.privacy,
    files: files.map((file) => ({ path: file.path, contentType: file.contentType, sizeBytes: Buffer.byteLength(file.body, 'utf8') })),
  };
  const withManifest = [
    { path: 'manifest.json', body: jsonBody(manifest), contentType: 'application/json' },
    { path: 'privacy-contract.json', body: jsonBody(pkg.privacy), contentType: 'application/json' },
    ...files,
  ];
  const readme = packageReadme({ ...pkg, files: withManifest });
  return [
    { path: 'README.md', body: readme, contentType: 'text/markdown' },
    ...withManifest,
  ];
}

function packageArchive(pkg) {
  const zip = new AdmZip();
  for (const file of packageFiles(pkg)) {
    zip.addFile(file.path, Buffer.from(file.body, 'utf8'));
  }
  return zip.toBuffer();
}

function normalizeProfile(profile) {
  const normalized = String(profile || DEFAULT_PROFILE).trim().toLowerCase();
  return normalized || DEFAULT_PROFILE;
}

function selectedProfiles(profile) {
  const normalized = normalizeProfile(profile);
  if (normalized === DEFAULT_PROFILE) return [...SUPPORTED_PROFILES];
  if (SUPPORTED_PROFILES.includes(normalized)) return [normalized];
  const err = new Error('unsupported SIEM package profile');
  err.code = 'UNSUPPORTED_PROFILE';
  throw err;
}

function integrationPackage(opts = {}) {
  const profile = normalizeProfile(opts.profile);
  const generatedAt = opts.generatedAt || new Date().toISOString();
  const samples = sampleEvents();
  const selected = selectedProfiles(profile);
  const profiles = selected.map((id) => BUILDERS[id](samples));
  const pkg = {
    schemaVersion: 1,
    generatedAt,
    requestedProfile: profile,
    supportedProfiles: [...SUPPORTED_PROFILES],
    privacy: privacyContract(),
    summary: {
      profileCount: profiles.length,
      eventTypes: ['promptwall.security_event', 'promptwall.posture_snapshot'],
      samplePayloads: profiles.reduce((sum, item) => sum + (Array.isArray(item.samplePayloads) ? item.samplePayloads.length : 0), 0),
      searches: profiles.reduce((sum, item) => sum + (item.savedSearches || item.detections || []).length, 0),
      dashboards: profiles.reduce((sum, item) => sum + (item.dashboardPanels || item.workbookPanels || item.incidentTemplates || []).length, 0),
      packageFiles: 0,
    },
    downloadFormats: ['json', 'zip'],
    profiles,
  };
  pkg.summary.packageFiles = packageFiles(pkg).length;
  return pkg;
}

module.exports = {
  SUPPORTED_PROFILES,
  integrationPackage,
  packageArchive,
  packageFiles,
  sampleEvents,
  selectedProfiles,
};
