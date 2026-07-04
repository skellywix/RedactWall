'use strict';
/** MCP connector registry separates shipped coverage from profile templates. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  CONNECTOR_PROFILES,
  connectorRegistryChecks,
  connectorRegistryStatus,
  profileStatus,
} = require('../sensors/mcp-guard/connector-registry');

function tempRoot(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-mcp-registry-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const microsoft = path.join(dir, 'sensors', 'mcp-guard', 'connectors', 'microsoft365.js');
  fs.mkdirSync(path.dirname(microsoft), { recursive: true });
  fs.writeFileSync(microsoft, 'module.exports = {};');
  const googleDrive = path.join(dir, 'sensors', 'mcp-guard', 'connectors', 'google-drive.js');
  fs.writeFileSync(googleDrive, 'module.exports = {};');
  const slack = path.join(dir, 'sensors', 'mcp-guard', 'connectors', 'slack.js');
  fs.writeFileSync(slack, 'module.exports = {};');
  const teams = path.join(dir, 'sensors', 'mcp-guard', 'connectors', 'teams.js');
  fs.writeFileSync(teams, 'module.exports = {};');
  const atlassian = path.join(dir, 'sensors', 'mcp-guard', 'connectors', 'atlassian.js');
  fs.writeFileSync(atlassian, 'module.exports = {};');
  const databaseReadonly = path.join(dir, 'sensors', 'mcp-guard', 'connectors', 'database-readonly.js');
  fs.writeFileSync(databaseReadonly, 'module.exports = {};');
  return dir;
}

test('connector registry reports shipped runtime and template breadth without secrets', (t) => {
  const repoRoot = tempRoot(t);
  const token = 'microsoft-graph-token-000000000000000000000001';
  const status = connectorRegistryStatus({
    repoRoot,
    envConfig: {
      M365_GRAPH_ACCESS_TOKEN: token,
      M365_TENANT_ID: 'tenant-acme',
      M365_GRAPH_SCOPES: 'Files.Read Sites.Selected',
      GOOGLE_DRIVE_ACCESS_TOKEN: 'google-token-000000000000000000000000001',
      SLACK_BOT_TOKEN: 'fixture-slack-token-000000000000000000000001',
      TEAMS_GRAPH_ACCESS_TOKEN: 'teams-graph-token-000000000000000000000001',
      ATLASSIAN_ACCESS_TOKEN: 'atlassian-token-000000000000000000000001',
      ATLASSIAN_SITE_URL: 'https://acme.atlassian.net',
      MCP_DATABASE_DSN: 'sqlite:///C:/data/read-only.db',
      MCP_DATABASE_LABEL: 'core-reporting',
    },
  });

  assert.strictEqual(status.summary.shipped, 6);
  assert.strictEqual(status.summary.shippedRuntimePresent, 6);
  assert.strictEqual(status.summary.profileTemplates, 0);
  assert.strictEqual(status.summary.nextConnector, 'none');
  assert.ok(status.profiles.some((profile) => profile.id === 'microsoft365' && profile.stage === 'shipped' && profile.configured));
  assert.ok(status.profiles.some((profile) => profile.id === 'google_drive' && profile.stage === 'shipped' && profile.configured));
  assert.ok(status.profiles.some((profile) => profile.id === 'slack' && profile.stage === 'shipped' && profile.configured));
  assert.ok(status.profiles.some((profile) => profile.id === 'teams' && profile.stage === 'shipped' && profile.configured));
  assert.ok(status.profiles.some((profile) => profile.id === 'jira_confluence' && profile.stage === 'shipped' && profile.configured));
  assert.ok(status.profiles.some((profile) => profile.id === 'database_readonly' && profile.stage === 'shipped' && profile.configured));
  assert.ok(!JSON.stringify(status).includes(token));
  assert.ok(!JSON.stringify(status).includes('google-token-'));
  assert.ok(!JSON.stringify(status).includes('fixture-slack-token-'));
  assert.ok(!JSON.stringify(status).includes('teams-graph-token-'));
  assert.ok(!JSON.stringify(status).includes('atlassian-token-'));
  assert.ok(!JSON.stringify(status).includes('sqlite:///C:/data/read-only.db'));

  const checks = connectorRegistryChecks(status);
  assert.ok(checks.some((item) => item.id === 'mcp_connector_registry' && item.ok && /shipped:6\/6/.test(item.detail)));
  assert.ok(checks.some((item) => item.id === 'mcp_connector_profile_microsoft365' && /stage:shipped/.test(item.detail)));
  assert.ok(checks.some((item) => item.id === 'mcp_connector_profile_google_drive' && /stage:shipped/.test(item.detail)));
  assert.ok(checks.some((item) => item.id === 'mcp_connector_profile_slack' && /stage:shipped/.test(item.detail)));
  assert.ok(checks.some((item) => item.id === 'mcp_connector_profile_teams' && /stage:shipped/.test(item.detail)));
  assert.ok(checks.some((item) => item.id === 'mcp_connector_profile_jira_confluence' && /stage:shipped/.test(item.detail)));
  assert.ok(checks.some((item) => item.id === 'mcp_connector_profile_database_readonly' && /stage:shipped/.test(item.detail)));
  assert.ok(!JSON.stringify(checks).includes(token));
});

test('registry marks shipped runtime attention separately from roadmap profiles', () => {
  const missing = profileStatus(CONNECTOR_PROFILES.find((profile) => profile.id === 'microsoft365'), {
    repoRoot: path.join(os.tmpdir(), 'missing-promptwall-root'),
    envConfig: {},
  });
  assert.strictEqual(missing.stage, 'shipped');
  assert.strictEqual(missing.runtimePresent, false);
  assert.strictEqual(missing.status, 'runtime_missing');

  const googleDrive = profileStatus(CONNECTOR_PROFILES.find((profile) => profile.id === 'google_drive'), {
    repoRoot: path.join(os.tmpdir(), 'missing-promptwall-root'),
    envConfig: { GOOGLE_DRIVE_ACCESS_TOKEN: 'google-token-000000000000000000000000001' },
  });
  assert.strictEqual(googleDrive.stage, 'shipped');
  assert.strictEqual(googleDrive.runtimePresent, false);
  assert.strictEqual(googleDrive.configured, true);
  assert.strictEqual(googleDrive.status, 'runtime_missing');

  const slack = profileStatus(CONNECTOR_PROFILES.find((profile) => profile.id === 'slack'), {
    repoRoot: path.join(os.tmpdir(), 'missing-promptwall-root'),
    envConfig: { SLACK_BOT_TOKEN: 'fixture-slack-token-000000000000000000000001' },
  });
  assert.strictEqual(slack.stage, 'shipped');
  assert.strictEqual(slack.runtimePresent, false);
  assert.strictEqual(slack.configured, true);
  assert.strictEqual(slack.status, 'runtime_missing');

  const teams = profileStatus(CONNECTOR_PROFILES.find((profile) => profile.id === 'teams'), {
    repoRoot: path.join(os.tmpdir(), 'missing-promptwall-root'),
    envConfig: { TEAMS_GRAPH_ACCESS_TOKEN: 'teams-graph-token-000000000000000000000001' },
  });
  assert.strictEqual(teams.stage, 'shipped');
  assert.strictEqual(teams.runtimePresent, false);
  assert.strictEqual(teams.configured, true);
  assert.strictEqual(teams.status, 'runtime_missing');

  const atlassian = profileStatus(CONNECTOR_PROFILES.find((profile) => profile.id === 'jira_confluence'), {
    repoRoot: path.join(os.tmpdir(), 'missing-promptwall-root'),
    envConfig: {
      ATLASSIAN_ACCESS_TOKEN: 'atlassian-token-000000000000000000000001',
      ATLASSIAN_SITE_URL: 'https://acme.atlassian.net',
    },
  });
  assert.strictEqual(atlassian.stage, 'shipped');
  assert.strictEqual(atlassian.runtimePresent, false);
  assert.strictEqual(atlassian.configured, true);
  assert.strictEqual(atlassian.status, 'runtime_missing');

  const database = profileStatus(CONNECTOR_PROFILES.find((profile) => profile.id === 'database_readonly'), {
    repoRoot: path.join(os.tmpdir(), 'missing-promptwall-root'),
    envConfig: { MCP_DATABASE_DSN: 'sqlite:///C:/data/read-only.db' },
  });
  assert.strictEqual(database.stage, 'shipped');
  assert.strictEqual(database.runtimePresent, false);
  assert.strictEqual(database.configured, true);
  assert.strictEqual(database.status, 'runtime_missing');
});
