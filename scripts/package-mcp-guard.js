'use strict';
/**
 * Build a prompt-free MCP guard handoff zip plus an integrity manifest.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const ROOT = path.join(__dirname, '..');
const DEFAULT_OUT_DIR = path.join(ROOT, 'dist', 'mcp-guard');
const PACKAGE_FILES = [
  'package.json',
  'server/env.js',
  'server/file-mutation-lock.js',
  'server/private-path.js',
  'detection-engine/detect.js',
  'sensors/shared/decision.js',
  'sensors/shared/bounded-response.js',
  'sensors/shared/opaque-content.js',
  'sensors/shared/signed-policy.js',
  'sensors/shared/server-url.js',
  'sensors/mcp-guard/guard.js',
  'sensors/mcp-guard/sdk.js',
  'sensors/mcp-guard/connector-registry.js',
  'sensors/mcp-guard/connectors/microsoft365.js',
  'sensors/mcp-guard/connectors/google-drive.js',
  'sensors/mcp-guard/connectors/slack.js',
  'sensors/mcp-guard/connectors/teams.js',
  'sensors/mcp-guard/connectors/atlassian.js',
  'sensors/mcp-guard/connectors/database-readonly.js',
  'sensors/mcp-guard/connectors/database-readonly-worker.js',
  'scripts/check-mcp-guard-install.js',
];

function posixPath(value) {
  return value.split(path.sep).join('/');
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function runtimeBody(relPath, root = ROOT) {
  const absPath = path.join(root, relPath);
  let body = fs.readFileSync(absPath);
  if (relPath === 'sensors/mcp-guard/guard.js') {
    body = Buffer.from(body.toString('utf8').replace(/\r?\n\/\/ ---- demo when run directly[\s\S]*$/, '\n'));
  }
  return body;
}

function validateRuntimeFiles(files) {
  const paths = new Set(files.map((file) => file.path));
  for (const required of PACKAGE_FILES) {
    if (!paths.has(required)) throw new Error(`MCP guard package is missing ${required}`);
  }

  const disallowed = [
    { label: 'development ingest key', pattern: /dev-ingest-key/ },
    { label: 'synthetic SSN demo value', pattern: /524-71-9043/ },
    { label: 'synthetic card demo value', pattern: /4111 1111 1111 1111/ },
    { label: 'real-looking placeholder key', pattern: /REPLACE_WITH_LONG_RANDOM_INGEST_KEY/ },
    { label: 'environment assignment', pattern: /\b(?:INGEST_API_KEY|REDACTWALL_SECRET|REDACTWALL_DATA_KEY)\s*=/ },
  ];

  for (const file of files) {
    const text = file.body.toString('utf8');
    for (const rule of disallowed) {
      if (rule.pattern.test(text)) {
        throw new Error(`MCP guard package contains ${rule.label} in ${file.path}`);
      }
    }
  }

  const guard = files.find((file) => file.path === 'sensors/mcp-guard/guard.js').body.toString('utf8');
  if (!/process\.env\.INGEST_API_KEY \|\| ''/.test(guard)) {
    throw new Error('MCP guard package must require explicit INGEST_API_KEY for control-plane logging');
  }
  if (/demo when run directly/.test(guard)) {
    throw new Error('MCP guard package must exclude direct-run demo code');
  }

  const sdk = files.find((file) => file.path === 'sensors/mcp-guard/sdk.js').body.toString('utf8');
  if (!/sanitizeToolResult/.test(sdk) || !/wrapConnectorTool/.test(sdk) || !/connectorHealthCheck/.test(sdk)) {
    throw new Error('MCP guard package must include connector SDK sanitization and health helpers');
  }
  if (!/carriesUnscannableToolResult/.test(sdk) || !/blockUnscannableToolResult/.test(sdk)) {
    throw new Error('MCP guard package must include the connector binary fail-closed guard');
  }
  if (!/blockUninspectableToolResult/.test(sdk)) {
    throw new Error('MCP guard package must include the connector inspection fail-closed guard');
  }
  if (!/guardToolRequest/.test(sdk) || !/executeConnectorTool/.test(sdk)) {
    throw new Error('MCP guard package must include connector request-policy preflight');
  }

  const registry = files.find((file) => file.path === 'sensors/mcp-guard/connector-registry.js').body.toString('utf8');
  if (!/CONNECTOR_PROFILES/.test(registry) || !/connectorRegistryStatus/.test(registry) || !/connectorRegistryChecks/.test(registry)) {
    throw new Error('MCP guard package must include connector registry profiles and install checks');
  }

  const microsoft365 = files.find((file) => file.path === 'sensors/mcp-guard/connectors/microsoft365.js').body.toString('utf8');
  if (!/sanitizeDriveItemContent/.test(microsoft365) || !/createDriveItemContentTool/.test(microsoft365) || !/microsoft365ConnectorHealth/.test(microsoft365)) {
    throw new Error('MCP guard package must include Microsoft 365 connector sanitization and health helpers');
  }
  if (!/executeConnectorTool/.test(microsoft365)) {
    throw new Error('MCP guard package must include Microsoft 365 connector request-policy preflight');
  }

  const googleDrive = files.find((file) => file.path === 'sensors/mcp-guard/connectors/google-drive.js').body.toString('utf8');
  if (!/sanitizeDriveFileContent/.test(googleDrive) || !/createDriveFileContentTool/.test(googleDrive) || !/googleDriveConnectorHealth/.test(googleDrive)) {
    throw new Error('MCP guard package must include Google Drive connector sanitization and health helpers');
  }
  if (!/executeConnectorTool/.test(googleDrive)) {
    throw new Error('MCP guard package must include Google Drive connector request-policy preflight');
  }

  const slack = files.find((file) => file.path === 'sensors/mcp-guard/connectors/slack.js').body.toString('utf8');
  if (!/sanitizeConversationHistory/.test(slack) || !/createSlackConversationHistoryTool/.test(slack) || !/sanitizeSlackFileContent/.test(slack) || !/slackConnectorHealth/.test(slack)) {
    throw new Error('MCP guard package must include Slack connector sanitization and health helpers');
  }
  if (!/executeConnectorTool/.test(slack)) {
    throw new Error('MCP guard package must include Slack connector request-policy preflight');
  }

  const teams = files.find((file) => file.path === 'sensors/mcp-guard/connectors/teams.js').body.toString('utf8');
  if (!/sanitizeTeamsChannelMessages/.test(teams) || !/createTeamsChannelMessagesTool/.test(teams) || !/sanitizeTeamsChatMessages/.test(teams) || !/teamsConnectorHealth/.test(teams)) {
    throw new Error('MCP guard package must include Microsoft Teams connector sanitization and health helpers');
  }
  if (!/executeConnectorTool/.test(teams)) {
    throw new Error('MCP guard package must include Microsoft Teams connector request-policy preflight');
  }

  const atlassian = files.find((file) => file.path === 'sensors/mcp-guard/connectors/atlassian.js').body.toString('utf8');
  if (!/sanitizeJiraIssue/.test(atlassian) || !/createJiraIssueTool/.test(atlassian) || !/sanitizeConfluencePage/.test(atlassian) || !/atlassianConnectorHealth/.test(atlassian)) {
    throw new Error('MCP guard package must include Atlassian connector sanitization and health helpers');
  }
  if (!/executeConnectorTool/.test(atlassian)) {
    throw new Error('MCP guard package must include Atlassian connector request-policy preflight');
  }

  const databaseReadonly = files.find((file) => file.path === 'sensors/mcp-guard/connectors/database-readonly.js').body.toString('utf8');
  if (!/sanitizeDatabaseRows/.test(databaseReadonly) || !/createDatabaseReadonlyQueryTool/.test(databaseReadonly) || !/sanitizeDatabaseSchema/.test(databaseReadonly) || !/databaseReadonlyConnectorHealth/.test(databaseReadonly)) {
    throw new Error('MCP guard package must include database read-only connector sanitization and health helpers');
  }
  if (!/executeConnectorTool/.test(databaseReadonly)) {
    throw new Error('MCP guard package must include database read-only connector request-policy preflight');
  }

  const installCheck = files.find((file) => file.path === 'scripts/check-mcp-guard-install.js').body.toString('utf8');
  if (!/api\/v1\/heartbeat/.test(installCheck) || !/buildInstallReport/.test(installCheck) || !/INGEST_API_KEY/.test(installCheck) || !/connectorRegistryStatus/.test(installCheck)) {
    throw new Error('MCP guard package must include install validation with heartbeat support');
  }
  if (/contentBase64|readFileSync\(filePath|dev-ingest-key|524-71-9043|4111 1111 1111 1111/.test(installCheck)) {
    throw new Error('MCP guard install validation must not read file bodies, package development keys, or carry demo prompt bodies');
  }
}

function packageMcpGuard(opts = {}) {
  const root = opts.root || ROOT;
  const outDir = opts.outDir || DEFAULT_OUT_DIR;
  const now = opts.now || new Date();
  const appVersion = readJson(path.join(root, 'package.json')).version;
  const files = PACKAGE_FILES.map((relPath) => ({
    path: posixPath(relPath),
    body: runtimeBody(relPath, root),
  }));

  validateRuntimeFiles(files);

  fs.mkdirSync(outDir, { recursive: true });
  const baseName = `redactwall-mcp-guard-v${appVersion}`;
  const zipPath = path.join(outDir, `${baseName}.zip`);
  const manifestPath = path.join(outDir, `${baseName}.manifest.json`);
  const zip = new AdmZip();
  const packagedFiles = files.map((file) => {
    zip.addFile(file.path, file.body);
    return { path: file.path, sizeBytes: file.body.length, sha256: sha256(file.body) };
  });

  zip.writeZip(zipPath);
  const zipBody = fs.readFileSync(zipPath);
  const packageManifest = {
    kind: 'redactwall-mcp-guard-package',
    packageName: path.basename(zipPath),
    appVersion,
    createdAt: now.toISOString(),
    sha256: sha256(zipBody),
    sizeBytes: zipBody.length,
    files: packagedFiles.sort((a, b) => a.path.localeCompare(b.path)),
    checks: {
      explicitIngestKeyRequired: true,
      sharedEngineIncluded: true,
      boundedResponseReaderIncluded: true,
      signedPolicyVerifierIncluded: true,
      connectorSdkIncluded: true,
      connectorRegistryIncluded: true,
      microsoft365ConnectorIncluded: true,
      googleDriveConnectorIncluded: true,
      slackConnectorIncluded: true,
      teamsConnectorIncluded: true,
      atlassianConnectorIncluded: true,
      databaseReadonlyConnectorIncluded: true,
      databaseQueryWorkerIncluded: true,
      demoCodeExcluded: true,
      installValidationIncluded: true,
      developmentIngestKeyAbsent: true,
      promptBodiesAbsent: true,
    },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(packageManifest, null, 2) + '\n');
  return { zipPath, manifestPath, packageManifest };
}

function parseArgs(argv = process.argv.slice(2)) {
  const args = [...argv];
  let outDir = DEFAULT_OUT_DIR;
  while (args.length) {
    const arg = args.shift();
    if (arg === '--out') {
      outDir = path.resolve(args.shift() || '');
    } else if (arg === '--help' || arg === '-h') {
      return { help: true, outDir };
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      outDir = path.resolve(arg);
    }
  }
  return { outDir };
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const packageFn = deps.packageMcpGuard || packageMcpGuard;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  try {
    const args = parseArgs(argv);
    if (args.help) {
      io.log('Usage: node scripts/package-mcp-guard.js [--out <directory>]');
      return null;
    }
    const result = packageFn({ outDir: args.outDir });
    io.log(`Wrote ${result.zipPath}`);
    io.log(`Wrote ${result.manifestPath}`);
    io.log(`SHA-256 ${result.packageManifest.sha256}`);
    return result;
  } catch (err) {
    io.error(err.message || err);
    setExitCode(1);
    return null;
  }
}

if (require.main === module) main();

module.exports = {
  main,
  packageMcpGuard,
  parseArgs,
  runtimeBody,
  sha256,
  validateRuntimeFiles,
};
