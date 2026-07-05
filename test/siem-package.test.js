'use strict';
/** SIEM/SOAR integration packages must stay useful and sanitized. */
const test = require('node:test');
const assert = require('node:assert');
const AdmZip = require('adm-zip');

const siemPackage = require('../server/siem-package');

function packageText(pkg) {
  return JSON.stringify(pkg);
}

function assertSanitized(pkg) {
  const text = packageText(pkg);
  for (const banned of [
    '524-71-9043',
    'loan note summary',
    'Debug this deploy script',
    'AWS key',
    'unit-token',
    'sk-proj-',
    'contentBase64',
    'C:\\Users\\',
  ]) {
    assert.strictEqual(text.includes(banned), false, `package leaked ${banned}`);
  }
}

test('integration package includes all supported profiles with sanitized samples', () => {
  const pkg = siemPackage.integrationPackage({ generatedAt: '2026-07-04T12:00:00.000Z' });
  assert.strictEqual(pkg.schemaVersion, 1);
  assert.deepStrictEqual(pkg.supportedProfiles, ['splunk', 'sentinel', 'chronicle', 'servicenow']);
  assert.strictEqual(pkg.summary.profileCount, 4);
  assert.ok(pkg.summary.packageFiles >= 20);
  assert.deepStrictEqual(pkg.downloadFormats, ['json', 'zip']);
  assert.strictEqual(pkg.privacy.rawPromptBodies, false);
  assert.strictEqual(pkg.privacy.rawFindingValues, false);
  assertSanitized(pkg);
});

test('integration package emits marketplace-style files and a sanitized zip archive', () => {
  const pkg = siemPackage.integrationPackage({ profile: 'sentinel', generatedAt: '2026-07-04T12:00:00.000Z' });
  const files = siemPackage.packageFiles(pkg);
  assert.ok(files.some((file) => file.path === 'README.md' && /RedactWall SOC Integration Package/.test(file.body)));
  assert.ok(files.some((file) => file.path === 'manifest.json'));
  assert.ok(files.some((file) => file.path === 'privacy-contract.json'));
  assert.ok(files.some((file) => file.path === 'profiles/sentinel/sentinel-dcr-transform.kql'));
  assert.ok(files.some((file) => file.path === 'profiles/sentinel/sentinel-analytics-rules.json'));
  assert.ok(files.every((file) => !/^[A-Za-z]:\\|\/\/|^\.\./.test(file.path)), 'package file paths must be relative artifact paths');
  assertSanitized({ files });

  const zip = new AdmZip(siemPackage.packageArchive(pkg));
  const entries = zip.getEntries().map((entry) => entry.entryName).sort();
  assert.ok(entries.includes('README.md'));
  assert.ok(entries.includes('manifest.json'));
  assert.ok(entries.includes('profiles/sentinel/sentinel-dcr-transform.kql'));
  assert.ok(entries.includes('profiles/sentinel/sentinel-workbook-panels.json'));
  assert.match(zip.readAsText('manifest.json'), /"requestedProfile": "sentinel"/);
  assertSanitized({ entries, manifest: zip.readAsText('manifest.json'), readme: zip.readAsText('README.md') });
});

test('splunk profile emits HEC shape, sourcetypes, and SPL searches', () => {
  const pkg = siemPackage.integrationPackage({ profile: 'splunk', generatedAt: '2026-07-04T12:00:00.000Z' });
  assert.strictEqual(pkg.profiles.length, 1);
  const profile = pkg.profiles[0];
  assert.strictEqual(profile.id, 'splunk');
  assert.strictEqual(profile.transport.endpointPath, '/services/collector/event');
  assert.ok(profile.transport.sourcetypes.includes('redactwall:security'));
  assert.ok(profile.savedSearches.some((item) => item.spl.includes('sourcetype=redactwall:security')));
  assert.ok(profile.samplePayloads[0].payload.event.eventType === 'redactwall.security_event');
  assertSanitized(pkg);
});

test('sentinel profile includes DCR transform hint, custom table, and KQL', () => {
  const pkg = siemPackage.integrationPackage({ profile: 'sentinel', generatedAt: '2026-07-04T12:00:00.000Z' });
  const profile = pkg.profiles[0];
  assert.strictEqual(profile.id, 'sentinel');
  assert.strictEqual(profile.transport.customTable, 'RedactWall_CL');
  assert.match(profile.transformKql, /project-away rawPrompt/);
  assert.ok(profile.savedSearches.some((item) => item.kql.includes('RedactWall_CL')));
  assert.ok(profile.fieldMappings.some((item) => item.commonSecurityLog === 'DeviceAction'));
  assertSanitized(pkg);
});

test('chronicle profile maps RedactWall events into UDM fields', () => {
  const pkg = siemPackage.integrationPackage({ profile: 'chronicle', generatedAt: '2026-07-04T12:00:00.000Z' });
  const profile = pkg.profiles[0];
  assert.strictEqual(profile.id, 'chronicle');
  assert.ok(profile.fieldMappings.some((item) => item.udm === 'security_result.action'));
  assert.strictEqual(profile.samplePayloads[0].payload.metadata.vendor_name, 'RedactWall');
  assert.strictEqual(profile.samplePayloads[0].payload.security_result[0].action, 'BLOCK');
  assertSanitized(pkg);
});

test('servicenow profile includes incident mapping without credentials', () => {
  const pkg = siemPackage.integrationPackage({ profile: 'servicenow', generatedAt: '2026-07-04T12:00:00.000Z' });
  const profile = pkg.profiles[0];
  assert.strictEqual(profile.id, 'servicenow');
  assert.strictEqual(profile.transport.endpointPath, '/api/now/table/incident');
  assert.ok(profile.fieldMappings.some((item) => item.servicenow === 'correlation_id'));
  assert.ok(profile.incidentTemplates.some((item) => item.record.category === 'security'));
  assertSanitized(pkg);
});

test('unsupported profile is rejected without echoing the requested value', () => {
  assert.throws(
    () => siemPackage.integrationPackage({ profile: 'member-524-71-9043' }),
    (err) => err && err.code === 'UNSUPPORTED_PROFILE' && !String(err.message).includes('524-71-9043'),
  );
});
