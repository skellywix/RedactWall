'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');

function source(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function section(body, start, end) {
  const from = body.indexOf(start);
  const to = body.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, `expected source section ${start} ... ${end}`);
  return body.slice(from, to);
}

test('shell posture freshness never advances from stats-only updates', () => {
  const shell = source('console/src/lib/shell.ts');
  const refresh = section(shell, 'const refresh = useCallback', 'const onStats = useCallback');
  const onStats = section(shell, 'const onStats = useCallback', 'useEffect(() =>');

  assert.doesNotMatch(refresh, /setLastUpdated\s*\(/);
  assert.doesNotMatch(onStats, /setLastUpdated\s*\(/);
  assert.match(shell, /import \{ fetchPostureResult, type PostureSurface \} from '\.\.\/api\/posture'/);
  assert.match(shell, /const result = await fetchPostureResult\(\)/);
  assert.match(shell, /!result\.ok \|\| !Array\.isArray\(result\.report\.surfaces\)/);
  assert.doesNotMatch(shell, /\bfetchPosture\(/);
  assert.match(shell, /useState<LiveState>\('reconnecting'\)/);
  assert.match(shell, /setPostureState\(hasPostureRef\.current \? 'stale' : 'unavailable'\)/);
  assert.strictEqual((shell.match(/setLastUpdated\s*\(/g) || []).length, 1, 'only verified posture may advance freshness');
});

test('rail exposes posture stale and unavailable states without current-safe claims', () => {
  const rail = source('console/src/components/NavRail.tsx');
  const app = source('console/src/App.tsx');

  assert.match(rail, /label: 'LAST VERIFIED'/);
  assert.match(rail, /label: 'UNAVAILABLE'/);
  assert.match(rail, /current status is unknown/);
  assert.match(rail, /aria-label=\{chip\.detail\}/);
  assert.match(app, /postureState=\{shell\.postureState\}/);
  assert.match(app, /postureUpdatedAt=\{shell\.lastUpdated\}/);
});

test('sign out redirects only after the logout route succeeds', () => {
  const app = source('console/src/App.tsx');
  const signOut = section(app, 'async function signOut()', '// Keep palette theme changes');

  assert.match(signOut, /allowAuthError: true/);
  assert.match(signOut, /response\?\.status === 401/);
  assert.match(signOut, /await apiErrorSummary\(response, ''\)/);
  assert.match(signOut, /if \(!response\?\.ok\)/);
  assert.match(signOut, /Your current session remains open/);
  const failureBranch = signOut.indexOf('if (!response?.ok)');
  const failureReturn = signOut.indexOf('return;', failureBranch);
  const successRedirect = signOut.lastIndexOf("window.location.href = '/login.html'");
  assert.ok(failureBranch >= 0 && failureBranch < failureReturn && failureReturn < successRedirect);
});

test('activity sequences snapshots against SSE and renders stale evidence explicitly', () => {
  const activity = source('console/src/views/Activity.tsx');
  const rowsHook = section(activity, 'function useActivityRows()', 'function useActivityTable');

  assert.match(rowsHook, /requestId !== requestRef\.current/);
  assert.match(rowsHook, /event\.sequence > startedAtSequence/);
  assert.match(rowsHook, /mergeActivityRows\(next, laterEvents\)/);
  assert.match(rowsHook, /setState\(rowsRef\.current \? 'stale' : 'unavailable'\)/);
  assert.match(rowsHook, /current === 'unavailable' \? 'stale' : current/);
  assert.doesNotMatch(rowsHook, /next \?\? prev/);
  assert.match(activity, /Showing verified activity received so far; current events may be missing/);
  assert.match(activity, /No current empty-state conclusion can be drawn/);
});

test('evidence decoder accepts findings whose mask was privacy-omitted by the server', () => {
  const audit = source('console/src/api/audit.ts');
  // sanitizeClientMask() deliberately drops missing/still-sensitive masks; the
  // decoder must treat an absent `masked` as valid, never voiding the pack.
  assert.match(audit, /item\.masked === undefined \|\| boundedTextValue\(item\.masked, 240\)/);
});

test('query audit history distinguishes complete empty, bounded-window empty, unavailable, loading, and entries', () => {
  const audit = source('console/src/api/audit.ts');
  const detail = source('console/src/components/queue/QueueDetail.tsx');

  assert.match(audit, /kind: 'verified'; entries: AuditEntry\[\]; window: AuditWindow/);
  assert.match(audit, /total !== integrity\.count/);
  assert.match(audit, /integrity\.ok && scanned > total/);
  assert.match(audit, /matched > scanned/);
  assert.match(audit, /row\.complete !== complete/);
  assert.match(audit, /kind: 'unavailable'; reason:/);
  assert.match(audit, /entry\.queryId !== queryId/);
  assert.match(audit, /'checkpoint-unavailable'/);
  assert.match(audit, /'pending-missing'/);
  assert.match(detail, /Loading verified audit history/);
  assert.match(detail, /complete retained audit set has no entries/);
  assert.match(detail, /verified recent window; older entries may exist/);
  assert.match(detail, /matching entries (?:found in|from) the verified recent window/);
  assert.match(detail, /Audit history is unavailable or malformed/);
  assert.match(detail, /<QueryAuditTrail key=\{query\.id\}/);
});

test('successful mutation responses are verified before the UI claims completion', () => {
  const policy = source('console/src/views/Policy.tsx');
  const policyApi = source('console/src/api/policy.ts');
  const identity = source('console/src/views/Identity.tsx');
  const licensing = source('console/src/views/Licensing.tsx');
  const monitor = source('console/src/views/Monitor.tsx');

  assert.match(policy, /Save response could not be verified\. Reload policy before making another change\./);
  assert.match(policy, /policyMatchesCoreUpdate\(saved, body\)/);
  assert.match(policy, /Template may have been applied, but the response could not be verified\./);
  assert.match(policy, /readPolicyImpactResponse\(impactRes\)/);
  assert.doesNotMatch(policy, /responseJsonBounded<PolicyImpact>/);
  assert.match(policy, /Purge completed, but the result could not be verified\./);
  assert.doesNotMatch(policy, /Purged \$\{body\.purged \|\| 0\}/);
  assert.match(policyApi, /export function decodePolicy\(value: unknown\): Policy \| null/);
  assert.match(policyApi, /MANDATORY_ALWAYS_BLOCK\.every/);
  assert.match(policyApi, /export function decodePolicyTemplates\(value: unknown\): PolicyTemplate\[\] \| null/);
  assert.match(policyApi, /export function decodePolicyImpact\(value: unknown\): PolicyImpact \| null/);
  assert.match(policyApi, /total === sampleSize \? counts : null/);
  assert.match(identity, /Invite response could not be verified\. Refresh invitations before retrying\./);
  assert.match(licensing, /Renewal may have been created, but the response could not be verified\./);
  assert.match(monitor, /responseBytesBounded\(response, SIEM_ZIP_MAX_BYTES\)/);
  assert.match(monitor, /validZipArchive\(bytes\)/);
  const snapshot = section(monitor, 'function useSocSnapshot', 'type VerdictState');
  const nonOk = snapshot.indexOf('if (!response?.ok)');
  const cachedError = snapshot.indexOf("apiErrorSummary(response, 'request failed')");
  const successBody = snapshot.indexOf('decodeSocNotifyResponse(await responseJsonBounded<unknown>');
  assert.ok(nonOk >= 0 && nonOk < cachedError && cachedError < successBody,
    'non-ok notification responses must use the cached API error before parsing a success body');
  assert.match(snapshot, /body\?\.sent === true && response\.status === 200/);
  assert.match(snapshot, /body\?\.sent === false && response\.status === 202/);
});
