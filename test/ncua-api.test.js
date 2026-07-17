'use strict';
/** NCUA Readiness route: auth, entitlement gating, and examiner-pack export. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-ncua-api-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-ncua-api-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
}, null, 2));

const app = require('../server/app');
const { listen } = require('./support/listen');
const license = require('../server/license');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }).toString();

function signLicense(payload) {
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const sig = crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64');
  return `${b64}.${sig}`;
}

function setLicense(payload) {
  license.refresh({
    publicKeyPem: PUB,
    expectedCustomerId: 'cu-1',
    readFile: () => {
      if (!payload) throw new Error('missing');
      return signLicense(payload);
    },
  });
}

const STANDARD_NO_ADDON = {
  customer: 'Test CU', customerId: 'cu-1', plan: 'standard', seats: 50,
  features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z',
};

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
    setLicense(null); // back to demo mode for whatever runs next
  }
}

async function login(port, user, password) {
  const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user, password }),
  });
  assert.strictEqual(res.status, 200);
  return (res.headers.get('set-cookie') || '').split(';')[0];
}

test('ncua readiness requires an authenticated console session', async () => {
  await withServer(async (port) => {
    const res = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`);
    assert.strictEqual(res.status, 401);
  });
});

test('ncua readiness returns the full report in demo mode for admin and auditor', async () => {
  await withServer(async (port) => {
    setLicense(null); // unlicensed = demo mode = entitled
    for (const [user, password] of [['admin', 'unit-pass'], ['auditor', 'auditor-pass']]) {
      const cookie = await login(port, user, password);
      const res = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie } });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.entitled, true);
      assert.strictEqual(body.report.profile, 'federal_credit_union');
      assert.ok(Number.isFinite(body.report.score));
      assert.ok(Array.isArray(body.report.controls));
      assert.ok(body.report.panels.audit.verified);
      const wire = JSON.stringify(body);
      assert.ok(!wire.includes('"salt"'));
      assert.ok(!wire.includes('"notes"'));
    }
  });
});

test('licensed install without the add-on gets entitled=false and no report', async () => {
  await withServer(async (port) => {
    setLicense(STANDARD_NO_ADDON);
    const cookie = await login(port, 'admin', 'unit-pass');
    const res = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie } });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(await res.json(), { entitled: false, report: null });

    setLicense({ ...STANDARD_NO_ADDON, features: ['ncua_readiness'] });
    const granted = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie } });
    const body = await granted.json();
    assert.strictEqual(body.entitled, true);
    assert.strictEqual(body.report.profile, 'federal_credit_union');
  });
});

test('examiner-profile export stamps schemaVersion 3; default export stays 2', async () => {
  await withServer(async (port) => {
    const cookie = await login(port, 'auditor', 'auditor-pass');
    const profiled = await fetch(
      `http://127.0.0.1:${port}/api/export/evidence?examinerProfile=federal_credit_union`,
      { headers: { cookie } },
    );
    assert.strictEqual(profiled.status, 200);
    const pack = await profiled.json();
    assert.strictEqual(pack.schemaVersion, 3);
    assert.strictEqual(pack.scope.examinerProfile, 'federal_credit_union');
    assert.strictEqual(pack.scope.rawPromptBodiesIncluded, false);
    assert.strictEqual(pack.ncuaReadiness.profile, 'federal_credit_union');

    const plain = await fetch(`http://127.0.0.1:${port}/api/export/evidence`, { headers: { cookie } });
    const plainPack = await plain.json();
    assert.strictEqual(plainPack.schemaVersion, 2);
    assert.strictEqual(plainPack.scope.examinerProfile, undefined);
    assert.strictEqual(plainPack.ncuaReadiness, undefined);
  });
});

async function adminSession(port) {
  const cookie = await login(port, 'admin', 'unit-pass');
  const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
  const { csrfToken } = await csrfRes.json();
  return { cookie, csrfToken };
}

function postJson(port, apiPath, { cookie, csrfToken }, body) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', cookie, 'x-csrf-token': csrfToken },
    body: JSON.stringify(body),
  });
}

test('use-case inventory: create, list, review, and prompt-free audit detail', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    const created = await postJson(port, '/api/ncua/use-cases', session, {
      destination: 'chat.openai.com',
      department: 'Lending',
      owner: 'j.smith@cu.test',
      approvedUse: 'Draft member letters with synthetic data only',
      allowedDataClasses: ['MEMBER_ID', 'LOAN_NUMBER'],
      vendorStatus: 'pending',
      nextReviewAt: '2027-01-01T00:00:00Z',
    });
    assert.strictEqual(created.status, 200);
    const { useCase } = await created.json();
    assert.strictEqual(useCase.canonicalHost, 'chat.openai.com');
    assert.strictEqual(useCase.reviewStatus, 'under_review');

    // Same host + different department = a distinct record.
    const marketing = await postJson(port, '/api/ncua/use-cases', session, {
      destination: 'chat.openai.com',
      department: 'Marketing',
    });
    assert.strictEqual(marketing.status, 200);

    const listRes = await fetch(`http://127.0.0.1:${port}/api/ncua/use-cases`, { headers: { cookie: session.cookie } });
    const listed = await listRes.json();
    assert.strictEqual(listed.entitled, true);
    assert.strictEqual(listed.useCases.length, 2);

    const review = await postJson(port, `/api/ncua/use-cases/${useCase.id}/review`, session, {
      reviewStatus: 'approved',
      vendorStatus: 'reviewed',
      nextReviewAt: '2027-06-01T00:00:00Z',
    });
    assert.strictEqual(review.status, 200);
    assert.strictEqual((await review.json()).useCase.reviewStatus, 'approved');

    // The audit trail records enums/counts only — never the operator's text.
    const audit = require('../server/db').listAudit(50);
    const entries = audit.filter((e) => ['USE_CASE_UPDATED', 'USE_CASE_REVIEWED'].includes(e.action));
    assert.ok(entries.length >= 3);
    for (const entry of entries) {
      assert.ok(!String(entry.detail || '').includes('Draft member letters'));
      assert.ok(!String(entry.detail || '').includes('j.smith'));
    }
  });
});

test('use-case validation rejects paths, prompt text, and unknown data classes', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    const cases = [
      { destination: 'chat.openai.com/share/abc', department: 'Lending' },
      { destination: 'chat.openai.com', department: 'Lending', approvedUse: 'line one\nline two of pasted prompt' },
      { destination: 'chat.openai.com', department: 'Lending', approvedUse: 'member 524-71-9043 loan file' },
      { destination: 'chat.openai.com', department: 'Lending', allowedDataClasses: ['NOT_A_DETECTOR'] },
      { destination: 'chat.openai.com', department: 'Lending', approvedUse: 'see https://evil.test/exfil' },
    ];
    for (const body of cases) {
      const res = await postJson(port, '/api/ncua/use-cases', session, body);
      assert.strictEqual(res.status, 400, JSON.stringify(body));
      const parsed = await res.json();
      const wire = JSON.stringify(parsed);
      assert.ok(!wire.includes('524-71-9043')); // field names only, never values
    }
  });
});

test('use-case mutations require CSRF and entitlement; reads hide records when unentitled', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    const noCsrf = await fetch(`http://127.0.0.1:${port}/api/ncua/use-cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', cookie: session.cookie },
      body: JSON.stringify({ destination: 'claude.ai', department: 'IT' }),
    });
    assert.strictEqual(noCsrf.status, 403);

    setLicense(STANDARD_NO_ADDON);
    const blocked = await postJson(port, '/api/ncua/use-cases', session, { destination: 'claude.ai', department: 'IT' });
    assert.strictEqual(blocked.status, 403);
    const listRes = await fetch(`http://127.0.0.1:${port}/api/ncua/use-cases`, { headers: { cookie: session.cookie } });
    assert.deepStrictEqual(await listRes.json(), { entitled: false, useCases: [] });
    setLicense(null);
  });
});

test('auditor cannot mutate use cases', async () => {
  await withServer(async (port) => {
    const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: 'auditor', password: 'auditor-pass' }),
    });
    const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
    const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
    const { csrfToken } = await csrfRes.json();
    const attempt = await fetch(`http://127.0.0.1:${port}/api/ncua/use-cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', cookie, 'x-csrf-token': csrfToken },
      body: JSON.stringify({ destination: 'claude.ai', department: 'IT' }),
    });
    assert.strictEqual(attempt.status, 403);
  });
});

test('use-case upsert preserves review evidence and dedupes department variants', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    const created = await postJson(port, '/api/ncua/use-cases', session, {
      destination: 'gemini.google.com',
      department: 'Collections',
      owner: 'c.jones@cu.test',
      approvedUse: 'Summarize hardship letters with synthetic data',
      allowedDataClasses: ['MEMBER_ID'],
      nextReviewAt: '2027-03-01',
    });
    const { useCase } = await created.json();
    await postJson(port, `/api/ncua/use-cases/${useCase.id}/review`, session, {
      reviewStatus: 'approved',
      vendorStatus: 'reviewed',
    });

    // Partial re-POST (different owner, whitespace/case department variant):
    // must update the SAME record and keep every unsent field intact.
    const repost = await postJson(port, '/api/ncua/use-cases', session, {
      destination: 'gemini.google.com',
      department: '  collections ',
      owner: 'new.owner@cu.test',
    });
    assert.strictEqual(repost.status, 200);
    const merged = (await repost.json()).useCase;
    assert.strictEqual(merged.id, useCase.id);
    assert.strictEqual(merged.owner, 'new.owner@cu.test');
    assert.strictEqual(merged.reviewStatus, 'approved');
    assert.strictEqual(merged.vendorStatus, 'reviewed');
    assert.strictEqual(merged.approvedUse, 'Summarize hardship letters with synthetic data');
    assert.deepStrictEqual(merged.allowedDataClasses, ['MEMBER_ID']);
    assert.strictEqual(merged.nextReviewAt, '2027-03-01');

    const rows = (await (await fetch(`http://127.0.0.1:${port}/api/ncua/use-cases`, { headers: { cookie: session.cookie } })).json()).useCases;
    assert.strictEqual(rows.filter((r) => r.canonicalHost === 'gemini.google.com').length, 1);
  });
});

test('review of an unknown use-case id returns 404; date fields reject V8 date comments', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    const missing = await postJson(port, '/api/ncua/use-cases/uc_missing/review', session, { reviewStatus: 'retired' });
    assert.strictEqual(missing.status, 404);

    // V8's lenient Date.parse accepts parenthesized "comments" — an SSN-shaped
    // string must not ride a date field into the audit log.
    const smuggled = await postJson(port, '/api/ncua/use-cases', session, {
      destination: 'claude.ai',
      department: 'IT',
      nextReviewAt: '2027-01-01 (078-05-1120)',
    });
    assert.strictEqual(smuggled.status, 400);
    const ssnHost = await postJson(port, '/api/ncua/use-cases', session, {
      destination: '078051120123.example.com',
      department: 'IT',
    });
    assert.strictEqual(ssnHost.status, 400);
  });
});

test('incident workflow: derived prompt-free timeline, 72h deadline, status flow', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    // Seed a real held member-data event through the gate.
    const gate = await fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': 'unit-ingest-key' },
      body: JSON.stringify({
        prompt: 'Synthetic member John Carter SSN 524-71-9043 exported to chat',
        user: 'teller@cu.test',
        destination: 'chat.openai.com',
        source: 'browser_extension',
        channel: 'submit',
      }),
    });
    assert.strictEqual(gate.status, 200);
    const held = await gate.json();
    assert.ok(held.id);

    const opened = await postJson(port, '/api/ncua/incidents', session, {
      title: 'Possible member-data exposure via browser paste',
      queryIds: [held.id, 'q_unknown_ignored'],
      detectedAt: '2026-07-08T00:00:00Z',
    });
    assert.strictEqual(opened.status, 200);
    const { incident } = await opened.json();
    assert.strictEqual(incident.status, 'open');
    assert.strictEqual(incident.deadlineAt, '2026-07-11T00:00:00.000Z');
    assert.strictEqual(incident.timeline.length, 1);
    assert.strictEqual(incident.timeline[0].prevented, true);
    assert.ok(incident.timeline[0].dataClasses.includes('US_SSN'));

    // The wire never carries the raw prompt or the raw SSN.
    const list = await fetch(`http://127.0.0.1:${port}/api/ncua/incidents`, { headers: { cookie: session.cookie } });
    const wire = JSON.stringify(await list.json());
    assert.ok(!wire.includes('524-71-9043'));
    assert.ok(!wire.includes('John Carter'));

    const reported = await postJson(port, `/api/ncua/incidents/${incident.id}/status`, session, { status: 'reported' });
    assert.strictEqual((await reported.json()).incident.status, 'reported');
    assert.ok((await (await fetch(`http://127.0.0.1:${port}/api/ncua/incidents`, { headers: { cookie: session.cookie } })).json())
      .incidents.every((i) => i.detectedAt === '2026-07-08T00:00:00.000Z'));

    const missing = await postJson(port, '/api/ncua/incidents/inc_missing/status', session, { status: 'closed' });
    assert.strictEqual(missing.status, 404);

    // Audit details stay enum/date/count-shaped.
    const audit = require('../server/db').listAudit(50).filter((e) => e.action && e.action.startsWith('INCIDENT_'));
    assert.ok(audit.length >= 2);
    for (const entry of audit) {
      assert.ok(!String(entry.detail || '').includes('member-data exposure'));
    }
  });
});

test('board packet: auditor POST with CSRF, seat aggregates only, cadence control flips covered', async () => {
  await withServer(async (port) => {
    const auditorCookie = await login(port, 'auditor', 'auditor-pass');
    const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie: auditorCookie } });
    const { csrfToken } = await csrfRes.json();

    // Generation is state-changing (it feeds the cadence control): a plain
    // GET or a CSRF-less POST must never mint board-reporting evidence.
    assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/ncua/board-packet`, { headers: { cookie: auditorCookie } })).status, 404);
    assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/ncua/board-packet`, { method: 'POST', headers: { cookie: auditorCookie } })).status, 403);

    const res = await fetch(`http://127.0.0.1:${port}/api/ncua/board-packet`, {
      method: 'POST',
      headers: { cookie: auditorCookie, 'x-csrf-token': csrfToken },
    });
    assert.strictEqual(res.status, 200);
    const packet = await res.json();
    assert.ok(Number.isFinite(packet.readiness.score));
    assert.ok(packet.seats.trueUp);
    assert.strictEqual(packet.seats.users, undefined); // never the roster
    const wire = JSON.stringify(packet);
    assert.ok(!wire.includes('"users"'));

    // The audit record stays enum/count-shaped.
    const auditEntry = require('../server/db').listAudit(20).find((e) => e.action === 'BOARD_PACKET_EXPORTED');
    assert.match(String(auditEntry.detail), /^score=\d+; state=[a-z]+$/);

    // Generation is recorded, so board_reporting grades covered on next read.
    const adminCookie = await login(port, 'admin', 'unit-pass');
    const readiness = await (await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie: adminCookie } })).json();
    const control = readiness.report.controls.find((c) => c.id === 'board_reporting');
    assert.strictEqual(control.state, 'covered');
  });
});

test('72h deadline is timezone-deterministic, future-clamped, and reportedAt is immutable', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    // A zoneless datetime must be treated as UTC, not server-local time.
    const zoneless = await postJson(port, '/api/ncua/incidents', session, {
      title: 'Zoneless detection time',
      detectedAt: '2026-07-01T00:00',
    });
    const inc1 = (await zoneless.json()).incident;
    assert.strictEqual(inc1.detectedAt, '2026-07-01T00:00:00.000Z');
    assert.strictEqual(inc1.deadlineAt, '2026-07-04T00:00:00.000Z');

    // A future-dated detection cannot push the deadline out of overdue reach.
    const future = await postJson(port, '/api/ncua/incidents', session, {
      title: 'Future-dated detection',
      detectedAt: '2999-01-01T00:00:00Z',
    });
    const inc2 = (await future.json()).incident;
    assert.ok(Date.parse(inc2.detectedAt) <= Date.now());

    // reportedAt only lands via the 'reported' transition and the first
    // stamp is permanent — a late report cannot be rewritten as on-time.
    const sneak = await postJson(port, `/api/ncua/incidents/${inc1.id}/status`, session, {
      status: 'under_review',
      reportedAt: '2026-07-02T00:00:00Z',
    });
    assert.strictEqual((await sneak.json()).incident.reportedAt ?? null, null);
    await postJson(port, `/api/ncua/incidents/${inc1.id}/status`, session, { status: 'reported' });
    const first = (await (await fetch(`http://127.0.0.1:${port}/api/ncua/incidents`, { headers: { cookie: session.cookie } })).json())
      .incidents.find((i) => i.id === inc1.id);
    const rewrite = await postJson(port, `/api/ncua/incidents/${inc1.id}/status`, session, {
      status: 'closed',
      reportedAt: '2026-07-01T01:00:00Z',
    });
    const closed = (await rewrite.json()).incident;
    assert.strictEqual(closed.reportedAt, first.reportedAt);
    // Status patches preserve every other field.
    assert.strictEqual(closed.title, 'Zoneless detection time');
    assert.strictEqual(closed.detectedAt, inc1.detectedAt);
    assert.strictEqual(closed.deadlineAt, inc1.deadlineAt);
  });
});

test('incident and board-packet routes respect the entitlement gate', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);
    setLicense(STANDARD_NO_ADDON);
    const blocked = await postJson(port, '/api/ncua/incidents', session, { title: 'Should not open' });
    assert.strictEqual(blocked.status, 403);
    const packet = await fetch(`http://127.0.0.1:${port}/api/ncua/board-packet`, {
      method: 'POST',
      headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken },
    });
    assert.strictEqual(packet.status, 403);
    const training = await postJson(port, '/api/ncua/board-training', session, { trainingCompletedAt: '2026-07-01' });
    assert.strictEqual(training.status, 403);
    const list = await fetch(`http://127.0.0.1:${port}/api/ncua/incidents`, { headers: { cookie: session.cookie } });
    assert.deepStrictEqual(await list.json(), { entitled: false, incidents: [] });
    setLicense(null);
  });
});

test('board training attestation: CSRF-gated, admin-only, audit is JSON date+reference, control reflects it', async () => {
  await withServer(async (port) => {
    const session = await adminSession(port);

    // CSRF-less POST is rejected.
    assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/ncua/board-training`, { method: 'POST', headers: { cookie: session.cookie } })).status, 403);

    // The read-only AUDITOR role cannot attest an external fact.
    const auditorCookie = await login(port, 'auditor', 'auditor-pass');
    const auditorCsrf = (await (await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie: auditorCookie } })).json()).csrfToken;
    const auditorPost = await postJson(port, '/api/ncua/board-training', { cookie: auditorCookie, csrfToken: auditorCsrf }, { trainingCompletedAt: '2026-07-01' });
    assert.strictEqual(auditorPost.status, 403);

    // A malformed date is rejected by the schema.
    const bad = await postJson(port, '/api/ncua/board-training', session, { trainingCompletedAt: 'not-a-date' });
    assert.strictEqual(bad.status, 400);

    // Contact-detail references (emails, phone-length digit runs) are rejected
    // before they can reach the append-only audit chain.
    for (const reference of ['jane.doe@example.com', 'call 512-555-1234']) {
      const pii = await postJson(port, '/api/ncua/board-training', session, { trainingCompletedAt: '2026-07-01', reference });
      assert.strictEqual(pii.status, 400);
    }

    // A valid attestation records date + reference.
    const res = await postJson(port, '/api/ncua/board-training', session, { trainingCompletedAt: '2026-07-01', reference: 'Board minutes 2026-Q2' });
    assert.strictEqual(res.status, 200);
    const stored = await res.json();
    assert.strictEqual(stored.trainingCompletedAt, '2026-07-01');
    assert.strictEqual(stored.reference, 'Board minutes 2026-Q2');
    assert.ok(stored.attestedAt);

    // The audit entry is JSON date+reference shaped; no prompt/PII.
    const entry = require('../server/db').listAudit(20).find((e) => e.action === 'BOARD_TRAINING_ATTESTED');
    assert.ok(entry);
    assert.deepStrictEqual(JSON.parse(entry.detail), { trainingCompletedAt: '2026-07-01', reference: 'Board minutes 2026-Q2' });

    // The board_reporting control surfaces the attestation on next read.
    const adminCookie = await login(port, 'admin', 'unit-pass');
    const readiness = await (await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie: adminCookie } })).json();
    const control = readiness.report.controls.find((c) => c.id === 'board_reporting');
    assert.match(control.summary, /Board cybersecurity training attested \(completed 2026-07-01/);
  });
});
