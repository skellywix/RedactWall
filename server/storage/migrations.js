'use strict';
/**
 * Ordered schema migrations for the control-plane store.
 *
 * Each migration ships both dialects so the same history produces the same
 * schema on SQLite (default, single-node) and Postgres (scale-out). Databases
 * created before this framework existed are stamped at the baseline version
 * without re-executing it.
 */

const MIGRATIONS = [
  {
    version: 1,
    name: 'baseline',
    sqlite: `
      CREATE TABLE IF NOT EXISTS queries (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        id         TEXT UNIQUE NOT NULL,
        createdAt  TEXT NOT NULL,
        status     TEXT NOT NULL,
        user       TEXT,
        data       TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_queries_status ON queries(status);
      CREATE INDEX IF NOT EXISTS idx_queries_created ON queries(createdAt);

      CREATE TABLE IF NOT EXISTS audit (
        seq       INTEGER PRIMARY KEY AUTOINCREMENT,
        id        TEXT UNIQUE NOT NULL,
        ts        TEXT NOT NULL,
        action    TEXT,
        queryId   TEXT,
        actor     TEXT,
        prevHash  TEXT NOT NULL,
        hash      TEXT NOT NULL,
        entry     TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_query ON audit(queryId);

      CREATE TABLE IF NOT EXISTS scim_users (
        seq       INTEGER PRIMARY KEY AUTOINCREMENT,
        id        TEXT UNIQUE NOT NULL,
        userName  TEXT UNIQUE NOT NULL,
        active    INTEGER NOT NULL DEFAULT 1,
        createdAt TEXT NOT NULL,
        updatedAt TEXT NOT NULL,
        data      TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scim_users_username ON scim_users(userName);

      CREATE TABLE IF NOT EXISTS scim_groups (
        seq         INTEGER PRIMARY KEY AUTOINCREMENT,
        id          TEXT UNIQUE NOT NULL,
        displayName TEXT UNIQUE NOT NULL,
        createdAt   TEXT NOT NULL,
        updatedAt   TEXT NOT NULL,
        data        TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scim_groups_display ON scim_groups(displayName);

      CREATE TABLE IF NOT EXISTS ai_apps (
        seq           INTEGER PRIMARY KEY AUTOINCREMENT,
        id            TEXT UNIQUE NOT NULL,
        canonicalHost TEXT UNIQUE NOT NULL,
        firstSeen     TEXT NOT NULL,
        lastSeen      TEXT NOT NULL,
        data          TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ai_apps_host ON ai_apps(canonicalHost);

      CREATE TABLE IF NOT EXISTS deliveries (
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,
        id           TEXT UNIQUE NOT NULL,
        ts           TEXT NOT NULL,
        destId       TEXT NOT NULL,
        dedupeKey    TEXT NOT NULL,
        status       TEXT NOT NULL,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_deliveries_dest ON deliveries(destId);
      CREATE INDEX IF NOT EXISTS idx_deliveries_dedupe ON deliveries(destId, dedupeKey);

      CREATE TABLE IF NOT EXISTS detector_feedback (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        id         TEXT UNIQUE NOT NULL,
        createdAt  TEXT NOT NULL,
        queryId    TEXT NOT NULL,
        detectorId TEXT NOT NULL,
        verdict    TEXT NOT NULL,
        actor      TEXT,
        data       TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_detector_feedback_query ON detector_feedback(queryId);
      CREATE INDEX IF NOT EXISTS idx_detector_feedback_detector ON detector_feedback(detectorId);
      CREATE INDEX IF NOT EXISTS idx_detector_feedback_verdict ON detector_feedback(verdict);

      CREATE TABLE IF NOT EXISTS identity_revocations (
        identity  TEXT PRIMARY KEY,
        revokedAt INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS mfa_recovery_used (
        codeIndex INTEGER PRIMARY KEY,
        usedAt    TEXT NOT NULL
      );
    `,
    postgres: `
      CREATE TABLE IF NOT EXISTS queries (
        seq          BIGSERIAL PRIMARY KEY,
        id           TEXT UNIQUE NOT NULL,
        "createdAt"  TEXT NOT NULL,
        status       TEXT NOT NULL,
        "user"       TEXT,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_queries_status ON queries(status);
      CREATE INDEX IF NOT EXISTS idx_queries_created ON queries("createdAt");

      CREATE TABLE IF NOT EXISTS audit (
        seq        BIGSERIAL PRIMARY KEY,
        id         TEXT UNIQUE NOT NULL,
        ts         TEXT NOT NULL,
        action     TEXT,
        "queryId"  TEXT,
        actor      TEXT,
        "prevHash" TEXT NOT NULL,
        hash       TEXT NOT NULL,
        entry      TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_query ON audit("queryId");

      CREATE TABLE IF NOT EXISTS scim_users (
        seq         BIGSERIAL PRIMARY KEY,
        id          TEXT UNIQUE NOT NULL,
        "userName"  TEXT UNIQUE NOT NULL,
        active      INTEGER NOT NULL DEFAULT 1,
        "createdAt" TEXT NOT NULL,
        "updatedAt" TEXT NOT NULL,
        data        TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scim_users_username ON scim_users("userName");

      CREATE TABLE IF NOT EXISTS scim_groups (
        seq           BIGSERIAL PRIMARY KEY,
        id            TEXT UNIQUE NOT NULL,
        "displayName" TEXT UNIQUE NOT NULL,
        "createdAt"   TEXT NOT NULL,
        "updatedAt"   TEXT NOT NULL,
        data          TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scim_groups_display ON scim_groups("displayName");

      CREATE TABLE IF NOT EXISTS ai_apps (
        seq             BIGSERIAL PRIMARY KEY,
        id              TEXT UNIQUE NOT NULL,
        "canonicalHost" TEXT UNIQUE NOT NULL,
        "firstSeen"     TEXT NOT NULL,
        "lastSeen"      TEXT NOT NULL,
        data            TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ai_apps_host ON ai_apps("canonicalHost");

      CREATE TABLE IF NOT EXISTS deliveries (
        seq         BIGSERIAL PRIMARY KEY,
        id          TEXT UNIQUE NOT NULL,
        ts          TEXT NOT NULL,
        "destId"    TEXT NOT NULL,
        "dedupeKey" TEXT NOT NULL,
        status      TEXT NOT NULL,
        data        TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_deliveries_dest ON deliveries("destId");
      CREATE INDEX IF NOT EXISTS idx_deliveries_dedupe ON deliveries("destId", "dedupeKey");

      CREATE TABLE IF NOT EXISTS detector_feedback (
        seq          BIGSERIAL PRIMARY KEY,
        id           TEXT UNIQUE NOT NULL,
        "createdAt"  TEXT NOT NULL,
        "queryId"    TEXT NOT NULL,
        "detectorId" TEXT NOT NULL,
        verdict      TEXT NOT NULL,
        actor        TEXT,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_detector_feedback_query ON detector_feedback("queryId");
      CREATE INDEX IF NOT EXISTS idx_detector_feedback_detector ON detector_feedback("detectorId");
      CREATE INDEX IF NOT EXISTS idx_detector_feedback_verdict ON detector_feedback(verdict);

      CREATE TABLE IF NOT EXISTS identity_revocations (
        identity    TEXT PRIMARY KEY,
        "revokedAt" BIGINT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS mfa_recovery_used (
        "codeIndex" INTEGER PRIMARY KEY,
        "usedAt"    TEXT NOT NULL
      );
    `,
  },
  {
    version: 2,
    name: 'audit-append-only',
    sqlite: `
      CREATE TRIGGER IF NOT EXISTS audit_append_only_update
      BEFORE UPDATE ON audit
      BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

      CREATE TRIGGER IF NOT EXISTS audit_append_only_delete
      BEFORE DELETE ON audit
      BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
    `,
    postgres: `
      CREATE OR REPLACE FUNCTION redactwall_audit_append_only() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'audit log is append-only';
      END;
      $$ LANGUAGE plpgsql;

      DROP TRIGGER IF EXISTS audit_append_only_guard ON audit;
      CREATE TRIGGER audit_append_only_guard
        BEFORE UPDATE OR DELETE ON audit
        FOR EACH ROW EXECUTE FUNCTION redactwall_audit_append_only();
    `,
  },
  {
    version: 3,
    name: 'tenant-scoping',
    sqlite: `
      ALTER TABLE queries ADD COLUMN orgId TEXT;
      UPDATE queries SET orgId = json_extract(data, '$.orgId');
      CREATE INDEX IF NOT EXISTS idx_queries_org_created ON queries(orgId, createdAt);
    `,
    postgres: `
      ALTER TABLE queries ADD COLUMN "orgId" TEXT;
      UPDATE queries SET "orgId" = NULLIF(data::jsonb->>'orgId', '');
      CREATE INDEX IF NOT EXISTS idx_queries_org_created ON queries("orgId", "createdAt");

      ALTER TABLE queries ENABLE ROW LEVEL SECURITY;
      ALTER TABLE queries FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS queries_tenant_isolation ON queries;
      CREATE POLICY queries_tenant_isolation ON queries
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 4,
    name: 'orgid-normalize-and-posture-index',
    // Re-backfill orgId with the SAME normalization runtime writes/filters use
    // (orgColumn: trimmed + lowercased, empty -> NULL). This repairs two v3
    // defects: pre-migration rows whose stored orgId had mixed case/whitespace
    // never matched the lowercased filter, and (on Postgres) the earlier
    // identifier-quoting bug that could NULL every row. It reads from the intact
    // data JSON, so it is safe and idempotent. The audit(action) index keeps
    // posture-state reconstruction from scanning the whole append-only log.
    sqlite: `
      UPDATE queries SET orgId = NULLIF(lower(trim(json_extract(data, '$.orgId'))), '');
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);
    `,
    postgres: `
      UPDATE queries SET "orgId" = NULLIF(lower(btrim(data::jsonb->>'orgId')), '');
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);
    `,
  },
  {
    version: 5,
    name: 'ai-use-cases',
    // AI use-case inventory (PLANS/ncua-readiness-center.md slice 2): one row
    // per (canonicalHost, department) so "ChatGPT in Lending" and "ChatGPT in
    // Marketing" carry separate approvals. Tenant-ready from day one: orgId is
    // written with the v4-corrected normalization (trim + lowercase, empty ->
    // NULL) and Postgres rows are isolated with the same RLS policy shape as
    // queries. department is stored normalized (trimmed, single-spaced) so the
    // unique index needs no dialect-specific expression support.
    sqlite: `
      CREATE TABLE IF NOT EXISTS ai_use_cases (
        seq           INTEGER PRIMARY KEY AUTOINCREMENT,
        id            TEXT UNIQUE NOT NULL,
        orgId         TEXT,
        canonicalHost TEXT NOT NULL,
        department    TEXT NOT NULL,
        reviewStatus  TEXT NOT NULL,
        nextReviewAt  TEXT,
        createdAt     TEXT NOT NULL,
        updatedAt     TEXT NOT NULL,
        data          TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_use_cases_host_dept ON ai_use_cases(canonicalHost, department);
      CREATE INDEX IF NOT EXISTS idx_ai_use_cases_org ON ai_use_cases(orgId);
      CREATE INDEX IF NOT EXISTS idx_ai_use_cases_review ON ai_use_cases(reviewStatus, nextReviewAt);
    `,
    postgres: `
      CREATE TABLE IF NOT EXISTS ai_use_cases (
        seq             BIGSERIAL PRIMARY KEY,
        id              TEXT UNIQUE NOT NULL,
        "orgId"         TEXT,
        "canonicalHost" TEXT NOT NULL,
        department      TEXT NOT NULL,
        "reviewStatus"  TEXT NOT NULL,
        "nextReviewAt"  TEXT,
        "createdAt"     TEXT NOT NULL,
        "updatedAt"     TEXT NOT NULL,
        data            TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_use_cases_host_dept ON ai_use_cases("canonicalHost", department);
      CREATE INDEX IF NOT EXISTS idx_ai_use_cases_org ON ai_use_cases("orgId");
      CREATE INDEX IF NOT EXISTS idx_ai_use_cases_review ON ai_use_cases("reviewStatus", "nextReviewAt");

      ALTER TABLE ai_use_cases ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ai_use_cases FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS ai_use_cases_tenant_isolation ON ai_use_cases;
      CREATE POLICY ai_use_cases_tenant_isolation ON ai_use_cases
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 6,
    name: 'ai-incidents',
    // 72-hour AI incident readiness (PLANS/ncua-readiness-center.md slice 3,
    // NCUA cyber-incident reporting rule, 12 CFR 748.1(c)). Rows hold status
    // and deadline metadata plus referenced query ids; the examiner timeline
    // is DERIVED on read from those queries — no event content is duplicated
    // here. Tenant-ready like ai_use_cases: v4-corrected orgId + the same RLS
    // policy shape.
    sqlite: `
      CREATE TABLE IF NOT EXISTS ai_incidents (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        id         TEXT UNIQUE NOT NULL,
        orgId      TEXT,
        status     TEXT NOT NULL,
        detectedAt TEXT NOT NULL,
        deadlineAt TEXT NOT NULL,
        reportedAt TEXT,
        createdAt  TEXT NOT NULL,
        updatedAt  TEXT NOT NULL,
        data       TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ai_incidents_org ON ai_incidents(orgId);
      CREATE INDEX IF NOT EXISTS idx_ai_incidents_status ON ai_incidents(status, deadlineAt);
    `,
    postgres: `
      CREATE TABLE IF NOT EXISTS ai_incidents (
        seq          BIGSERIAL PRIMARY KEY,
        id           TEXT UNIQUE NOT NULL,
        "orgId"      TEXT,
        status       TEXT NOT NULL,
        "detectedAt" TEXT NOT NULL,
        "deadlineAt" TEXT NOT NULL,
        "reportedAt" TEXT,
        "createdAt"  TEXT NOT NULL,
        "updatedAt"  TEXT NOT NULL,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ai_incidents_org ON ai_incidents("orgId");
      CREATE INDEX IF NOT EXISTS idx_ai_incidents_status ON ai_incidents(status, "deadlineAt");

      ALTER TABLE ai_incidents ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ai_incidents FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS ai_incidents_tenant_isolation ON ai_incidents;
      CREATE POLICY ai_incidents_tenant_isolation ON ai_incidents
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 7,
    name: 'administration-users-and-licensing',
    // Customer-admin directory and licensing operations. These tables are
    // metadata-only: invite tokens are hashed, passwords are salted hashes, and
    // seat release/reassign state never rewrites historical sensor activity.
    sqlite: `
      CREATE TABLE IF NOT EXISTS admin_users (
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,
        id           TEXT UNIQUE NOT NULL,
        orgId        TEXT,
        userName     TEXT UNIQUE NOT NULL,
        displayName  TEXT,
        role         TEXT NOT NULL,
        active       INTEGER NOT NULL DEFAULT 1,
        createdAt    TEXT NOT NULL,
        updatedAt    TEXT NOT NULL,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_admin_users_org ON admin_users(orgId);
      CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(userName);
      CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role, active);

      CREATE TABLE IF NOT EXISTS admin_invitations (
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,
        id           TEXT UNIQUE NOT NULL,
        orgId        TEXT,
        userName     TEXT NOT NULL,
        tokenHash    TEXT UNIQUE NOT NULL,
        status       TEXT NOT NULL,
        expiresAt    TEXT NOT NULL,
        acceptedAt   TEXT,
        createdAt    TEXT NOT NULL,
        updatedAt    TEXT NOT NULL,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_admin_invitations_org ON admin_invitations(orgId);
      CREATE INDEX IF NOT EXISTS idx_admin_invitations_username ON admin_invitations(userName);
      CREATE INDEX IF NOT EXISTS idx_admin_invitations_status ON admin_invitations(status, expiresAt);

      CREATE TABLE IF NOT EXISTS license_seat_assignments (
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,
        id           TEXT UNIQUE NOT NULL,
        orgId        TEXT,
        userKey      TEXT UNIQUE NOT NULL,
        userName     TEXT NOT NULL,
        status       TEXT NOT NULL,
        reason       TEXT NOT NULL,
        actor        TEXT NOT NULL,
        createdAt    TEXT NOT NULL,
        updatedAt    TEXT NOT NULL,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_license_seat_assignments_org ON license_seat_assignments(orgId);
      CREATE INDEX IF NOT EXISTS idx_license_seat_assignments_status ON license_seat_assignments(status);

      CREATE TABLE IF NOT EXISTS license_renewal_requests (
        seq             INTEGER PRIMARY KEY AUTOINCREMENT,
        id              TEXT UNIQUE NOT NULL,
        orgId           TEXT,
        status          TEXT NOT NULL,
        requestedSeats  INTEGER,
        contactEmail    TEXT,
        createdAt       TEXT NOT NULL,
        updatedAt       TEXT NOT NULL,
        data            TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_license_renewal_requests_org ON license_renewal_requests(orgId);
      CREATE INDEX IF NOT EXISTS idx_license_renewal_requests_status ON license_renewal_requests(status, createdAt);
    `,
    postgres: `
      CREATE TABLE IF NOT EXISTS admin_users (
        seq           BIGSERIAL PRIMARY KEY,
        id            TEXT UNIQUE NOT NULL,
        "orgId"       TEXT,
        "userName"    TEXT UNIQUE NOT NULL,
        "displayName" TEXT,
        role          TEXT NOT NULL,
        active        INTEGER NOT NULL DEFAULT 1,
        "createdAt"   TEXT NOT NULL,
        "updatedAt"   TEXT NOT NULL,
        data          TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_admin_users_org ON admin_users("orgId");
      CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users("userName");
      CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role, active);

      ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;
      ALTER TABLE admin_users FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS admin_users_tenant_isolation ON admin_users;
      CREATE POLICY admin_users_tenant_isolation ON admin_users
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));

      CREATE TABLE IF NOT EXISTS admin_invitations (
        seq          BIGSERIAL PRIMARY KEY,
        id           TEXT UNIQUE NOT NULL,
        "orgId"      TEXT,
        "userName"   TEXT NOT NULL,
        "tokenHash"  TEXT UNIQUE NOT NULL,
        status       TEXT NOT NULL,
        "expiresAt"  TEXT NOT NULL,
        "acceptedAt" TEXT,
        "createdAt"  TEXT NOT NULL,
        "updatedAt"  TEXT NOT NULL,
        data         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_admin_invitations_org ON admin_invitations("orgId");
      CREATE INDEX IF NOT EXISTS idx_admin_invitations_username ON admin_invitations("userName");
      CREATE INDEX IF NOT EXISTS idx_admin_invitations_status ON admin_invitations(status, "expiresAt");

      ALTER TABLE admin_invitations ENABLE ROW LEVEL SECURITY;
      ALTER TABLE admin_invitations FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS admin_invitations_tenant_isolation ON admin_invitations;
      CREATE POLICY admin_invitations_tenant_isolation ON admin_invitations
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));

      CREATE TABLE IF NOT EXISTS license_seat_assignments (
        seq         BIGSERIAL PRIMARY KEY,
        id          TEXT UNIQUE NOT NULL,
        "orgId"     TEXT,
        "userKey"   TEXT UNIQUE NOT NULL,
        "userName"  TEXT NOT NULL,
        status      TEXT NOT NULL,
        reason      TEXT NOT NULL,
        actor       TEXT NOT NULL,
        "createdAt" TEXT NOT NULL,
        "updatedAt" TEXT NOT NULL,
        data        TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_license_seat_assignments_org ON license_seat_assignments("orgId");
      CREATE INDEX IF NOT EXISTS idx_license_seat_assignments_status ON license_seat_assignments(status);

      ALTER TABLE license_seat_assignments ENABLE ROW LEVEL SECURITY;
      ALTER TABLE license_seat_assignments FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS license_seat_assignments_tenant_isolation ON license_seat_assignments;
      CREATE POLICY license_seat_assignments_tenant_isolation ON license_seat_assignments
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));

      CREATE TABLE IF NOT EXISTS license_renewal_requests (
        seq              BIGSERIAL PRIMARY KEY,
        id               TEXT UNIQUE NOT NULL,
        "orgId"          TEXT,
        status           TEXT NOT NULL,
        "requestedSeats" INTEGER,
        "contactEmail"   TEXT,
        "createdAt"      TEXT NOT NULL,
        "updatedAt"      TEXT NOT NULL,
        data             TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_license_renewal_requests_org ON license_renewal_requests("orgId");
      CREATE INDEX IF NOT EXISTS idx_license_renewal_requests_status ON license_renewal_requests(status, "createdAt");

      ALTER TABLE license_renewal_requests ENABLE ROW LEVEL SECURITY;
      ALTER TABLE license_renewal_requests FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS license_renewal_requests_tenant_isolation ON license_renewal_requests;
      CREATE POLICY license_renewal_requests_tenant_isolation ON license_renewal_requests
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 8,
    name: 'authenticated-audit-checkpoint',
    // The authenticated chain uses private sidecar state rather than another
    // database column. Recording a schema version still gives db.js a one-time,
    // crash-recoverable bootstrap signal for existing unkeyed chains. On later
    // starts a missing sidecar is treated as tampering, never silently recreated.
    sqlite: 'SELECT 1;',
    postgres: 'SELECT 1;',
  },
  {
    version: 9,
    name: 'shared-vendor-license-state',
    // Connected-license verdict freshness and status must be shared by every
    // replica. The audit remains the tamper-evident evidence anchor; this row
    // is the transactionally serialized high-water used by the live CAS.
    // Connected deployments must drain all pre-v9 replicas before applying
    // this migration; old processes do not reconcile shared state on requests.
    sqlite: `
      CREATE TABLE IF NOT EXISTS vendor_license_state (
        customerId TEXT PRIMARY KEY,
        issuedAt   INTEGER NOT NULL,
        contactAt  INTEGER NOT NULL,
        status     TEXT NOT NULL CHECK (status IN ('active', 'revoked'))
      );
    `,
    postgres: `
      CREATE TABLE IF NOT EXISTS vendor_license_state (
        "customerId" TEXT PRIMARY KEY,
        "issuedAt"   BIGINT NOT NULL,
        "contactAt"  BIGINT NOT NULL,
        status       TEXT NOT NULL CHECK (status IN ('active', 'revoked'))
      );

      ALTER TABLE vendor_license_state ENABLE ROW LEVEL SECURITY;
      ALTER TABLE vendor_license_state FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS vendor_license_state_tenant_isolation ON vendor_license_state;
      CREATE POLICY vendor_license_state_tenant_isolation ON vendor_license_state
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "customerId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "customerId" = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 10,
    name: 'native-handoff-ingest-idempotency',
    // One opaque HMAC maps to one committed query inside a normalized,
    // non-null tenant scope. Query creation, its audit append, and this mapping
    // are one transaction; retries never need raw event or prompt content.
    sqlite: `
      ALTER TABLE audit ADD COLUMN ingestIdentityHash TEXT
        GENERATED ALWAYS AS (json_extract(entry, '$.ingestIdempotency.identityHash')) VIRTUAL;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_ingest_identity
        ON audit(ingestIdentityHash) WHERE ingestIdentityHash IS NOT NULL;

      CREATE TABLE IF NOT EXISTS ingest_idempotency (
        scope       TEXT NOT NULL,
        orgId       TEXT NOT NULL,
        keyHash     TEXT NOT NULL,
        queryId     TEXT UNIQUE NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
        auditId     TEXT UNIQUE NOT NULL REFERENCES audit(id),
        replaySnapshot TEXT NOT NULL,
        createdAt   TEXT NOT NULL,
        PRIMARY KEY (scope, orgId, keyHash)
      );
      CREATE INDEX IF NOT EXISTS idx_ingest_idempotency_query ON ingest_idempotency(queryId);
    `,
    postgres: `
      ALTER TABLE audit ADD COLUMN IF NOT EXISTS "ingestIdentityHash" TEXT
        GENERATED ALWAYS AS ((entry::jsonb #>> '{ingestIdempotency,identityHash}')) STORED;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_ingest_identity
        ON audit("ingestIdentityHash") WHERE "ingestIdentityHash" IS NOT NULL;

      CREATE TABLE IF NOT EXISTS ingest_idempotency (
        scope       TEXT NOT NULL,
        "orgId"     TEXT NOT NULL,
        "keyHash"   TEXT NOT NULL,
        "queryId"   TEXT UNIQUE NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
        "auditId"   TEXT UNIQUE NOT NULL REFERENCES audit(id),
        "replaySnapshot" TEXT NOT NULL,
        "createdAt" TEXT NOT NULL,
        PRIMARY KEY (scope, "orgId", "keyHash")
      );
      CREATE INDEX IF NOT EXISTS idx_ingest_idempotency_query ON ingest_idempotency("queryId");

      ALTER TABLE ingest_idempotency ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ingest_idempotency FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS ingest_idempotency_tenant_isolation ON ingest_idempotency;
      CREATE POLICY ingest_idempotency_tenant_isolation ON ingest_idempotency
        USING (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') = ''
          OR "orgId" = current_setting('redactwall.org_id', true));
    `,
  },
];

module.exports = { MIGRATIONS };
