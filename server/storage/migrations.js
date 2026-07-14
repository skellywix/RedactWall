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
    // Historical schema retained so released databases continue to migrate.
    // The legacy vendor-link reader/writer was removed by the connected-first
    // cutover. These rows are inert and are never licensing authority.
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
  {
    version: 11,
    name: 'connected-entitlement-state-and-ack-outbox',
    // Connected entitlements are the primary licensing authority. The exact
    // customer+deployment high-water, its authenticated state snapshot, and a
    // retryable acknowledgement are committed together. Versions 11-13 are
    // one unreleased migration train: every migration must complete
    // before a connected writer starts. Pre-v11 replicas must be drained before
    // this train is enabled because they cannot enforce pause or consume the
    // acknowledgement outbox.
    sqlite: `
      ALTER TABLE audit ADD COLUMN connected_authority_ref TEXT
        GENERATED ALWAYS AS (
          json_extract(entry, '$.connectedAuthorityRef')
        ) VIRTUAL;
      ALTER TABLE audit ADD COLUMN connected_ack_ref TEXT
        GENERATED ALWAYS AS (
          json_extract(entry, '$.connectedAckRef')
        ) VIRTUAL;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_authority
        ON audit(connected_authority_ref, seq DESC)
        WHERE connected_authority_ref IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_ack
        ON audit(connected_ack_ref, seq DESC)
        WHERE connected_ack_ref IS NOT NULL;

      CREATE TABLE IF NOT EXISTS connected_entitlement_state (
        customer_id         TEXT NOT NULL,
        deployment_id       TEXT NOT NULL,
        authority_ref       TEXT NOT NULL UNIQUE,
        entitlement_version INTEGER NOT NULL,
        entitlement_digest  TEXT,
        state_json           TEXT NOT NULL,
        updated_at           TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id)
      );

      CREATE TABLE IF NOT EXISTS connected_ack_outbox (
        id             TEXT PRIMARY KEY,
        customer_id    TEXT NOT NULL,
        deployment_id  TEXT NOT NULL,
        target_kind    TEXT NOT NULL,
        target_version INTEGER NOT NULL,
        target_digest  TEXT NOT NULL,
        lifecycle_stage TEXT NOT NULL CHECK (lifecycle_stage IN ('applied')),
        payload_json   TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        status         TEXT NOT NULL CHECK (status IN ('pending', 'acknowledged')),
        attempts       INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, target_kind, target_version, target_digest, lifecycle_stage),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_entitlement_state(customer_id, deployment_id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_connected_ack_pending
        ON connected_ack_outbox(customer_id, deployment_id, status, next_attempt_at, created_at);
    `,
    postgres: `
      ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS connected_authority_ref TEXT
        GENERATED ALWAYS AS ((entry::jsonb ->> 'connectedAuthorityRef')) STORED;
      ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS connected_ack_ref TEXT
        GENERATED ALWAYS AS ((entry::jsonb ->> 'connectedAckRef')) STORED;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_authority
        ON public.audit(connected_authority_ref, seq DESC)
        WHERE connected_authority_ref IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_ack
        ON public.audit(connected_ack_ref, seq DESC)
        WHERE connected_ack_ref IS NOT NULL;

      CREATE TABLE IF NOT EXISTS public.connected_entitlement_state (
        customer_id         TEXT NOT NULL,
        deployment_id       TEXT NOT NULL,
        authority_ref       TEXT NOT NULL UNIQUE,
        entitlement_version BIGINT NOT NULL,
        entitlement_digest  TEXT,
        state_json           TEXT NOT NULL,
        updated_at           TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id)
      );

      CREATE TABLE IF NOT EXISTS public.connected_ack_outbox (
        id             TEXT PRIMARY KEY,
        customer_id    TEXT NOT NULL,
        deployment_id  TEXT NOT NULL,
        target_kind    TEXT NOT NULL,
        target_version BIGINT NOT NULL,
        target_digest  TEXT NOT NULL,
        lifecycle_stage TEXT NOT NULL CHECK (lifecycle_stage IN ('applied')),
        payload_json   TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        status         TEXT NOT NULL CHECK (status IN ('pending', 'acknowledged')),
        attempts       INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, target_kind, target_version, target_digest, lifecycle_stage),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES public.connected_entitlement_state(customer_id, deployment_id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_connected_ack_pending
        ON public.connected_ack_outbox(customer_id, deployment_id, status, next_attempt_at, created_at);

      ALTER TABLE public.connected_entitlement_state ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_entitlement_state FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS connected_entitlement_state_tenant_isolation ON public.connected_entitlement_state;
      CREATE POLICY connected_entitlement_state_tenant_isolation ON public.connected_entitlement_state
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      ALTER TABLE public.connected_ack_outbox ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_ack_outbox FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS connected_ack_outbox_tenant_isolation ON public.connected_ack_outbox;
      CREATE POLICY connected_ack_outbox_tenant_isolation ON public.connected_ack_outbox
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 12,
    name: 'connected-online-registry-high-water',
    // The online active/revoked registry is independent from commercial
    // entitlements. This table persists the exact signed registry generation,
    // stable registry-state digest, deployment binding, and authenticated
    // state snapshot. Pre-v12 replicas must be drained because they report
    // generation zero and cannot enforce the vendor registry high-water.
    sqlite: `
      CREATE TABLE IF NOT EXISTS connected_online_registry_state (
        customer_id          TEXT NOT NULL,
        deployment_id        TEXT NOT NULL,
        authority_ref        TEXT NOT NULL UNIQUE,
        registry_generation  INTEGER NOT NULL CHECK (registry_generation >= 1),
        registry_state_digest TEXT NOT NULL CHECK (
          length(registry_state_digest) = 64
          AND registry_state_digest NOT GLOB '*[^0-9a-f]*'
        ),
        status               TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
        state_json           TEXT NOT NULL,
        updated_at           TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id)
      );
      CREATE INDEX IF NOT EXISTS idx_connected_registry_generation
        ON connected_online_registry_state(customer_id, deployment_id, registry_generation DESC);
    `,
    postgres: `
      CREATE TABLE IF NOT EXISTS public.connected_online_registry_state (
        customer_id          TEXT NOT NULL,
        deployment_id        TEXT NOT NULL,
        authority_ref        TEXT NOT NULL UNIQUE,
        registry_generation  BIGINT NOT NULL CHECK (registry_generation >= 1),
        registry_state_digest TEXT NOT NULL CHECK (
          length(registry_state_digest) = 64
          AND registry_state_digest ~ '^[0-9a-f]{64}$'
        ),
        status               TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
        state_json           TEXT NOT NULL,
        updated_at           TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id)
      );
      CREATE INDEX IF NOT EXISTS idx_connected_registry_generation
        ON public.connected_online_registry_state(customer_id, deployment_id, registry_generation DESC);

      ALTER TABLE public.connected_online_registry_state ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_online_registry_state FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS connected_online_registry_tenant_isolation
        ON public.connected_online_registry_state;
      CREATE POLICY connected_online_registry_tenant_isolation
        ON public.connected_online_registry_state
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 13,
    name: 'connected-entitlement-final-acknowledgement-state',
    // The former unreleased v11 writer could create only an applied ACK. Such
    // data has no authenticated delivered predecessor, so it cannot be safely
    // synthesized. Reject a populated intermediate database atomically. Empty
    // v11 stores are reshaped before any connected writer is allowed to start.
    // This unreleased train creates the strict v4 bounded archive ledger. Any
    // development database stamped with an older v13 shape must be recreated;
    // SQL alone cannot authenticate and convert its prior archive evidence.
    sqlite: `
      CREATE TEMP TABLE connected_ack_v13_upgrade_guard (
        populated INTEGER NOT NULL CHECK (populated = 0)
      );
      INSERT INTO connected_ack_v13_upgrade_guard(populated)
      SELECT CASE WHEN EXISTS (
        SELECT 1 FROM connected_entitlement_state
      ) OR EXISTS (
        SELECT 1 FROM connected_ack_outbox
      ) THEN 1 ELSE 0 END;
      DROP TABLE connected_ack_v13_upgrade_guard;

      DROP INDEX IF EXISTS idx_connected_ack_pending;
      CREATE TABLE connected_ack_outbox_v13 (
        id             TEXT PRIMARY KEY,
        customer_id    TEXT NOT NULL,
        deployment_id  TEXT NOT NULL,
        target_kind    TEXT NOT NULL,
        target_version INTEGER NOT NULL,
        target_digest  TEXT NOT NULL,
        lifecycle_stage TEXT NOT NULL CHECK (lifecycle_stage IN ('delivered', 'applied')),
        payload_json   TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        status         TEXT NOT NULL CHECK (status IN ('pending', 'acknowledged', 'terminal')),
        failure_class  TEXT CHECK (failure_class IS NULL OR failure_class IN (
          'transport_unavailable', 'transport_ambiguous', 'rate_limited',
          'authentication_rejected', 'invalid_signature', 'unknown_signing_key',
          'invalid_schema', 'customer_mismatch', 'deployment_mismatch',
          'version_conflict', 'protocol_rejected', 'response_too_large',
          'expired', 'clock_rollback', 'state_corrupt'
        )),
        attempts       INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, target_kind, target_version, target_digest, lifecycle_stage),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_entitlement_state(customer_id, deployment_id) ON DELETE CASCADE
      );
      DROP TABLE connected_ack_outbox;
      ALTER TABLE connected_ack_outbox_v13 RENAME TO connected_ack_outbox;
      CREATE INDEX idx_connected_ack_pending
        ON connected_ack_outbox(customer_id, deployment_id, status, next_attempt_at,
          target_version, lifecycle_stage, created_at);

      CREATE TABLE connected_ack_health (
        customer_id   TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        authority_ref TEXT NOT NULL UNIQUE,
        state_json    TEXT NOT NULL,
        updated_at    TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_entitlement_state(customer_id, deployment_id) ON DELETE CASCADE
      );

      CREATE TABLE connected_ack_archive (
        archive_seq     INTEGER PRIMARY KEY AUTOINCREMENT,
        id              TEXT NOT NULL UNIQUE,
        customer_id     TEXT NOT NULL,
        deployment_id   TEXT NOT NULL,
        target_kind     TEXT NOT NULL,
        target_version  INTEGER NOT NULL,
        target_digest   TEXT NOT NULL,
        lifecycle_stage TEXT NOT NULL CHECK (lifecycle_stage IN ('delivered', 'applied')),
        payload_json    TEXT NOT NULL,
        payload_digest  TEXT NOT NULL,
        status          TEXT NOT NULL CHECK (status = 'acknowledged'),
        failure_class   TEXT CHECK (failure_class IS NULL),
        attempts        INTEGER NOT NULL CHECK (attempts >= 1),
        next_attempt_at TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        archived_at     TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, target_kind, target_version,
          target_digest, lifecycle_stage),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_entitlement_state(customer_id, deployment_id)
      );
      CREATE INDEX idx_connected_ack_archive_scope
        ON connected_ack_archive(customer_id, deployment_id, archive_seq);

      CREATE TABLE connected_ack_archive_mutations (
        event_seq       INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id     TEXT NOT NULL,
        deployment_id   TEXT NOT NULL,
        scope_seq       INTEGER NOT NULL CHECK (scope_seq > 0),
        mutation_kind   TEXT NOT NULL CHECK (mutation_kind IN ('insert', 'update', 'delete')),
        archive_seq     INTEGER NOT NULL CHECK (archive_seq > 0),
        archive_id      TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, scope_seq)
      );
      CREATE INDEX idx_connected_ack_archive_mutation_scope
        ON connected_ack_archive_mutations(customer_id, deployment_id, scope_seq DESC);
      CREATE TRIGGER connected_ack_archive_record_insert
        AFTER INSERT ON connected_ack_archive
        BEGIN
          INSERT INTO connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT NEW.customer_id, NEW.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'insert', NEW.archive_seq, NEW.id
          FROM connected_ack_archive_mutations
          WHERE customer_id = NEW.customer_id AND deployment_id = NEW.deployment_id;
        END;
      CREATE TRIGGER connected_ack_archive_record_update
        AFTER UPDATE ON connected_ack_archive
        BEGIN
          INSERT INTO connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'update', OLD.archive_seq, OLD.id
          FROM connected_ack_archive_mutations
          WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
          INSERT INTO connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT NEW.customer_id, NEW.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'update', NEW.archive_seq, NEW.id
          FROM connected_ack_archive_mutations
          WHERE customer_id = NEW.customer_id AND deployment_id = NEW.deployment_id
          HAVING NEW.customer_id IS NOT OLD.customer_id
             OR NEW.deployment_id IS NOT OLD.deployment_id;
        END;
      CREATE TRIGGER connected_ack_archive_record_delete
        AFTER DELETE ON connected_ack_archive
        BEGIN
          INSERT INTO connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'delete', OLD.archive_seq, OLD.id
          FROM connected_ack_archive_mutations
          WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
        END;
      CREATE TRIGGER connected_ack_archive_no_update
        BEFORE UPDATE ON connected_ack_archive
        BEGIN SELECT RAISE(ABORT, 'connected ACK archive is append-only'); END;
      CREATE TRIGGER connected_ack_archive_mutations_no_update
        BEFORE UPDATE ON connected_ack_archive_mutations
        BEGIN SELECT RAISE(ABORT, 'connected ACK archive mutation log is append-only'); END;
      CREATE TRIGGER connected_ack_archive_mutations_no_replace
        BEFORE INSERT ON connected_ack_archive_mutations
        WHEN EXISTS (
          SELECT 1 FROM connected_ack_archive_mutations
          WHERE event_seq = NEW.event_seq
             OR (customer_id = NEW.customer_id AND deployment_id = NEW.deployment_id
               AND scope_seq = NEW.scope_seq)
        )
        BEGIN SELECT RAISE(ABORT, 'connected ACK archive mutation log is append-only'); END;

      ALTER TABLE audit ADD COLUMN connected_entry_action TEXT
        GENERATED ALWAYS AS (json_extract(entry, '$.action')) VIRTUAL;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_authority_action
        ON audit(connected_authority_ref, connected_entry_action, seq DESC)
        WHERE connected_authority_ref IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_ack_action
        ON audit(connected_ack_ref, connected_entry_action, seq DESC)
        WHERE connected_ack_ref IS NOT NULL;
    `,
    postgres: `
      LOCK TABLE public.connected_entitlement_state, public.connected_ack_outbox
        IN ACCESS EXCLUSIVE MODE;
      ALTER TABLE public.connected_entitlement_state NO FORCE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_ack_outbox NO FORCE ROW LEVEL SECURITY;
      DO $connected_ack_v13_upgrade_guard$
      BEGIN
        IF EXISTS (SELECT 1 FROM public.connected_entitlement_state)
          OR EXISTS (SELECT 1 FROM public.connected_ack_outbox) THEN
          RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'connected acknowledgement migration requires a pre-v11 empty state and re-enrollment';
        END IF;
      END;
      $connected_ack_v13_upgrade_guard$;
      ALTER TABLE public.connected_entitlement_state FORCE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_ack_outbox FORCE ROW LEVEL SECURITY;

      ALTER TABLE public.connected_ack_outbox
        DROP CONSTRAINT IF EXISTS connected_ack_outbox_lifecycle_stage_check;
      ALTER TABLE public.connected_ack_outbox
        ADD CONSTRAINT connected_ack_outbox_lifecycle_stage_check
        CHECK (lifecycle_stage IN ('delivered', 'applied'));
      ALTER TABLE public.connected_ack_outbox
        DROP CONSTRAINT IF EXISTS connected_ack_outbox_status_check;
      ALTER TABLE public.connected_ack_outbox
        ADD CONSTRAINT connected_ack_outbox_status_check
        CHECK (status IN ('pending', 'acknowledged', 'terminal'));
      ALTER TABLE public.connected_ack_outbox ADD COLUMN IF NOT EXISTS failure_class TEXT;
      ALTER TABLE public.connected_ack_outbox
        DROP CONSTRAINT IF EXISTS connected_ack_outbox_failure_class_check;
      ALTER TABLE public.connected_ack_outbox
        ADD CONSTRAINT connected_ack_outbox_failure_class_check
        CHECK (failure_class IS NULL OR failure_class IN (
          'transport_unavailable', 'transport_ambiguous', 'rate_limited',
          'authentication_rejected', 'invalid_signature', 'unknown_signing_key',
          'invalid_schema', 'customer_mismatch', 'deployment_mismatch',
          'version_conflict', 'protocol_rejected', 'response_too_large',
          'expired', 'clock_rollback', 'state_corrupt'
        ));
      DROP INDEX IF EXISTS idx_connected_ack_pending;
      CREATE INDEX idx_connected_ack_pending
        ON public.connected_ack_outbox(customer_id, deployment_id, status, next_attempt_at,
          target_version, lifecycle_stage, created_at);

      CREATE TABLE public.connected_ack_health (
        customer_id   TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        authority_ref TEXT NOT NULL UNIQUE,
        state_json    TEXT NOT NULL,
        updated_at    TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES public.connected_entitlement_state(customer_id, deployment_id) ON DELETE CASCADE
      );
      ALTER TABLE public.connected_ack_health ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_ack_health FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS connected_ack_health_tenant_isolation ON public.connected_ack_health;
      CREATE POLICY connected_ack_health_tenant_isolation ON public.connected_ack_health
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE TABLE public.connected_ack_archive (
        archive_seq     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        id              TEXT NOT NULL UNIQUE,
        customer_id     TEXT NOT NULL,
        deployment_id   TEXT NOT NULL,
        target_kind     TEXT NOT NULL,
        target_version  BIGINT NOT NULL,
        target_digest   TEXT NOT NULL,
        lifecycle_stage TEXT NOT NULL CHECK (lifecycle_stage IN ('delivered', 'applied')),
        payload_json    TEXT NOT NULL,
        payload_digest  TEXT NOT NULL,
        status          TEXT NOT NULL CHECK (status = 'acknowledged'),
        failure_class   TEXT CHECK (failure_class IS NULL),
        attempts        BIGINT NOT NULL CHECK (attempts >= 1),
        next_attempt_at TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        archived_at     TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, target_kind, target_version,
          target_digest, lifecycle_stage),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES public.connected_entitlement_state(customer_id, deployment_id)
      );
      CREATE INDEX idx_connected_ack_archive_scope
        ON public.connected_ack_archive(customer_id, deployment_id, archive_seq);
      ALTER TABLE public.connected_ack_archive ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_ack_archive FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS connected_ack_archive_tenant_isolation ON public.connected_ack_archive;
      CREATE POLICY connected_ack_archive_tenant_isolation ON public.connected_ack_archive
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE TABLE public.connected_ack_archive_mutations (
        event_seq       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        customer_id     TEXT NOT NULL,
        deployment_id   TEXT NOT NULL,
        scope_seq       BIGINT NOT NULL CHECK (scope_seq > 0),
        mutation_kind   TEXT NOT NULL CHECK (mutation_kind IN ('insert', 'update', 'delete')),
        archive_seq     BIGINT NOT NULL CHECK (archive_seq > 0),
        archive_id      TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, scope_seq)
      );
      CREATE INDEX idx_connected_ack_archive_mutation_scope
        ON public.connected_ack_archive_mutations(customer_id, deployment_id, scope_seq DESC);
      ALTER TABLE public.connected_ack_archive_mutations ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_ack_archive_mutations FORCE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS connected_ack_archive_mutation_tenant_isolation
        ON public.connected_ack_archive_mutations;
      CREATE POLICY connected_ack_archive_mutation_tenant_isolation
        ON public.connected_ack_archive_mutations
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE OR REPLACE FUNCTION public.record_connected_ack_archive_mutation()
      RETURNS trigger LANGUAGE plpgsql
      SET search_path = pg_catalog
      AS $connected_ack_archive_record$
      BEGIN
        IF TG_OP = 'INSERT' THEN
          INSERT INTO public.connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT NEW.customer_id, NEW.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'insert', NEW.archive_seq, NEW.id
          FROM public.connected_ack_archive_mutations
          WHERE customer_id = NEW.customer_id AND deployment_id = NEW.deployment_id;
        ELSIF TG_OP = 'DELETE' THEN
          INSERT INTO public.connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'delete', OLD.archive_seq, OLD.id
          FROM public.connected_ack_archive_mutations
          WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
        ELSE
          INSERT INTO public.connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'update', OLD.archive_seq, OLD.id
          FROM public.connected_ack_archive_mutations
          WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
          IF NEW.customer_id IS DISTINCT FROM OLD.customer_id
             OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id THEN
            INSERT INTO public.connected_ack_archive_mutations
              (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
            SELECT NEW.customer_id, NEW.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
              'update', NEW.archive_seq, NEW.id
            FROM public.connected_ack_archive_mutations
            WHERE customer_id = NEW.customer_id AND deployment_id = NEW.deployment_id;
          END IF;
        END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
      END;
      $connected_ack_archive_record$;
      DROP TRIGGER IF EXISTS connected_ack_archive_record_mutation ON public.connected_ack_archive;
      CREATE TRIGGER connected_ack_archive_record_mutation
        AFTER INSERT OR UPDATE OR DELETE ON public.connected_ack_archive
        FOR EACH ROW EXECUTE FUNCTION public.record_connected_ack_archive_mutation();

      CREATE OR REPLACE FUNCTION public.reject_connected_ack_archive_mutation()
      RETURNS trigger LANGUAGE plpgsql
      SET search_path = pg_catalog
      AS $connected_ack_archive_guard$
      BEGIN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = 'connected ACK archive is append-only';
      END;
      $connected_ack_archive_guard$;
      DROP TRIGGER IF EXISTS connected_ack_archive_no_update ON public.connected_ack_archive;
      CREATE TRIGGER connected_ack_archive_no_update
        BEFORE UPDATE ON public.connected_ack_archive
        FOR EACH ROW EXECUTE FUNCTION public.reject_connected_ack_archive_mutation();
      DROP TRIGGER IF EXISTS connected_ack_archive_no_delete ON public.connected_ack_archive;

      CREATE OR REPLACE FUNCTION public.reject_connected_ack_archive_event_mutation()
      RETURNS trigger LANGUAGE plpgsql
      SET search_path = pg_catalog
      AS $connected_ack_archive_event_guard$
      BEGIN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = 'connected ACK archive mutation log is append-only';
      END;
      $connected_ack_archive_event_guard$;
      DROP TRIGGER IF EXISTS connected_ack_archive_mutations_no_update
        ON public.connected_ack_archive_mutations;
      CREATE TRIGGER connected_ack_archive_mutations_no_update
        BEFORE UPDATE ON public.connected_ack_archive_mutations
        FOR EACH ROW EXECUTE FUNCTION public.reject_connected_ack_archive_event_mutation();
      DROP TRIGGER IF EXISTS connected_ack_archive_mutations_no_delete
        ON public.connected_ack_archive_mutations;

      ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS connected_entry_action TEXT
        GENERATED ALWAYS AS ((entry::jsonb ->> 'action')) STORED;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_authority_action
        ON public.audit(connected_authority_ref, connected_entry_action, seq DESC)
        WHERE connected_authority_ref IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_audit_connected_ack_action
        ON public.audit(connected_ack_ref, connected_entry_action, seq DESC)
        WHERE connected_ack_ref IS NOT NULL;
    `,
  },
  {
    version: 14,
    name: 'customer-diagnostic-outbox',
    sqlite: `
      CREATE TABLE customer_diagnostic_outbox (
        customer_id       TEXT NOT NULL,
        deployment_id     TEXT NOT NULL,
        message_id        TEXT NOT NULL,
        payload_json      TEXT,
        payload_digest    TEXT NOT NULL,
        status            TEXT NOT NULL CHECK (status IN (
          'pending', 'leased', 'delivered', 'expired', 'dead_letter'
        )),
        state_version     INTEGER NOT NULL CHECK (state_version > 0),
        attempts          INTEGER NOT NULL CHECK (attempts >= 0),
        next_attempt_at   TEXT,
        lease_id          TEXT,
        lease_until       TEXT,
        settled_lease_id  TEXT,
        created_at        TEXT NOT NULL,
        updated_at        TEXT NOT NULL,
        retain_until      TEXT,
        last_audit_action TEXT NOT NULL,
        last_audit_at     TEXT NOT NULL,
        state_key_id      TEXT NOT NULL,
        state_mac         TEXT NOT NULL,
        audit_key_id      TEXT NOT NULL,
        audit_anchor      TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id, message_id)
      );
      CREATE INDEX idx_customer_diagnostic_ready
        ON customer_diagnostic_outbox(
          customer_id, deployment_id, status, next_attempt_at, lease_until,
          created_at, message_id
        );
      CREATE INDEX idx_customer_diagnostic_tombstone
        ON customer_diagnostic_outbox(
          customer_id, deployment_id, status, retain_until, created_at, message_id
        );

      CREATE TABLE customer_diagnostic_time_high_water (
        customer_id   TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        observed_at   TEXT NOT NULL,
        state_key_id  TEXT NOT NULL,
        state_mac     TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id)
      );

      CREATE TABLE customer_diagnostic_audit (
        event_seq     INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id   TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        message_id    TEXT,
        action        TEXT NOT NULL CHECK (action IN (
          'DIAGNOSTIC_QUEUED', 'DIAGNOSTIC_LEASED',
          'DIAGNOSTIC_RETRY_SCHEDULED', 'DIAGNOSTIC_DELIVERED',
          'DIAGNOSTIC_EXPIRED', 'DIAGNOSTIC_DEAD_LETTERED',
          'DIAGNOSTIC_TOMBSTONE_PURGED', 'DIAGNOSTIC_REJECTED'
        )),
        occurred_at   TEXT NOT NULL,
        event_json    TEXT NOT NULL,
        audit_key_id  TEXT NOT NULL,
        audit_anchor  TEXT NOT NULL
      );
      CREATE INDEX idx_customer_diagnostic_audit_message
        ON customer_diagnostic_audit(
          customer_id, deployment_id, message_id, event_seq DESC
        );
      CREATE TRIGGER customer_diagnostic_audit_no_update
        BEFORE UPDATE ON customer_diagnostic_audit
        BEGIN
          SELECT RAISE(ABORT, 'customer diagnostic audit is append-only');
        END;
      CREATE TRIGGER customer_diagnostic_audit_no_delete
        BEFORE DELETE ON customer_diagnostic_audit
        BEGIN
          SELECT RAISE(ABORT, 'customer diagnostic audit is append-only');
        END;
    `,
    postgres: `
      CREATE TABLE public.customer_diagnostic_outbox (
        customer_id       TEXT NOT NULL,
        deployment_id     TEXT NOT NULL,
        message_id        TEXT NOT NULL,
        payload_json      TEXT,
        payload_digest    TEXT NOT NULL,
        status            TEXT NOT NULL CHECK (status IN (
          'pending', 'leased', 'delivered', 'expired', 'dead_letter'
        )),
        state_version     INTEGER NOT NULL CHECK (state_version > 0),
        attempts          INTEGER NOT NULL CHECK (attempts >= 0),
        next_attempt_at   TEXT,
        lease_id          TEXT,
        lease_until       TEXT,
        settled_lease_id  TEXT,
        created_at        TEXT NOT NULL,
        updated_at        TEXT NOT NULL,
        retain_until      TEXT,
        last_audit_action TEXT NOT NULL,
        last_audit_at     TEXT NOT NULL,
        state_key_id      TEXT NOT NULL,
        state_mac         TEXT NOT NULL,
        audit_key_id      TEXT NOT NULL,
        audit_anchor      TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id, message_id)
      );
      CREATE INDEX idx_customer_diagnostic_ready
        ON public.customer_diagnostic_outbox(
          customer_id, deployment_id, status, next_attempt_at, lease_until,
          created_at, message_id
        );
      CREATE INDEX idx_customer_diagnostic_tombstone
        ON public.customer_diagnostic_outbox(
          customer_id, deployment_id, status, retain_until, created_at, message_id
        );
      ALTER TABLE public.customer_diagnostic_outbox ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.customer_diagnostic_outbox FORCE ROW LEVEL SECURITY;
      CREATE POLICY customer_diagnostic_outbox_tenant_isolation
        ON public.customer_diagnostic_outbox
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE TABLE public.customer_diagnostic_time_high_water (
        customer_id   TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        observed_at   TEXT NOT NULL,
        state_key_id  TEXT NOT NULL,
        state_mac     TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id)
      );
      ALTER TABLE public.customer_diagnostic_time_high_water ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.customer_diagnostic_time_high_water FORCE ROW LEVEL SECURITY;
      CREATE POLICY customer_diagnostic_time_tenant_isolation
        ON public.customer_diagnostic_time_high_water
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE TABLE public.customer_diagnostic_audit (
        event_seq     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        customer_id   TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        message_id    TEXT,
        action        TEXT NOT NULL CHECK (action IN (
          'DIAGNOSTIC_QUEUED', 'DIAGNOSTIC_LEASED',
          'DIAGNOSTIC_RETRY_SCHEDULED', 'DIAGNOSTIC_DELIVERED',
          'DIAGNOSTIC_EXPIRED', 'DIAGNOSTIC_DEAD_LETTERED',
          'DIAGNOSTIC_TOMBSTONE_PURGED', 'DIAGNOSTIC_REJECTED'
        )),
        occurred_at   TEXT NOT NULL,
        event_json    TEXT NOT NULL,
        audit_key_id  TEXT NOT NULL,
        audit_anchor  TEXT NOT NULL
      );
      CREATE INDEX idx_customer_diagnostic_audit_message
        ON public.customer_diagnostic_audit(
          customer_id, deployment_id, message_id, event_seq DESC
        );
      ALTER TABLE public.customer_diagnostic_audit ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.customer_diagnostic_audit FORCE ROW LEVEL SECURITY;
      CREATE POLICY customer_diagnostic_audit_tenant_isolation
        ON public.customer_diagnostic_audit
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE OR REPLACE FUNCTION public.reject_customer_diagnostic_audit_mutation()
      RETURNS trigger LANGUAGE plpgsql
      SET search_path = pg_catalog
      AS $customer_diagnostic_audit_guard$
      BEGIN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = 'customer diagnostic audit is append-only';
      END;
      $customer_diagnostic_audit_guard$;
      CREATE TRIGGER customer_diagnostic_audit_no_update
        BEFORE UPDATE ON public.customer_diagnostic_audit
        FOR EACH ROW EXECUTE FUNCTION public.reject_customer_diagnostic_audit_mutation();
      CREATE TRIGGER customer_diagnostic_audit_no_delete
        BEFORE DELETE ON public.customer_diagnostic_audit
        FOR EACH ROW EXECUTE FUNCTION public.reject_customer_diagnostic_audit_mutation();
    `,
  },
  {
    version: 15,
    name: 'connected-acknowledged-authority-projection',
    // A signed registry verdict plus signed entitlement is applied before its
    // customer acknowledgement can reach the Owner plane. This projection is
    // the authenticated boundary between those two facts. It binds the exact
    // current pair and the last pair whose delivered+applied lifecycle was
    // durably accepted. Missing projection state is deliberately recoverable
    // through a later exact heartbeat replay, but grants no connected authority.
    sqlite: `
      CREATE TABLE connected_authority_pair_lineage (
        pair_digest                     TEXT PRIMARY KEY CHECK (
          length(pair_digest) = 64 AND pair_digest NOT GLOB '*[^0-9a-f]*'
        ),
        customer_id                     TEXT NOT NULL,
        deployment_id                   TEXT NOT NULL,
        transition_kind                 TEXT NOT NULL CHECK (
          transition_kind IN ('entitlement_release', 'registry_only')
        ),
        registry_generation             INTEGER NOT NULL CHECK (registry_generation >= 1),
        registry_state_digest           TEXT NOT NULL CHECK (
          length(registry_state_digest) = 64
          AND registry_state_digest NOT GLOB '*[^0-9a-f]*'
        ),
        registry_status                 TEXT NOT NULL CHECK (registry_status IN ('active', 'revoked')),
        entitlement_version             INTEGER NOT NULL CHECK (entitlement_version >= 1),
        entitlement_digest              TEXT NOT NULL CHECK (
          length(entitlement_digest) = 64 AND entitlement_digest NOT GLOB '*[^0-9a-f]*'
        ),
        artifact_digest                 TEXT NOT NULL CHECK (
          length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'
        ),
        entitlement_status              TEXT NOT NULL CHECK (
          entitlement_status IN ('active', 'paused', 'revoked')
        ),
        authority_json                  TEXT NOT NULL CHECK (length(authority_json) <= 16384),
        entitlement_issued_at           TEXT NOT NULL,
        entitlement_expires_at          TEXT NOT NULL,
        entitlement_fallback_until      TEXT,
        entitlement_reason_code         TEXT NOT NULL,
        entitlement_signing_key_id      TEXT NOT NULL,
        delivered_ack_id                TEXT NOT NULL CHECK (
          length(CAST(delivered_ack_id AS BLOB)) BETWEEN 1 AND 256
        ),
        delivered_ack_payload_digest    TEXT NOT NULL CHECK (
          length(delivered_ack_payload_digest) = 64
          AND delivered_ack_payload_digest NOT GLOB '*[^0-9a-f]*'
        ),
        applied_ack_id                  TEXT NOT NULL CHECK (
          length(CAST(applied_ack_id AS BLOB)) BETWEEN 1 AND 256
        ),
        applied_ack_payload_digest      TEXT NOT NULL CHECK (
          length(applied_ack_payload_digest) = 64
          AND applied_ack_payload_digest NOT GLOB '*[^0-9a-f]*'
        ),
        created_at                      TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, registry_generation, registry_state_digest,
          entitlement_version, entitlement_digest, artifact_digest),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_entitlement_state(customer_id, deployment_id),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_online_registry_state(customer_id, deployment_id)
      );
      CREATE INDEX idx_connected_authority_pair_ack
        ON connected_authority_pair_lineage(
          customer_id, deployment_id, applied_ack_id, applied_ack_payload_digest
        );
      CREATE INDEX idx_connected_authority_pair_high_water
        ON connected_authority_pair_lineage(
          customer_id, deployment_id, registry_generation, entitlement_version
        );
      CREATE TRIGGER connected_authority_pair_no_update
        BEFORE UPDATE ON connected_authority_pair_lineage
        BEGIN SELECT RAISE(ABORT, 'connected authority pair lineage is immutable'); END;

      CREATE TABLE connected_authority_pair_deletions (
        event_seq            INTEGER PRIMARY KEY AUTOINCREMENT,
        event_version        INTEGER NOT NULL CHECK (event_version = 1),
        customer_id          TEXT NOT NULL CHECK (
          length(customer_id) BETWEEN 2 AND 63
        ),
        deployment_id        TEXT NOT NULL CHECK (
          length(deployment_id) = 36
          AND substr(deployment_id, 1, 4) = 'dep_'
          AND substr(deployment_id, 5) NOT GLOB '*[^0-9a-f]*'
        ),
        scope_seq            INTEGER NOT NULL CHECK (scope_seq >= 1),
        transition_kind      TEXT NOT NULL CHECK (
          transition_kind IN ('entitlement_release', 'registry_only')
        ),
        pair_digest          TEXT NOT NULL CHECK (
          length(pair_digest) = 64 AND pair_digest NOT GLOB '*[^0-9a-f]*'
        ),
        registry_generation INTEGER NOT NULL CHECK (registry_generation >= 1),
        entitlement_version INTEGER NOT NULL CHECK (entitlement_version >= 1),
        applied_ack_id       TEXT NOT NULL CHECK (length(applied_ack_id) BETWEEN 1 AND 256),
        applied_ack_payload_digest TEXT NOT NULL CHECK (
          length(applied_ack_payload_digest) = 64
          AND applied_ack_payload_digest NOT GLOB '*[^0-9a-f]*'
        ),
        deleted_at           TEXT NOT NULL CHECK (length(deleted_at) = 24),
        UNIQUE (customer_id, deployment_id, scope_seq)
      );
      CREATE INDEX idx_connected_authority_pair_deletion_scope
        ON connected_authority_pair_deletions(customer_id, deployment_id, scope_seq DESC);
      CREATE TRIGGER connected_authority_pair_record_delete
        AFTER DELETE ON connected_authority_pair_lineage
        BEGIN
          INSERT INTO connected_authority_pair_deletions
            (event_version, customer_id, deployment_id, scope_seq, transition_kind,
             pair_digest, registry_generation, entitlement_version, applied_ack_id,
             applied_ack_payload_digest, deleted_at)
          SELECT 1, OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            OLD.transition_kind, OLD.pair_digest, OLD.registry_generation,
            OLD.entitlement_version, OLD.applied_ack_id, OLD.applied_ack_payload_digest,
            strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
          FROM connected_authority_pair_deletions
          WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
        END;
      CREATE TRIGGER connected_authority_pair_deletions_no_update
        BEFORE UPDATE ON connected_authority_pair_deletions
        BEGIN SELECT RAISE(ABORT, 'connected authority pair deletion log is append-only'); END;
      CREATE TRIGGER connected_authority_pair_deletions_no_delete
        BEFORE DELETE ON connected_authority_pair_deletions
        BEGIN SELECT RAISE(ABORT, 'connected authority pair deletion log is append-only'); END;

      CREATE TABLE connected_acknowledged_authority_state (
        customer_id                    TEXT NOT NULL,
        deployment_id                  TEXT NOT NULL,
        authority_ref                  TEXT NOT NULL UNIQUE,
        current_pair_digest            TEXT NOT NULL UNIQUE,
        current_registry_generation    INTEGER NOT NULL CHECK (current_registry_generation >= 1),
        current_registry_state_digest  TEXT NOT NULL CHECK (
          length(current_registry_state_digest) = 64
          AND current_registry_state_digest NOT GLOB '*[^0-9a-f]*'
        ),
        current_entitlement_version    INTEGER NOT NULL CHECK (current_entitlement_version >= 1),
        current_entitlement_digest     TEXT NOT NULL CHECK (
          length(current_entitlement_digest) = 64
          AND current_entitlement_digest NOT GLOB '*[^0-9a-f]*'
        ),
        acknowledged_registry_generation   INTEGER CHECK (acknowledged_registry_generation >= 1),
        acknowledged_registry_state_digest TEXT CHECK (
          acknowledged_registry_state_digest IS NULL OR (
            length(acknowledged_registry_state_digest) = 64
            AND acknowledged_registry_state_digest NOT GLOB '*[^0-9a-f]*'
          )
        ),
        acknowledged_entitlement_version   INTEGER CHECK (acknowledged_entitlement_version >= 1),
        acknowledged_entitlement_digest    TEXT CHECK (
          acknowledged_entitlement_digest IS NULL OR (
            length(acknowledged_entitlement_digest) = 64
            AND acknowledged_entitlement_digest NOT GLOB '*[^0-9a-f]*'
          )
        ),
        acknowledged_pair_digest       TEXT UNIQUE,
        history_count                  INTEGER NOT NULL CHECK (history_count >= 0),
        history_digest                 TEXT NOT NULL CHECK (
          length(history_digest) = 64 AND history_digest NOT GLOB '*[^0-9a-f]*'
        ),
        deletion_count                 INTEGER NOT NULL CHECK (deletion_count >= 0),
        deletion_high_water            INTEGER NOT NULL CHECK (deletion_high_water >= 0),
        deletion_digest                TEXT NOT NULL CHECK (
          length(deletion_digest) = 64 AND deletion_digest NOT GLOB '*[^0-9a-f]*'
        ),
        state_json                     TEXT NOT NULL,
        updated_at                     TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id),
        CHECK ((acknowledged_registry_generation IS NULL
          AND acknowledged_registry_state_digest IS NULL
          AND acknowledged_entitlement_version IS NULL
          AND acknowledged_entitlement_digest IS NULL
          AND acknowledged_pair_digest IS NULL) OR
          (acknowledged_registry_generation IS NOT NULL
          AND acknowledged_registry_state_digest IS NOT NULL
          AND acknowledged_entitlement_version IS NOT NULL
          AND acknowledged_entitlement_digest IS NOT NULL
          AND acknowledged_pair_digest IS NOT NULL)),
        CHECK ((deletion_count = 0 AND deletion_high_water = 0)
          OR (deletion_count > 0 AND deletion_high_water > 0)),
        CHECK (deletion_count = history_count),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_entitlement_state(customer_id, deployment_id),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES connected_online_registry_state(customer_id, deployment_id),
        FOREIGN KEY (current_pair_digest)
          REFERENCES connected_authority_pair_lineage(pair_digest),
        FOREIGN KEY (acknowledged_pair_digest)
          REFERENCES connected_authority_pair_lineage(pair_digest)
      );
      CREATE INDEX idx_connected_acknowledged_authority_high_water
        ON connected_acknowledged_authority_state(
          customer_id, deployment_id,
          acknowledged_registry_generation DESC,
          acknowledged_entitlement_version DESC
        );
    `,
    postgres: `
      CREATE TABLE public.connected_authority_pair_lineage (
        pair_digest                     TEXT PRIMARY KEY CHECK (pair_digest ~ '^[0-9a-f]{64}$'),
        customer_id                     TEXT NOT NULL,
        deployment_id                   TEXT NOT NULL,
        transition_kind                 TEXT NOT NULL CHECK (
          transition_kind IN ('entitlement_release', 'registry_only')
        ),
        registry_generation             BIGINT NOT NULL CHECK (registry_generation >= 1),
        registry_state_digest           TEXT NOT NULL CHECK (registry_state_digest ~ '^[0-9a-f]{64}$'),
        registry_status                 TEXT NOT NULL CHECK (registry_status IN ('active', 'revoked')),
        entitlement_version             BIGINT NOT NULL CHECK (entitlement_version >= 1),
        entitlement_digest              TEXT NOT NULL CHECK (entitlement_digest ~ '^[0-9a-f]{64}$'),
        artifact_digest                 TEXT NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
        entitlement_status              TEXT NOT NULL CHECK (
          entitlement_status IN ('active', 'paused', 'revoked')
        ),
        authority_json                  TEXT NOT NULL CHECK (octet_length(authority_json) <= 16384),
        entitlement_issued_at           TEXT NOT NULL,
        entitlement_expires_at          TEXT NOT NULL,
        entitlement_fallback_until      TEXT,
        entitlement_reason_code         TEXT NOT NULL,
        entitlement_signing_key_id      TEXT NOT NULL,
        delivered_ack_id                TEXT NOT NULL CHECK (
          octet_length(delivered_ack_id) BETWEEN 1 AND 256
        ),
        delivered_ack_payload_digest    TEXT NOT NULL CHECK (
          delivered_ack_payload_digest ~ '^[0-9a-f]{64}$'
        ),
        applied_ack_id                  TEXT NOT NULL CHECK (
          octet_length(applied_ack_id) BETWEEN 1 AND 256
        ),
        applied_ack_payload_digest      TEXT NOT NULL CHECK (
          applied_ack_payload_digest ~ '^[0-9a-f]{64}$'
        ),
        created_at                      TEXT NOT NULL,
        UNIQUE (customer_id, deployment_id, registry_generation, registry_state_digest,
          entitlement_version, entitlement_digest, artifact_digest),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES public.connected_entitlement_state(customer_id, deployment_id),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES public.connected_online_registry_state(customer_id, deployment_id)
      );
      CREATE INDEX idx_connected_authority_pair_ack
        ON public.connected_authority_pair_lineage(
          customer_id, deployment_id, applied_ack_id, applied_ack_payload_digest
        );
      CREATE INDEX idx_connected_authority_pair_high_water
        ON public.connected_authority_pair_lineage(
          customer_id, deployment_id, registry_generation, entitlement_version
        );
      ALTER TABLE public.connected_authority_pair_lineage ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_authority_pair_lineage FORCE ROW LEVEL SECURITY;
      CREATE POLICY connected_authority_pair_tenant_isolation
        ON public.connected_authority_pair_lineage
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE TABLE public.connected_authority_pair_deletions (
        event_seq            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        event_version        SMALLINT NOT NULL CHECK (event_version = 1),
        customer_id          TEXT NOT NULL CHECK (length(customer_id) BETWEEN 2 AND 63),
        deployment_id        TEXT NOT NULL CHECK (
          deployment_id ~ '^dep_[0-9a-f]{32}$'
        ),
        scope_seq            BIGINT NOT NULL CHECK (scope_seq >= 1),
        transition_kind      TEXT NOT NULL CHECK (
          transition_kind IN ('entitlement_release', 'registry_only')
        ),
        pair_digest          TEXT NOT NULL CHECK (pair_digest ~ '^[0-9a-f]{64}$'),
        registry_generation BIGINT NOT NULL CHECK (registry_generation >= 1),
        entitlement_version BIGINT NOT NULL CHECK (entitlement_version >= 1),
        applied_ack_id       TEXT NOT NULL CHECK (length(applied_ack_id) BETWEEN 1 AND 256),
        applied_ack_payload_digest TEXT NOT NULL CHECK (
          applied_ack_payload_digest ~ '^[0-9a-f]{64}$'
        ),
        deleted_at           TEXT NOT NULL CHECK (length(deleted_at) = 24),
        UNIQUE (customer_id, deployment_id, scope_seq)
      );
      CREATE INDEX idx_connected_authority_pair_deletion_scope
        ON public.connected_authority_pair_deletions(
          customer_id, deployment_id, scope_seq DESC
        );
      ALTER TABLE public.connected_authority_pair_deletions ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_authority_pair_deletions FORCE ROW LEVEL SECURITY;
      CREATE POLICY connected_authority_pair_deletion_tenant_isolation
        ON public.connected_authority_pair_deletions
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      CREATE OR REPLACE FUNCTION public.record_connected_authority_pair_delete()
      RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog
      AS $connected_authority_pair_delete$
      BEGIN
        INSERT INTO public.connected_authority_pair_deletions
          (event_version, customer_id, deployment_id, scope_seq, transition_kind,
           pair_digest, registry_generation, entitlement_version, applied_ack_id,
           applied_ack_payload_digest, deleted_at)
        SELECT 1, OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
          OLD.transition_kind, OLD.pair_digest, OLD.registry_generation,
          OLD.entitlement_version, OLD.applied_ack_id, OLD.applied_ack_payload_digest,
          to_char(pg_catalog.clock_timestamp() AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        FROM public.connected_authority_pair_deletions
        WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
        RETURN OLD;
      END;
      $connected_authority_pair_delete$;
      CREATE TRIGGER connected_authority_pair_record_delete
        AFTER DELETE ON public.connected_authority_pair_lineage
        FOR EACH ROW EXECUTE FUNCTION public.record_connected_authority_pair_delete();
      CREATE OR REPLACE FUNCTION public.reject_connected_authority_pair_update()
      RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog
      AS $connected_authority_pair_update$
      BEGIN
        RAISE EXCEPTION USING ERRCODE = '55000',
          MESSAGE = 'connected authority pair lineage is immutable';
      END;
      $connected_authority_pair_update$;
      CREATE TRIGGER connected_authority_pair_no_update
        BEFORE UPDATE ON public.connected_authority_pair_lineage
        FOR EACH ROW EXECUTE FUNCTION public.reject_connected_authority_pair_update();
      CREATE OR REPLACE FUNCTION public.reject_connected_authority_pair_deletion_mutation()
      RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog
      AS $connected_authority_pair_deletion_guard$
      BEGIN
        RAISE EXCEPTION USING ERRCODE = '55000',
          MESSAGE = 'connected authority pair deletion log is append-only';
      END;
      $connected_authority_pair_deletion_guard$;
      CREATE TRIGGER connected_authority_pair_deletions_no_update
        BEFORE UPDATE ON public.connected_authority_pair_deletions
        FOR EACH ROW EXECUTE FUNCTION public.reject_connected_authority_pair_deletion_mutation();
      CREATE TRIGGER connected_authority_pair_deletions_no_delete
        BEFORE DELETE ON public.connected_authority_pair_deletions
        FOR EACH ROW EXECUTE FUNCTION public.reject_connected_authority_pair_deletion_mutation();

      CREATE TABLE public.connected_acknowledged_authority_state (
        customer_id                    TEXT NOT NULL,
        deployment_id                  TEXT NOT NULL,
        authority_ref                  TEXT NOT NULL UNIQUE,
        current_pair_digest            TEXT NOT NULL UNIQUE,
        current_registry_generation    BIGINT NOT NULL CHECK (current_registry_generation >= 1),
        current_registry_state_digest  TEXT NOT NULL CHECK (
          length(current_registry_state_digest) = 64
          AND current_registry_state_digest ~ '^[0-9a-f]{64}$'
        ),
        current_entitlement_version    BIGINT NOT NULL CHECK (current_entitlement_version >= 1),
        current_entitlement_digest     TEXT NOT NULL CHECK (
          length(current_entitlement_digest) = 64
          AND current_entitlement_digest ~ '^[0-9a-f]{64}$'
        ),
        acknowledged_registry_generation   BIGINT CHECK (acknowledged_registry_generation >= 1),
        acknowledged_registry_state_digest TEXT CHECK (
          acknowledged_registry_state_digest IS NULL
          OR acknowledged_registry_state_digest ~ '^[0-9a-f]{64}$'
        ),
        acknowledged_entitlement_version   BIGINT CHECK (acknowledged_entitlement_version >= 1),
        acknowledged_entitlement_digest    TEXT CHECK (
          acknowledged_entitlement_digest IS NULL
          OR acknowledged_entitlement_digest ~ '^[0-9a-f]{64}$'
        ),
        acknowledged_pair_digest       TEXT UNIQUE,
        history_count                  BIGINT NOT NULL CHECK (history_count >= 0),
        history_digest                 TEXT NOT NULL CHECK (history_digest ~ '^[0-9a-f]{64}$'),
        deletion_count                 BIGINT NOT NULL CHECK (deletion_count >= 0),
        deletion_high_water            BIGINT NOT NULL CHECK (deletion_high_water >= 0),
        deletion_digest                TEXT NOT NULL CHECK (deletion_digest ~ '^[0-9a-f]{64}$'),
        state_json                     TEXT NOT NULL,
        updated_at                     TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id),
        CHECK ((acknowledged_registry_generation IS NULL
          AND acknowledged_registry_state_digest IS NULL
          AND acknowledged_entitlement_version IS NULL
          AND acknowledged_entitlement_digest IS NULL
          AND acknowledged_pair_digest IS NULL) OR
          (acknowledged_registry_generation IS NOT NULL
          AND acknowledged_registry_state_digest IS NOT NULL
          AND acknowledged_entitlement_version IS NOT NULL
          AND acknowledged_entitlement_digest IS NOT NULL
          AND acknowledged_pair_digest IS NOT NULL)),
        CHECK ((deletion_count = 0 AND deletion_high_water = 0)
          OR (deletion_count > 0 AND deletion_high_water > 0)),
        CHECK (deletion_count = history_count),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES public.connected_entitlement_state(customer_id, deployment_id),
        FOREIGN KEY (customer_id, deployment_id)
          REFERENCES public.connected_online_registry_state(customer_id, deployment_id),
        FOREIGN KEY (current_pair_digest)
          REFERENCES public.connected_authority_pair_lineage(pair_digest),
        FOREIGN KEY (acknowledged_pair_digest)
          REFERENCES public.connected_authority_pair_lineage(pair_digest)
      );
      CREATE INDEX idx_connected_acknowledged_authority_high_water
        ON public.connected_acknowledged_authority_state(
          customer_id, deployment_id,
          acknowledged_registry_generation DESC,
          acknowledged_entitlement_version DESC
        );
      ALTER TABLE public.connected_acknowledged_authority_state ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.connected_acknowledged_authority_state FORCE ROW LEVEL SECURITY;
      CREATE POLICY connected_acknowledged_authority_tenant_isolation
        ON public.connected_acknowledged_authority_state
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));
    `,
  },
  {
    version: 16,
    name: 'customer-diagnostic-main-audit-checkpoint',
    sqlite: `
      CREATE TABLE customer_diagnostic_checkpoint (
        customer_id        TEXT NOT NULL,
        deployment_id      TEXT NOT NULL,
        checkpoint_version INTEGER NOT NULL CHECK (checkpoint_version > 0),
        local_audit_count  INTEGER NOT NULL CHECK (local_audit_count >= 0),
        local_audit_seq    INTEGER NOT NULL CHECK (local_audit_seq >= 0),
        local_audit_head   TEXT NOT NULL,
        time_observed_at   TEXT,
        time_state_digest  TEXT NOT NULL,
        row_count          INTEGER NOT NULL CHECK (row_count >= 0),
        pending_count      INTEGER NOT NULL CHECK (pending_count >= 0),
        tombstone_count    INTEGER NOT NULL CHECK (tombstone_count >= 0),
        tombstone_head     TEXT NOT NULL,
        purge_count        INTEGER NOT NULL CHECK (purge_count >= 0),
        purge_seq          INTEGER NOT NULL CHECK (purge_seq >= 0),
        purge_head         TEXT NOT NULL,
        state_digest       TEXT NOT NULL,
        checkpoint_ref     TEXT NOT NULL UNIQUE,
        checkpoint_digest  TEXT NOT NULL,
        main_audit_id      TEXT NOT NULL,
        main_audit_hash    TEXT NOT NULL,
        updated_at         TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id),
        CHECK (pending_count + tombstone_count = row_count),
        CHECK (purge_count <= local_audit_count),
        CHECK (local_audit_seq >= local_audit_count),
        CHECK (purge_seq <= local_audit_seq)
      );

      ALTER TABLE audit ADD COLUMN diagnostic_checkpoint_ref TEXT
        GENERATED ALWAYS AS (json_extract(entry, '$.diagnosticCheckpointRef')) VIRTUAL;
      CREATE INDEX idx_audit_diagnostic_checkpoint
        ON audit(diagnostic_checkpoint_ref, seq DESC)
        WHERE diagnostic_checkpoint_ref IS NOT NULL;
    `,
    postgres: `
      CREATE TABLE public.customer_diagnostic_checkpoint (
        customer_id        TEXT NOT NULL,
        deployment_id      TEXT NOT NULL,
        checkpoint_version BIGINT NOT NULL CHECK (checkpoint_version > 0),
        local_audit_count  BIGINT NOT NULL CHECK (local_audit_count >= 0),
        local_audit_seq    BIGINT NOT NULL CHECK (local_audit_seq >= 0),
        local_audit_head   TEXT NOT NULL,
        time_observed_at   TEXT,
        time_state_digest  TEXT NOT NULL,
        row_count          BIGINT NOT NULL CHECK (row_count >= 0),
        pending_count      BIGINT NOT NULL CHECK (pending_count >= 0),
        tombstone_count    BIGINT NOT NULL CHECK (tombstone_count >= 0),
        tombstone_head     TEXT NOT NULL,
        purge_count        BIGINT NOT NULL CHECK (purge_count >= 0),
        purge_seq          BIGINT NOT NULL CHECK (purge_seq >= 0),
        purge_head         TEXT NOT NULL,
        state_digest       TEXT NOT NULL,
        checkpoint_ref     TEXT NOT NULL UNIQUE,
        checkpoint_digest  TEXT NOT NULL,
        main_audit_id      TEXT NOT NULL,
        main_audit_hash    TEXT NOT NULL,
        updated_at         TEXT NOT NULL,
        PRIMARY KEY (customer_id, deployment_id),
        CHECK (pending_count + tombstone_count = row_count),
        CHECK (purge_count <= local_audit_count),
        CHECK (local_audit_seq >= local_audit_count),
        CHECK (purge_seq <= local_audit_seq)
      );
      ALTER TABLE public.customer_diagnostic_checkpoint ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.customer_diagnostic_checkpoint FORCE ROW LEVEL SECURITY;
      CREATE POLICY customer_diagnostic_checkpoint_tenant_isolation
        ON public.customer_diagnostic_checkpoint
        USING (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('redactwall.org_id', true), '') <> ''
          AND customer_id = current_setting('redactwall.org_id', true));

      ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS diagnostic_checkpoint_ref TEXT
        GENERATED ALWAYS AS ((entry::jsonb ->> 'diagnosticCheckpointRef')) STORED;
      CREATE INDEX IF NOT EXISTS idx_audit_diagnostic_checkpoint
        ON public.audit(diagnostic_checkpoint_ref, seq DESC)
        WHERE diagnostic_checkpoint_ref IS NOT NULL;
    `,
  },
];

module.exports = { MIGRATIONS };
