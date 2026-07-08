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
];

module.exports = { MIGRATIONS };
