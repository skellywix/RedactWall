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
      CREATE OR REPLACE FUNCTION promptwall_audit_append_only() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'audit log is append-only';
      END;
      $$ LANGUAGE plpgsql;

      DROP TRIGGER IF EXISTS audit_append_only_guard ON audit;
      CREATE TRIGGER audit_append_only_guard
        BEFORE UPDATE OR DELETE ON audit
        FOR EACH ROW EXECUTE FUNCTION promptwall_audit_append_only();
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
        USING (COALESCE(current_setting('promptwall.org_id', true), '') = ''
          OR "orgId" = current_setting('promptwall.org_id', true))
        WITH CHECK (COALESCE(current_setting('promptwall.org_id', true), '') = ''
          OR "orgId" = current_setting('promptwall.org_id', true));
    `,
  },
];

module.exports = { MIGRATIONS };
