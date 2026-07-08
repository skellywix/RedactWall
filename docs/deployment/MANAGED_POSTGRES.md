# Managed Postgres Operations

This runbook is for operating the RedactWall control plane on Postgres —
normally a managed service such as Amazon RDS/Aurora, Cloud SQL, or Azure
Database for PostgreSQL. It covers enabling the driver, application-role
setup, schema migrations, timeout and retry tuning, backups and restore
drills, monitoring, and sizing.

## When To Use Postgres

Stay on SQLite unless you are building the shared multi-tenant SaaS plane.
The default local-disk SQLite store is the supported shape for demos, pilots,
and paid customer-silo stacks (one isolated stack per customer, per the
2026-06-26 customer-silo decision in `DECISIONS.md` and
`docs/deployment/AWS_SAAS_DEPLOYMENT.md`). Move to Postgres when you need:

- One control plane serving multiple tenants, with row-level tenant isolation.
- Multiple control-plane replicas behind a load balancer.
- Managed high availability, snapshots, and point-in-time recovery.

Postgres 16 and 17 are exercised in CI.

## Enabling The Driver

```text
REDACTWALL_DB_DRIVER=postgres
REDACTWALL_DATABASE_URL=postgresql://redactwall_app:<password>@db.internal:5432/redactwall?sslmode=require
```

`DATABASE_URL` is accepted as a fallback when `REDACTWALL_DATABASE_URL` is not
set. Always require TLS (`sslmode=require`, or `verify-full` with a CA bundle
when your provider supports it); the connection string carries credentials, so
keep it in your secret manager and never in shell history, logs, or manifests.
RedactWall's own tooling never echoes it.

All control-plane replicas must also share the same `REDACTWALL_SECRET` and
`REDACTWALL_DATA_KEY` so sessions, receipts, and sealed prompts stay valid
across replicas.

## Application Role Setup

Run RedactWall as a dedicated, least-privileged role. The tenant-scoping
migration applies `FORCE ROW LEVEL SECURITY`, so RLS binds even the table
owner — but **superusers and any role with `BYPASSRLS` silently bypass RLS**.
Never point `REDACTWALL_DATABASE_URL` at one.

```sql
CREATE ROLE redactwall_app LOGIN PASSWORD '<from-secret-manager>'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE DATABASE redactwall OWNER redactwall_app;
```

The app role owns its database because schema migrations run automatically at
startup (see below) and must be able to create tables, triggers, and policies.
`FORCE ROW LEVEL SECURITY` is what keeps that ownership safe: the owner is
still policy-bound. Verify the runtime role cannot bypass RLS:

```sql
SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'redactwall_app';
-- rolsuper and rolbypassrls must both be false
```

`test/storage-postgres-rls.test.js` pins this contract in CI: tenant contexts
cannot read, update, delete, or re-tag each other's rows, and a blank
`redactwall.org_id` context is the documented operator mode that sees all
tenants. Set the tenant context per request through the storage layer only;
do not hand out this role for ad-hoc human access.

**Wiring status.** For the customer-silo model (one RedactWall stack per
tenant), the session tenant context is now pinned at startup from the configured
tenant (`db.wireTenantContext`), and the Postgres worker re-applies it across
reconnects — so RLS enforces isolation rather than sitting inert. A blank tenant
context (operator / self-host mode) is fail-open by design. Per-request
multi-tenancy on a **shared** control plane is a separate model: it needs a
transaction-local `SET LOCAL redactwall.org_id` bound on each request, and is
gated behind the shared-SaaS work in `PLANS/platform-roadmap.md`.

## Schema Migrations

Migrations are applied automatically when the process opens the store: on
startup, `server/db.js` calls `runMigrations` from `server/storage/index.js`,
which walks the ordered list in `server/storage/migrations.js` (each migration
ships matching SQLite and Postgres SQL), applies each pending version inside a
transaction, and records it in `schema_migrations`. A database created before
the migration framework existed is stamped at the baseline version instead of
re-running it. There is no separate migrate command.

Upgrade runbook:

1. Take a snapshot (or confirm PITR coverage) before deploying a version that
   adds a migration.
2. Roll one replica first and let it finish startup. Concurrent first-boots
   can race on the `schema_migrations` primary key; the loser fails startup
   and is fixed by restarting it after the winner completes, but rolling one
   instance first avoids the noise.
3. Confirm the history, then roll the rest:

```sql
SELECT version, name, "appliedAt" FROM schema_migrations ORDER BY version;
```

Migrations are forward-only. Rollback is restore-from-backup, not a down
migration — one more reason the drill below should already be routine.

Migration statements run under the same session `statement_timeout` as normal
traffic (default 25 s). If a future migration rewrites a very large table,
raise `REDACTWALL_PG_STATEMENT_TIMEOUT_MS` for that deploy — the bridge's call
timeout follows it automatically — and lower it again afterwards.

## Statement Timeout And Connect Retry

The driver holds one Postgres connection in a worker thread behind a
synchronous bridge (see Monitoring below). Two protections bound it, both
tunable by environment variable:

| Variable | Default | Bounds | Purpose |
| --- | --- | --- | --- |
| `REDACTWALL_PG_STATEMENT_TIMEOUT_MS` | `25000` | 1000–600000 | Session `statement_timeout`. The bridge's own call timeout is always this value + 5000 ms, so the database cancels a runaway statement (error code `57014`) and keeps the connection alive before the bridge gives up. |
| `REDACTWALL_PG_CONNECT_ATTEMPTS` | `5` | 1–20 | Connection attempts per retry cycle, on initial connect and after connection loss. A cycle that exhausts its attempts fails the calling operation with `postgres connect failed after N attempt(s)`; it never loops forever. |
| `REDACTWALL_PG_CONNECT_BASE_DELAY_MS` | `200` | 10–10000 | Base delay for exponential backoff between attempts (200, 400, 800, 1600 ms...; individual delays cap at 15 s). |
| `REDACTWALL_PG_CONNECT_TIMEOUT_MS` | `5000` | 500–60000 | Per-attempt TCP/startup timeout, so a black-holed connect cannot hang a cycle. |

With defaults, a full failed reconnect cycle costs about 28 seconds; requests
issued while the database is down fail with the clear error above rather than
queueing. After the database returns, the next call reconnects automatically.
If you raise `REDACTWALL_PG_CONNECT_ATTEMPTS` or the per-attempt timeout, a
cycle can exceed the bridge call timeout and callers will see
`postgres bridge timeout` instead of the retry error — keep
attempts × connect timeout below `REDACTWALL_PG_STATEMENT_TIMEOUT_MS` + 5000 ms.

## Backups And Restore Drills

The standard backup tooling works on Postgres when the driver is Postgres
(same environment detection as the server):

```bash
npm run backup -- backups          # pg_dump custom-format .dump + manifest
npm run backup:verify -- backups/redactwall-<stamp>.dump
npm run backup:restore -- backups/redactwall-<stamp>.dump <database-name-or-url>
npm run backup:drill               # dump, restore to a scratch DB, verify, drop
```

Behavior on Postgres:

- `backup` drives `pg_dump --format=custom --enable-row-security` and writes
  the same verifier-first manifest as SQLite: hashes, sizes, row counts, and
  the source audit-chain verification result — never prompt bodies and never
  connection credentials (credentials pass to `pg_dump`/`pg_restore` via
  libpq environment variables, not argv). A blank tenant context sees every
  tenant row, so the dump is complete; the drill's count checks would expose
  a partial dump.
- `backup` refuses to run if the live audit chain does not verify, exactly
  like SQLite mode.
- `backup:verify` checks the dump's SHA-256 against the manifest. A dump
  cannot be opened in place, so full audit-chain verification happens on
  restore — which is why the drill exists.
- `backup:restore` verifies the manifest hash first, then runs
  `pg_restore --no-owner --no-privileges --exit-on-error` into the named
  target database (bare name = same server; a full `postgresql://` URL is
  also accepted), then verifies the restored audit chain through the
  production driver. `--force` adds `--clean --if-exists`.
- `backup:drill` restores into a uniquely named scratch database
  (`redactwall_drill_<hex>`), verifies the audit hash-chain and row counts
  there, and always drops the scratch database — `--keep` retains only the
  dump and manifest. The connecting role therefore needs `CREATEDB` for
  drills; either grant it to a dedicated maintenance role or run the drill
  with a separate elevated `REDACTWALL_DATABASE_URL`.
- `pg_dump`/`pg_restore` must be on `PATH` with a major version at least the
  server's (Debian/Ubuntu: `apt-get install postgresql-client`; RHEL/Amazon
  Linux: `dnf install postgresql16`; macOS: `brew install libpq`). If they
  are missing the tools fail with an install hint; they never silently fall
  back to SQLite mode.

On managed Postgres, also enable the provider's automated snapshots and
point-in-time recovery and treat them as the primary disaster-recovery layer;
`pg_dump` backups are the portable, verifier-first evidence layer on top, and
the drill is what proves either path actually restores. After **any** restore
— drill, `pg_restore`, snapshot, or PITR — the restored plane must not serve
traffic until:

```bash
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

As with SQLite, backups do not cover `.env` secrets (`REDACTWALL_DATA_KEY`
above all — sealed prompts in a restored store cannot be revealed without
it), the policy file, or custom detector packs. Capture those through your
secret/configuration management (see "What Backups Do Not Cover" in
`docs/deployment/DEPLOYMENT.md`).

## Monitoring

- `/readyz` exercises the database on every probe (it runs a real stats query
  through the driver) and returns `503` with `database: false` when Postgres
  is unreachable — wire it into your load balancer health checks so a replica
  that lost its connection drops out of rotation while the bounded reconnect
  runs.
- **Single-connection throughput ceiling, stated honestly:** each replica
  holds exactly one Postgres connection, and the control plane's synchronous
  storage contract means the Node main thread blocks (`Atomics.wait`) for the
  duration of every statement. Statements execute strictly one at a time per
  replica, so throughput is bounded by statement latency: ~1 ms round trips
  support hundreds of storage operations per second per replica; a 20 ms
  cross-region hop caps it near 50. Keep the database in the same
  region/VPC as the replicas, and scale by adding replicas (each brings one
  connection). An async driver path for hot read endpoints is future work
  triggered by measured latency, not speculation.
- Alert on `57014` (statement timeout) and `postgres connect failed` /
  `postgres bridge timeout` strings in application logs; all three indicate
  the database, not the application, needs attention. These errors carry no
  prompt text or credentials.
- On the database side, watch connection count (it should be ~replica count
  plus your own tooling), storage growth (the `queries` and append-only
  `audit` tables dominate), and replication/failover events.

## Sizing

The workload is modest: short single-row reads/writes from N replicas, one
connection each, no connection pool. A small managed instance (2 vCPU / 4–8
GB, e.g. `db.t4g.medium`-class) with SSD storage comfortably serves the
control plane at pilot-to-mid scale; grow storage before compute. Provision
IOPS for the audit append path only after `/api/metrics` latency says so.
High availability (multi-AZ, automated failover) matters more than instance
size — during a failover, replicas serve `503` from `/readyz`, retry with
bounded backoff, and recover without restart.
