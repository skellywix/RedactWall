# Console parity details — the little things competitors have

Method: four research passes over public knowledge bases — Netskope
(docs.netskope.com: Skope IT, Client deployment, CCI, Advanced Analytics),
Zscaler (help.zscaler.com: Insights Logs, Client Connector App Store, Gen AI
Security Report, Audit Logs, Cloud NSS), Microsoft (learn.microsoft.com:
Purview DSPM for AI, Activity explorer, Audit search, Defender for Cloud
Apps), and Nightfall (help.nightfall.ai: Events, Detectors, Dashboard,
GenAI plugin) — compared against the actual markup in
`server/public/index.html` (per `section#tab-*`) and the loaders in
`server/public/dashboard.js`. This file tracks console conveniences, not
platform features; each line names where the pattern was seen so we can
read the source doc before copying it.

Legend: **HAVE** shipped · **PARTIAL** exists but thinner than competitors ·
**MISSING** not in our console.

## Top 10 highest-value quick wins

1. **CSV export on All Activity and Audit Log** — every competitor exports
   tables to CSV (Netskope Skope IT async export, Zscaler Insights 100K–1M
   rows, MDCA Activity log Export button, Nightfall emailed CSV). We only
   export a JSON evidence pack. Client-side CSV of the loaded rows is a
   one-function win in `dashboard.js`.
2. **Audit Log filters: action type + actor + date** — Zscaler audit logs
   filter by time range, action, category, admin ID; Purview audit search is
   a whole filterable job system. Ours is a fixed table + global text filter.
3. **Rows-per-page selector (10/20/50/100)** on activity/lineage/audit —
   Netskope bottom-right selector (10–100), Nightfall pages at 50. Ours is a
   hardcoded 10 with a Show-more.
4. **Time-range picker on All Activity** — Netskope defaults to "last 7 days"
   and remembers the choice; Nightfall has 7/30/90/180-day chips. Our only
   range picker lives in Insights.
5. **Deploy: per-package requirements + copy-able checksum + install hint** —
   Zscaler App Store lists platform per row and release notes per version;
   Netskope docs publish the exact `msiexec` one-liner and an OS-support
   matrix. We now show file metadata, but not "runs on what" or how to
   install silently.
6. **Kill `prompt()`/`alert()` flows** — Catalog add/import/review-reason and
   Integrations "Send test" results use native dialogs. Competitors use
   inline flyouts/toasts everywhere (MDCA drawer, Nightfall side panel).
7. **Status filter chips on Approval Queue** — Nightfall presents event
   status as tabs (Active/Pending/Resolved/Ignored) with per-status counts;
   MDCA alerts filter New/In progress/Resolved.
8. **Shareable filtered-view URL** — Nightfall's Share button encodes all
   active filters in the URL. We already sync `?tab=` — extend it to the
   global filter and time range.
9. **App Catalog: sortable columns + bulk tag/sanction** — MDCA bulk-selects
   rows to unsanction; Netskope Edit Tags dialog has preset Sanctioned/
   Unsanctioned pairs. Our catalog rows are one-at-a-time.
10. **Empty states that set expectations** — Purview reports say "allow 24
    hours" before data appears; MDCA shows a persistent processing banner
    after log upload. Our empty states mostly say "no data".

## Approval Queue (`#tab-queue`)

- [x] HAVE: one-click approve/deny with reason, severity chips, redacted
  preview (core parity with Nightfall event actions).
- [ ] MISSING: status tabs/chips with counts — Active/Pending/Resolved views
  (Nightfall Event Status tabs; MDCA alert statuses New/In progress/Resolved).
- [ ] MISSING: bulk actions with a scope picker — "50 on screen" vs "all
  matching filter", single-integration guard (Nightfall Applying Bulk Actions).
- [ ] MISSING: hover on a status showing who set it and when (Nightfall
  Events status cell hover).
- [ ] PARTIAL: assignment exists (approver routing) but no inline-editable
  "Assigned to" on the row like MDCA/Netskope incident bulk-edit of severity
  and assignee (Netskope DLP Incidents).
- [ ] MISSING: per-row activity log section in the detail view — what
  happened to this event so far (Nightfall event side panel section 3).

## AI Command Center (`#tab-monitor`)

- [x] HAVE: live posture actions, severity glyph legend, real-time counters.
- [ ] MISSING: "Analyze more" drill-through links from every widget into the
  filtered activity view (Zscaler Gen AI Security Report widgets; Purview
  reports drill into Activity explorer).
- [ ] MISSING: policy-action pivot filters at the top — Allowed/Blocked/
  Isolated, sanctioned vs unsanctioned (Zscaler Gen AI report filters;
  Purview app-scope pivots Copilot/Enterprise/Other).
- [ ] MISSING: per-widget CSV download icon (Zscaler About Widgets;
  Netskope widget kebab menu).

## All Activity (`#tab-activity`)

- [x] HAVE: global text filter, severity glyphs, Show more paging.
- [ ] MISSING: CSV export honoring active filters (quick win #1).
- [ ] MISSING: time-range picker with remembered selection (quick win #4;
  Netskope restores your last range).
- [ ] MISSING: rows-per-page selector (quick win #3).
- [ ] MISSING: column chooser grouped by category (Netskope Customize
  Columns gear icon; Zscaler column checkboxes with select/deselect all).
- [ ] MISSING: field-level query syntax (`user like john`, `action eq
  BLOCKED`) or per-column search (Netskope Skope IT query language; Zscaler
  per-column magnifying glass).
- [ ] MISSING: saved filters / saved views (Netskope Save Filter; MDCA
  "Save as" named queries + 8 suggested starter queries).
- [ ] MISSING: row flyout with pivot shortcuts — same user / same
  destination / same 48 hours, add-any-field-to-filter (MDCA activity
  drawer funnel icons).

## Insights (`#tab-insights`)

- [x] HAVE: 7/30/90-day window, top destinations, trend charts.
- [ ] PARTIAL: no custom date range with calendar (Zscaler custom range up
  to 92 days; Nightfall custom range on Dashboard).
- [ ] MISSING: scheduled report delivery — emailed PDF/CSV on a
  daily/weekly/monthly cadence (Netskope Schedule delivery gear menu;
  Zscaler weekly/monthly/quarterly links that expire in 15 days).
- [ ] MISSING: exec-facing named reports (Zscaler Executive Insights /
  Company Risk Score; MDCA six-page executive PDF; Nightfall four
  Generate-Reports presets capped at top-15 users).
- [ ] MISSING: per-chart CSV download (Zscaler per-widget/per-column
  Download icons).

## Coverage (`#tab-coverage`) and Lineage (`#tab-lineage`)

- [x] HAVE: coverage matrix, file-flow lineage views.
- [ ] MISSING: fleet/device table conveniences — bulk enable/disable,
  per-device event-history timeline with a "reason" column, per-service
  pause with default 30-minute window (Netskope Devices page).
- [ ] MISSING: device state taxonomy surfaced as a legend — Registered /
  Removal Pending / Quarantined etc. (Zscaler Client Connector device
  states).
- [ ] MISSING: stale-sensor alerting — automatic alert when no data for 48
  hours, disk-full warning on collectors (MDCA log collector health).

## App Catalog (`#tab-catalog`)

- [x] HAVE: risk scoring, sanction states, review flow, discovery.
- [ ] PARTIAL: `prompt()`/`alert()` for add/import/review reason — needs
  inline forms (quick win #6).
- [ ] MISSING: sortable columns and bulk tag/sanction with row checkboxes
  (MDCA discovered apps; Netskope Edit Tags preset pairs).
- [ ] MISSING: app detail drawer with tabbed Overview/Info/Usage and
  score-factor breakdown (MDCA app page tabs; Netskope CCI seven-category
  breakdown).
- [ ] MISSING: score override with a business-justification note visible to
  other admins (MDCA "Override app score" + App note).
- [ ] MISSING: app compare — side-by-side of 2–3 apps (Netskope CCI Compare
  Apps).
- [ ] MISSING: catalog export (Netskope publishes the category list as
  XLSX; MDCA exports discovered apps).

## Compliance (`#tab-compliance`)

- [x] HAVE: control readiness, evidence pack export, regulation templates.
- [ ] MISSING: recommendation cards with one-click preconfigured policy
  creation and a verify-status flyout (Purview DSPM "Get started" checks
  and "Fortify your data security" cards).
- [ ] MISSING: policies-overview export for a chosen time range, downloadable
  later from an "Exported reports" area (MDCA Policies Export button).

## Identity (`#tab-identity`)

- [x] HAVE: OIDC/SCIM setup, seats, role mapping, step-up.
- [ ] MISSING: per-connector "Test now" style check for OIDC/SCIM with
  last-tested timestamp (MDCA connector Test now; Zscaler NSS feeds show
  last connectivity test time).
- [ ] MISSING: exclusion lists with a reason field (MDCA Exclude entities
  tabs with recommended free-text reason).

## Configuration / Policy (`#tab-policy`)

- [x] HAVE: policy editor, templates, signed bundles, impact preview.
- [ ] MISSING: policy list conveniences — clone/duplicate, enable/disable
  toggle that keeps order slot, drag-reorder with a pending "Apply Changes"
  model (Netskope Real-time Protection kebab menu Clone/Revert/Disable/
  Move; Zscaler disabled rules keep their rule-order slot).
- [ ] MISSING: rule labels for grouping/filtering policies (Zscaler Rule
  Labels first-class field).
- [ ] MISSING: simulation mode — run policy without enforcement, report
  what would have matched, then one-click enforce (Purview DLP simulation
  mode with/without policy tips).
- [ ] MISSING: download policy as PDF/JSON for change review (Zscaler
  Downloading and Printing Policies).
- [ ] MISSING: "new policy from search" — convert the current activity
  filter into a policy (MDCA New policy from search).
- [ ] MISSING: detector aids — regex tester/playground link, curated regex
  library, context "hot words" rules, exclusion dictionaries with file
  upload, minimum-findings threshold (Nightfall detector editor family).

## Deploy (`#tab-deploy`)

- [x] HAVE (this branch): per-package file name, `application/zip` type,
  size, version, file count, SHA-256, guide path; audited download history
  with actor and timestamp.
- [ ] MISSING: per-package requirements line — browser/OS floor, Node
  runtime (Zscaler App Store lists platform per row; Netskope OS-support
  matrix page; our Firefox build already pins `strict_min_version: 109.0`).
- [ ] MISSING: copy-to-clipboard for the full checksum (Zscaler/Netskope
  publish hashes for installer verification).
- [ ] MISSING: silent-install / force-install hint per package — the
  Netskope `msiexec /I NSClient.msi host=… token=… /qn` analog; ours is
  Chrome `ExtensionInstallForcelist`, Edge/Firefox policies, agent env vars
  (Netskope Client for Windows; Nightfall plugin deployment via Google
  Admin/MDM/GPO).
- [ ] MISSING: release-notes/version-history view per package beyond the
  download log (Zscaler Information icon per version row; Netskope Golden
  Release pages). Needs release infrastructure — note as spec'd, not
  implementable while packages are built from the running tree.
- [ ] MISSING: staged rollout controls (Zscaler Mass vs Phased Rollout with
  pause/resume) — out of scope for zip downloads; revisit if we add
  auto-update channels.

## Integrations (`#tab-integrations`)

- [x] HAVE: SIEM package export, subscriptions with Send test, delivery
  history.
- [ ] PARTIAL: "Send test" result lands in `alert()` — should be an inline
  status with the last-tested timestamp persisted next to the destination
  (Zscaler Cloud NSS shows timestamp of last connectivity test; MDCA Test
  now link).
- [ ] MISSING: documented feed-health semantics as a status legend — what
  delivered/retrying/dropped mean (Zscaler NSS: 200/204 delivered, 400
  dropped, else retry 1 hour).
- [ ] MISSING: add/edit destinations in the UI (config file only today);
  competitors run OAuth/wizard flows with scope pickers (Nightfall Slack
  Add-to-Slack, GitHub org picker with all-vs-selected repos).
- [ ] MISSING: per-recipient notification digests with per-class minimum
  severity (Zscaler alert subscriptions).

## Audit Log (`#tab-audit`)

- [x] HAVE: hash-chain integrity banner, JSON evidence export, actor and
  action per row.
- [ ] MISSING: filters — time range, action type, actor, plus search by
  resource (Zscaler audit-log filters; Purview audit search).
- [ ] MISSING: CSV download (Zscaler audit CSV; quick win #1).
- [ ] MISSING: retention statement in the UI — "kept N months" (Zscaler
  states 6 months; Purview edition-gated export caps).

## Updates (`#tab-updates`)

- [x] HAVE: update check/apply/restart with role gating.
- [ ] MISSING: release-notes link per available version and a
  known-issues/fixed-issues split (Netskope versioned release-note pages
  with issue IDs; Zscaler per-version Information icon).
- [ ] MISSING: rollback affordance — "revert to previous version" flow
  (Zscaler documented revert path).

## Cross-cutting

- [x] HAVE: command palette (Ctrl/Cmd-K), URL tab sync, theme persistence,
  role-gated navigation — none of the four competitors document a command
  palette; keep it.
- [ ] MISSING: toast notifications for async completions instead of
  `alert()` (MDCA top-right toast after log upload).
- [ ] MISSING: async export job center for anything slow (Zscaler Job
  Center with 72-hour expiry; Purview audit jobs with progress %).
- [ ] MISSING: "last updated / data latency" hints on report panels
  (Purview 24-hour ingest note; MDCA scan-order latency notes).

Item counts: Queue 5 · Command Center 3 · Activity 7 · Insights 4 ·
Coverage/Lineage 3 · Catalog 6 · Compliance 2 · Identity 2 · Policy 6 ·
Deploy 5 · Integrations 4 · Audit 3 · Updates 2 · Cross-cutting 3 — 55
tracked items, 10 quick wins above.
