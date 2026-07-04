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

## Status

Implemented since this file was written: all ten quick wins, plus score
explainability with regulation citations (GLBA/NCUA/PCI/HIPAA chips in the
queue/activity rationale and in block reasons), the Detection Tester, and
cross-sensor fleet awareness (sensors heartbeat, learn about their
companions, and the console shows per-user coverage gaps). Items still open
are marked MISSING below with the reason when deliberate.

## Top 10 highest-value quick wins (all shipped)

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
- [x] HAVE: queue filter chips show live counts (All/Mine/Unassigned/Escalated).
- [x] HAVE: bulk approve/deny - row checkboxes + bulk bar with a shared
  audited note; approvals require the same password step-up as single
  decisions; per-item outcomes report what was skipped and why (50 max).
- [x] HAVE: activity status chips show who decided, when, and the note on
  hover/click.
- [ ] PARTIAL: assignment exists (approver routing) but no inline-editable
  "Assigned to" on the row like MDCA/Netskope incident bulk-edit of severity
  and assignee (Netskope DLP Incidents).
- [x] HAVE: History section in the incident inspector - every audit-chain
  entry for the selected incident (created, reveals, escalations, decision).

## AI Command Center (`#tab-monitor`)

- [x] HAVE: live posture actions, severity glyph legend, real-time counters.
- [x] HAVE: every Command Center metric card is a drill-through button into
  the tab where the operator can act (coverage / integrations / queue /
  activity by metric type).
- [ ] MISSING: policy-action pivot filters at the top — Allowed/Blocked/
  Isolated, sanctioned vs unsanctioned (Zscaler Gen AI report filters;
  Purview app-scope pivots Copilot/Enterprise/Other).
- [ ] MISSING: per-widget CSV download icon (Zscaler About Widgets;
  Netskope widget kebab menu).

## All Activity (`#tab-activity`)

- [x] HAVE: global text filter, severity glyphs, Show more paging.
- [x] HAVE: CSV export honoring active filters (Export CSV on Activity + Audit).
- [x] HAVE: time-range picker (24h/7d/30d/all); saved views remember it.
- [x] HAVE: rows-per-page selector (10/25/50/100) on Activity and Audit.
- [ ] MISSING: column chooser grouped by category (Netskope Customize
  Columns gear icon; Zscaler column checkboxes with select/deselect all).
- [x] HAVE: field query syntax - `user:`, `dest:`, `status:`, `sev:`, `source:`, `action:` tokens in the global search, mixed with free text.
- [x] HAVE: saved views - name the current search + range + page size, reapply from the dropdown (stored locally, 12 max).
- [x] HAVE: pivot shortcuts - SAME USER / SAME DESTINATION buttons in the expanded activity row set the field query.

## Insights (`#tab-insights`)

- [x] HAVE: 7/30/90-day window, top destinations, trend charts.
- [x] PARTIAL->BETTER: window extended to 180/365-day presets; no calendar picker (deliberate - presets cover exam windows).
- [ ] MISSING: scheduled report delivery — emailed PDF/CSV on a
  daily/weekly/monthly cadence (Netskope Schedule delivery gear menu;
  Zscaler weekly/monthly/quarterly links that expire in 15 days).
- [ ] MISSING: exec-facing named reports (Zscaler Executive Insights /
  Company Risk Score; MDCA six-page executive PDF; Nightfall four
  Generate-Reports presets capped at top-15 users).
- [x] HAVE: Export CSV on Insights downloads the daily decision series for the window.

## Coverage (`#tab-coverage`) and Lineage (`#tab-lineage`)

- [x] HAVE: coverage matrix, file-flow lineage views.
- [ ] MISSING: fleet/device table conveniences — bulk enable/disable,
  per-device event-history timeline with a "reason" column, per-service
  pause with default 30-minute window (Netskope Devices page).
- [x] HAVE: per-user fleet matrix with ACTIVE / STALE / MISSING state chips
  (tooltips explain each state and last-seen).
- [x] PARTIAL: sensors stale after 48h are flagged in the fleet matrix and in
  the companion view returned to other sensors; no subscription alert event
  fires yet for staleness.

## App Catalog (`#tab-catalog`)

- [x] HAVE: risk scoring, sanction states, review flow, discovery.
- [x] HAVE: inline add-app and import forms, per-row inline review reason, toast notifications; zero native dialogs remain in the console.
- [x] HAVE: sortable catalog columns and bulk allow/govern/block with a shared audited reason.
- [ ] MISSING: app detail drawer with tabbed Overview/Info/Usage and
  score-factor breakdown (MDCA app page tabs; Netskope CCI seven-category
  breakdown).
- [ ] MISSING: score override with a business-justification note visible to
  other admins (MDCA "Override app score" + App note).
- [ ] MISSING: app compare — side-by-side of 2–3 apps (Netskope CCI Compare
  Apps).
- [x] HAVE: catalog Export CSV (app, host, provider, risk, status, events, sources).

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
- [x] HAVE: Download policy JSON button on Configuration (PDF deliberately skipped - JSON diffs are what change review needs).
- [ ] MISSING: "new policy from search" — convert the current activity
  filter into a policy (MDCA New policy from search).
- [x] HAVE (tester): Detection Tester runs sample text through the live engine + policy with full severity/confidence/points/regulation rationale, in memory only. Context rules / exclusion dictionaries remain policy-file driven.

## Deploy (`#tab-deploy`)

- [x] HAVE (this branch): per-package file name, `application/zip` type,
  size, version, file count, SHA-256, guide path; audited download history
  with actor and timestamp.
- [x] HAVE: per-package "Runs on" line (Chrome/Brave 88+, Edge 88+, Firefox 109+, Node.js 22+).
- [x] HAVE: SHA-256 chip copies the full checksum.
- [x] HAVE: per-package Rollout line pointing at the force-install policy file or runbook.
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
- [x] HAVE: Send test shows a persistent inline "Last test: status / attempts / time" badge on the row.
- [x] HAVE: delivery status legend under the history table (delivered / retrying / failed semantics).
- [ ] MISSING: add/edit destinations in the UI (config file only today);
  competitors run OAuth/wizard flows with scope pickers (Nightfall Slack
  Add-to-Slack, GitHub org picker with all-vs-selected repos).
- [ ] MISSING: per-recipient notification digests with per-class minimum
  severity (Zscaler alert subscriptions).

## Audit Log (`#tab-audit`)

- [x] HAVE: hash-chain integrity banner, JSON evidence export, actor and
  action per row.
- [x] HAVE: audit action-type filter + the field query syntax (actor:, action:) in global search.
- [x] HAVE: audit Export CSV honoring active filters.
- [x] HAVE: retention statement under the integrity banner (append-only, never purged; evidence packs for archives).

## Updates (`#tab-updates`)

- [x] HAVE: update check/apply/restart with role gating.
- [x] PARTIAL: "Release notes" link on the Updates tab opens the configured
  GitHub repository's releases page; per-version known/fixed-issue splits
  need release infrastructure this repo does not have yet.
- [ ] MISSING: rollback affordance — "revert to previous version" flow
  (Zscaler documented revert path).

## Cross-cutting

- [x] HAVE: command palette (Ctrl/Cmd-K), URL tab sync, theme persistence,
  role-gated navigation — none of the four competitors document a command
  palette; keep it.
- [x] HAVE: toast component replaced every alert() in the console.
- [ ] MISSING: async export job center for anything slow (Zscaler Job
  Center with 72-hour expiry; Purview audit jobs with progress %).
- [ ] MISSING: "last updated / data latency" hints on report panels
  (Purview 24-hour ingest note; MDCA scan-order latency notes).

Item counts: Queue 5 · Command Center 3 · Activity 7 · Insights 4 ·
Coverage/Lineage 3 · Catalog 6 · Compliance 2 · Identity 2 · Policy 6 ·
Deploy 5 · Integrations 4 · Audit 3 · Updates 2 · Cross-cutting 3 — 55
tracked items, 10 quick wins above.
