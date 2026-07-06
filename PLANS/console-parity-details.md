# Console parity details — the little things competitors have

> **Status (2026-07-06):** Historical parity checklist. The React `/app` console
> reached full parity and the legacy `server/public/index.html` / `dashboard.js`
> referenced below were retired; this file is kept as the record of what was
> ported and why.

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
queue/activity rationale and in block reasons), the Detection Tester,
cross-sensor fleet awareness (sensors heartbeat, learn about their
companions, and the console shows per-user coverage gaps), inline queue
reassignment, SENSOR_STALE staleness alerts, and the monitor decision
chip row. Every remaining unchecked item below is a DELIBERATE SKIP with
its reason inline - the buildable checklist is complete.

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
- [x] HAVE: inline-editable "Assigned to" on the row (Security Admin only) -
  assignee username, group, and role edit in place, audited as
  APPROVAL_REASSIGNED, with empty values returning the item to "anyone in
  the group" (POST /api/queries/:id/assign).
- [x] HAVE: History section in the incident inspector - every audit-chain
  entry for the selected incident (created, reveals, escalations, decision).

## AI Command Center (`#tab-monitor`)

- [x] HAVE: live posture actions, severity glyph legend, real-time counters.
- [x] HAVE: every Command Center metric card is a drill-through button into
  the tab where the operator can act (coverage / integrations / queue /
  activity by metric type).
- [x] HAVE: decision pivot chip row on the monitor - one chip per gate
  outcome with live counts, each drilling into All Activity with the
  matching `status:` field query (in addition to metric drill-throughs).
- [ ] DELIBERATE SKIP: per-widget CSV on the Command Center - Insights owns
  data exports (series + executive summary CSV); monitor cards drill
  through to the acting tab instead of duplicating exports.

## All Activity (`#tab-activity`)

- [x] HAVE: global text filter, severity glyphs, Show more paging.
- [x] HAVE: CSV export honoring active filters (Export CSV on Activity + Audit).
- [x] HAVE: time-range picker (24h/7d/30d/all); saved views remember it.
- [x] HAVE: rows-per-page selector (10/25/50/100) on Activity and Audit.
- [x] HAVE: Columns chooser on All Activity - checkbox menu toggling any of
  the nine columns, persisted locally.
- [x] HAVE: field query syntax - `user:`, `dest:`, `status:`, `sev:`, `source:`, `action:` tokens in the global search, mixed with free text.
- [x] HAVE: saved views - name the current search + range + page size, reapply from the dropdown (stored locally, 12 max).
- [x] HAVE: pivot shortcuts - SAME USER / SAME DESTINATION buttons in the expanded activity row set the field query.

## Insights (`#tab-insights`)

- [x] HAVE: 7/30/90-day window, top destinations, trend charts.
- [x] PARTIAL->BETTER: window extended to 180/365-day presets; no calendar picker (deliberate - presets cover exam windows).
- [x] HAVE: daily digest to any subscription destination with the 'digest'
  event type (24h timer + POST /api/reports/digest/send for on-demand);
  email specifically follows once an SMTP relay is configured.
- [x] HAVE: "Executive summary" export on Insights (decision totals, top
  destinations/users, risk bands as CSV); PDF rendering deliberately
  skipped - CSV drops into any board deck.
- [x] HAVE: Export CSV on Insights downloads the daily decision series for the window.

## Coverage (`#tab-coverage`) and Lineage (`#tab-lineage`)

- [x] HAVE: coverage matrix, file-flow lineage views.
- [ ] DELIBERATE SKIP: remote device enable/disable/pause - sensors have no
  remote-control channel by design (they fail closed on their own); the
  fleet matrix + companion reporting covers visibility.
- [x] HAVE: per-user fleet matrix with ACTIVE / STALE / MISSING state chips
  (tooltips explain each state and last-seen).
- [x] HAVE: sensors stale after 48h are flagged in the fleet matrix and in
  the companion view returned to other sensors, and an hourly sweep fires a
  SENSOR_STALE subscription event (metadata only, once per silence period,
  audited as SENSOR_STALE_ALERTED).

## App Catalog (`#tab-catalog`)

- [x] HAVE: risk scoring, sanction states, review flow, discovery.
- [x] HAVE: inline add-app and import forms, per-row inline review reason, toast notifications; zero native dialogs remain in the console.
- [x] HAVE: sortable catalog columns and bulk allow/govern/block with a shared audited reason.
- [x] HAVE: app detail drawer (click the app name) - provider, region,
  computed vs overridden score, first/last seen, sources with counts,
  risk attributes, owner/notes, and a jump into that app's activity.
- [x] HAVE: analyst score override (0-100) with a required justification
  note, shown to every admin next to the computed score, audited, and
  clearable.
- [ ] DELIBERATE SKIP: app compare - the sortable table with the detail
  drawer covers the comparison job at our catalog size (<100 apps).
- [x] HAVE: catalog Export CSV (app, host, provider, risk, status, events, sources).

## Compliance (`#tab-compliance`)

- [x] HAVE: control readiness, evidence pack export, regulation templates.
- [x] HAVE: "Recommended next steps" cards on Compliance - every
  attention-state control becomes a card that jumps into Configuration.
- [x] HAVE: controls CSV export on Compliance (control, state, frameworks,
  summary); exports are instant here so no deferred-download area needed.

## Identity (`#tab-identity`)

- [x] HAVE: OIDC/SCIM setup, seats, role mapping, step-up.
- [x] HAVE: "Test configuration" on Identity - config-completeness check for
  OIDC, redirect URI, SCIM token, and break-glass account with a checked-at
  timestamp, recorded in the audit log.
- [ ] DELIBERATE SKIP: separate identity exclusion lists - policy scopes
  and the SCIM default-auditor floor cover exclusion semantics; a reason
  field there would duplicate scope notes.

## Configuration / Policy (`#tab-policy`)

- [x] HAVE: policy editor, templates, signed bundles, impact preview.
- [ ] DELIBERATE SKIP: rule clone/reorder - RedactWall policy is a single
  document with scoped overlays, not an ordered rule list; there is no
  rule-order to manage, which is itself the examiner-friendly design.
- [ ] DELIBERATE SKIP: rule labels - scoped-enforcement entries carry ids
  and human-readable matchers; labels add a second naming system.
- [x] PARTIAL: policy impact preview replays recent traffic against a
  proposed policy before saving (policy-impact-preview.js); a standing
  simulation *mode* with its own dashboard is future work.
- [x] HAVE: Download policy JSON button on Configuration (PDF deliberately skipped - JSON diffs are what change review needs).
- [ ] DELIBERATE SKIP: new-policy-from-search - the activity pivots put the
  user/destination on the clipboard-equivalent (search box) and the scope
  builders accept them directly; auto-conversion risks over-broad scopes.
- [x] HAVE (tester): Detection Tester runs sample text through the live engine + policy with full severity/confidence/points/regulation rationale, in memory only. Context rules / exclusion dictionaries remain policy-file driven.

## Deploy (`#tab-deploy`)

- [x] HAVE (this branch): per-package file name, `application/zip` type,
  size, version, file count, SHA-256, guide path; audited download history
  with actor and timestamp.
- [x] HAVE: per-package "Runs on" line (Chrome/Brave 88+, Edge 88+, Firefox 109+, Node.js 22+).
- [x] HAVE: SHA-256 chip copies the full checksum.
- [x] HAVE: per-package Rollout line pointing at the force-install policy file or runbook.
- [ ] DELIBERATE SKIP: per-version release notes on Deploy - packages are
  built from the running tree, so there is exactly one live version; the
  Updates tab links to the GitHub releases page for history.
- [ ] DELIBERATE SKIP: staged rollout controls - out of scope for zip
  downloads; revisit if auto-update channels arrive.

## Integrations (`#tab-integrations`)

- [x] HAVE: SIEM package export, subscriptions with Send test, delivery
  history.
- [x] HAVE: Send test shows a persistent inline "Last test: status / attempts / time" badge on the row.
- [x] HAVE: delivery status legend under the history table (delivered / retrying / failed semantics).
- [ ] DELIBERATE SKIP: destination CRUD in the UI - destinations carry
  secrets (tokens/webhook URLs) that we keep out of browser round-trips by
  design; config/subscriptions.json is the reviewed, versioned path.
- [x] PARTIAL: destinations already carry minRisk/minSeverity/eventTypes
  floors, and the new daily digest targets any destination subscribed to
  the 'digest' event type; per-human email recipients follow with SMTP.

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
- [ ] DELIBERATE SKIP: rollback - the updater is fast-forward-only by
  design; reverting means redeploying the previous release per the install
  runbook, which keeps the audit chain append-only.

## Cross-cutting

- [x] HAVE: command palette (Ctrl/Cmd-K), URL tab sync, theme persistence,
  role-gated navigation — none of the four competitors document a command
  palette; keep it.
- [x] HAVE: toast component replaced every alert() in the console.
- [ ] DELIBERATE SKIP: async export job center - every export here is
  client-side and instant; revisit if server-rendered exports arrive.
- [x] HAVE: LAST UPDATED clock in the topbar, UPDATED stamp on Overview and
  the Command Center, checked-at on identity tests, last-test badges on
  integrations - every live panel says how fresh it is.

Item counts: Queue 5 · Command Center 3 · Activity 7 · Insights 4 ·
Coverage/Lineage 3 · Catalog 6 · Compliance 2 · Identity 2 · Policy 6 ·
Deploy 5 · Integrations 4 · Audit 3 · Updates 2 · Cross-cutting 3 — 55
tracked items, 10 quick wins above.
