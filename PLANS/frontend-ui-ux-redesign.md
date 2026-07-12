# Frontend UI/UX redesign and delivery plan

- Status: active
- Owner: Frontend Engineering
- Supporting owners: Product, Backend Engineering, QA, Security Engineering, DevOps
- Branch: `codex/frontend-ui-redesign`
- Worktree: `C:\Users\Eric\Desktop\Coding_Projects\RedactWall-ui-redesign`
- Baseline: local `main` commit `b0b3552` (`GG`)

## Goal and context

Redesign the existing RedactWall operator console into a cohesive, accessible,
responsive, production-ready security workbench without changing its security
semantics or inventing backend behavior. Preserve the existing React console,
role-scoped navigation, approval workflows, dark and light themes, and animated
AI exposure map. Improve the hierarchy, reusable design system, responsive
shell, state truthfulness, map controls, and maintainability. Add UI only for
backend capabilities that already exist and can be exercised safely.

The current frontend is already broad and product-specific. It has 18 lazy
routes, strong privacy copy, meaningful operator workflows, and a useful map.
The redesign should refine this foundation rather than replace it.

## Concurrent work and integration boundary

The primary `RedactWall` worktree is intentionally not used for frontend edits.
Another session is changing security-sensitive audit, storage, authentication,
backup, gateway-token, deployment, and test files directly on `main`.

Current boundary:

- Frontend work happens only in `RedactWall-ui-redesign`.
- Do not touch the other session's active files, including `AGENTS.md`,
  `server/audit-anchor.js`, `server/storage/index.js`, `server/private-path.js`,
  `server/auth.js`, `scripts/backup-store.js`, `gateway/tokens.js`, related
  deployment docs, or their tests. One reviewed frontend contract gap requires
  an additive `server/db.js` field named `held`, which combines approval and
  justification holds while preserving the legacy exact `pending` field. Keep
  that one-line change isolated and resolve it explicitly when the backend
  session's database work is integrated.
- After the backend session commits, merge or rebase the updated `main` into the
  UI branch and repeat all validation from a clean process.
- The current backend diff has an open review concern around failure after
  pending audit high-water publication. Do not merge the combined result until
  that boundary and the real Windows/Postgres paths are proven.
- `origin/main` advanced during implementation to `eedda77` with the credit
  union P1 batch and v0.4.0. Both local branches still descend from `b0b3552`,
  whose merge base with the remote line is `4084483`.
- A read-only merge-tree check predicts content conflicts in `CHANGELOG.md`,
  `scripts/edm-fingerprint.js`, and `server/db.js`. Resolve those only after the
  backend session commits, preserving both the v0.4.0/FFIEC work and the newer
  audit/storage protocol. The only direct remote/frontend overlap is the FFIEC
  framework entry in Compliance, which this branch has already incorporated.

## Non-negotiable invariants

- No raw PII, prompt text, secrets, tokens, or sensitive filenames may appear in
  UI logs, error text, analytics, screenshots, fixtures, or audit entries.
- Queue, reveal, approval, authorization, CSRF, step-up, and role decisions stay
  server-authoritative.
- `alwaysBlock` behavior and detector logic are out of scope. If an integration
  unexpectedly touches detection, use `detection-engine/detect.js` only, run
  `npm run sync-engine`, and keep `npm run sync-check` and `npm run eval` green.
- Do not weaken audit-chain, storage, backup, authentication, or permission
  behavior to make browser tests pass.
- Do not add a frontend dependency unless native React, HTML, CSS, and the
  existing Playwright stack cannot satisfy a requirement.
- No third-party visual assets are planned. Existing repository-owned SVG
  iconography will be reused or extended with original inline SVG.
- Preserve the current backend route contracts and hash-route deep links.
- WCAG 2.2 Level AA is the acceptance baseline.

## Current architecture

| Area | Current implementation |
| --- | --- |
| Framework | React 19, TypeScript 6, Vite 8 |
| Delivery | `/app/` bundle emitted to ignored `server/public/app/` and served behind Express authentication |
| Routing | Dependency-free hash routing in `console/src/lib/router.ts` |
| Shell | `App` with `NavRail`, `Topbar`, `CommandPalette`, and lazy-loaded views |
| State | View-local React hooks, same-origin API wrapper, cookie session, SSE, limited local storage |
| Authorization | Backend authoritative, with role-filtered routes and mutation controls in the UI |
| Styling | `console-base.css`, `console-theme.css`, `app.css`, and view CSS with overlapping legacy tokens |
| Tests | Node tests, Playwright console suites, black-box `suite/`, full `review:ci` gate |

### Route inventory

| Group | Routes |
| --- | --- |
| Member Defense | Overview, Member Data Queue, Command Center, Exam Activity |
| Risk & Proof | Insights, Coverage, Lineage, Decision Quality, Examiner Audit Chain |
| Governance | AI Vendor Catalog, NCUA / GLBA Controls, Texas FCU Readiness, Policy Configuration |
| Administration | Users & Roles, Licensing, Sensor Rollout, Evidence Delivery, Controlled Updates |

Secondary surfaces in scope for visual consistency are the sign-in page,
invitation acceptance page, extension popup, extension enforcement dialog and
toasts, coverage-required page, and isolated reveal page. The React console is
the first delivery priority.

## Audit findings that drive the redesign

### Strengths to preserve

- Product-specific information architecture and credit-union language.
- Strong privacy posture with sanitized, masked, and prompt-free evidence.
- Role-scoped navigation and server-backed permissions.
- Approval step-up, bulk decisions, reassignment, history, staff lifecycle,
  licensing, NCUA, policy, deployment, audit, and update workflows.
- Dark and light themes, semantic status colors, route chunking, and a current
  raw bundle comfortably under the existing asset budget.
- The team-to-control-to-destination exposure map and its inspector.

### Gaps to fix

- Mobile navigation expands all routes into a large wrapped header below
  900px. Replace it with an accessible drawer/disclosure pattern.
- `console-base.css` and `console-theme.css` duplicate core tokens while
  `app.css` compensates for leaked legacy layout rules.
- Command Center and Policy are oversized, card-heavy monoliths with too many
  empty panels visible at once.
- The map becomes an 820px horizontal scroller on mobile, has no zoom/pan/fit
  controls, and its edges are pointer-only.
- Queue fetch failure is converted into an empty array, which can falsely claim
  that the queue is clear.
- Audit and Compliance can expose evidence controls to roles that receive a
  backend 403 instead of showing an explicit permission state.
- The command palette restores focus but does not keep focus contained while
  its modal is open.
- Login and invitation pages duplicate large inline style systems.
- Screenshot coverage is desktop-only and omits the Licensing page.
- No dedicated automated accessibility assertions exist.

## Backend capabilities to expose

These are high-confidence frontend gaps because the backend routes already
exist and have relevant authorization:

1. `GET /api/security/package`
   - Add a trust-package action and permission state in Compliance or Evidence
     Delivery.
   - Do not expose secret configuration or raw evidence.
2. `POST /api/receipts/verify`
   - Add a bounded receipt verifier to Examiner Audit Chain.
   - Keep input local to the request and render only the whitelisted result.
3. `POST /api/tickets/sync`
   - Add an admin-only ticket-status sync action in Queue or Exam Activity.
   - Show progress, counts, partial failure, and last-success state truthfully.

Do not duplicate `/api/metrics`, `/api/risk`, or `/api/billing/*`; existing
Overview, Insights, Audit, and Licensing workflows already cover their operator
jobs. Sensor, SCIM, OpenAPI, and release-token routes remain integration APIs,
not missing console screens.

## Design direction

### Point of view

Keep the existing "Examiner's Instrument" identity: calm, authoritative,
dense but legible, and appropriate for a regulated financial institution.
Avoid playful SaaS styling, decorative gradients, ambient artwork, excessive
cards, and motion without an operational purpose.

### Typography

- Retain the dependency-free system UI stack.
- Use a deliberate scale for page titles, section headings, body copy, labels,
  and annotations instead of relying on uppercase microcopy everywhere.
- Use tabular numerals for audit ids, timestamps, risk scores, counts, and
  evidence metrics.
- Preserve readable line lengths and allow 200% text resizing.

### Color and status

- Graphite and paper neutrals remain the primary surfaces.
- Iris remains the interaction and selection color, not decoration.
- Critical/block is red, high/justify is amber, warn is yellow, safe/allow is
  green, and informational state is iris.
- Every state uses text plus icon, glyph, border, or shape. Color is never the
  only cue.
- Essential text meets 4.5:1 contrast and interactive boundaries meet 3:1.

### Spacing, shape, and elevation

- Establish shared `--space-*`, `--size-*`, `--text-*`, `--radius-*`,
  `--shadow-*`, and `--motion-*` tokens.
- Use hairline borders and limited elevation to express nesting.
- Keep primary touch targets at 44px on mobile and all targets at least 24px.
- Use panels for task boundaries, not as wrappers around every sentence or
  empty state.

### Motion

- Keep transitions short and purposeful.
- Preserve the map's directional flow and queue-settle cues.
- Add a visible map animation pause control.
- Under `prefers-reduced-motion`, remove flowing dashes, pulses, animated zoom,
  layout travel, and decorative transitions.

## Options considered

### Option A: CSS-only visual reskin

Pros:

- Smallest diff and fastest local validation.
- Low risk to data and authorization behavior.

Cons:

- Leaves false-empty states, mobile navigation, map keyboard gaps, oversized
  workflows, and missing backend coverage unresolved.
- Keeps the duplicated legacy design layers and weak maintainability.

### Option B: Incremental React redesign in place

Pros:

- Preserves every route and backend contract.
- Allows shared foundations first, then workflow-by-workflow delivery.
- Supports focused regression tests and easy comparison with baseline images.
- Keeps the diff reviewable and lets security work merge independently.

Cons:

- Requires careful compatibility work while legacy classes are retired.
- Needs multiple screenshot and regression loops.

### Option C: New component framework or full frontend rewrite

Pros:

- Could produce a clean component API quickly.

Cons:

- Adds dependencies and supply-chain surface.
- Risks functional, accessibility, CSP, and permission regressions across 18
  existing routes.
- Makes comparison with the proven backend wiring much harder.

### Recommendation

Use Option B. Normalize foundations in place, migrate the highest-value
workflows first, and keep compatibility shims until all affected views have
browser proof.

## Adopted product decisions

No blocking product decision is required before implementation. The following
defaults are adopted unless the product owner changes them:

- WCAG 2.2 AA is the release target.
- Dark remains the default theme and the persisted theme choice remains.
- Existing route grouping and deep links remain stable.
- Mobile uses a modal navigation drawer opened from the top bar.
- Policy uses guided sections with an advanced disclosure, not a separate rule
  engine or reordered policy semantics.
- Command Center uses task-first progressive disclosure and collapses redundant
  empty modules into a concise readiness state.
- The map offers Map and Details modes, keyboard-equivalent selection, bounded
  zoom/pan controls, Fit, Reset, and Pause.
- Security package, receipt verification, and ticket sync are added only through
  their existing backend APIs and role requirements.
- No new production dependency or third-party asset is planned.

## Implementation plan

### Slice 1: Baseline, test matrix, and design-system foundation

Primary files:

- `server/public/console-base.css`
- `server/public/console-theme.css`
- `console/src/app.css`
- `console/src/components/Panel.tsx`
- new shared presentation components under `console/src/components/system/`
- `docs/frontend/DESIGN_SYSTEM.md`
- `e2e/console-design.spec.js`

Work:

- Preserve the 34 existing desktop baseline screenshots as ignored evidence.
- Add Licensing to all-view screenshot coverage.
- Consolidate authoritative tokens into one documented layer.
- Add shared page header, status, button, field, toolbar, empty, unavailable,
  stale, permission, and success patterns.
- Add a skip link, global focus treatment, forced-colors support, reduced-motion
  treatment, and consistent target sizing.
- Keep the existing asset budget and CSP posture.

Evidence:

- `npm run console:check`
- `npm run console:build`
- focused design-system browser assertions

### Slice 2: Responsive and accessible application shell

Primary files:

- `console/src/App.tsx`
- `console/src/app.css`
- `console/src/components/NavRail.tsx`
- `console/src/components/Topbar.tsx`
- `console/src/components/CommandPalette.tsx`
- `console/src/components/ThemeToggle.tsx`

Work:

- Keep the desktop rail but improve hierarchy and short-height behavior.
- Add a labeled mobile menu button, modal drawer, backdrop, Escape close,
  outside close, focus containment, and focus restoration.
- Close the drawer after navigation and preserve route/role filtering.
- Make the current route and tenant/environment context clear in the top bar.
- Trap focus correctly in the command palette and restore it to the launcher.
- Ensure sticky UI never obscures keyboard focus.

Evidence:

- Keyboard-only route navigation and palette tests.
- 320px reflow and short-height screenshots.
- Role-scoped navigation assertions for admin, operator, and auditor.

### Slice 3: Overview and animated exposure map

Primary files:

- `console/src/views/Overview.tsx`
- `console/src/views/Overview.css`
- `console/src/components/overview/LeakMap.tsx`
- `console/src/components/overview/LeakMap.css`

Work:

- Preserve the map's purpose and sanitized `posture.leakMap` contract.
- Improve node layout, edge readability, hierarchy, legend, and inspector.
- Make edge selection keyboard-operable.
- Add Map and Details modes with a semantic relationship table/list.
- Add visible Zoom in/out, Pan, Fit, Reset, and Pause controls; retain pointer
  gestures only as optional enhancements.
- Preserve selection and focus during filters and responsive relayout.
- Make decorative flow motion inaccessible to assistive technology and keep
  meaningful state in DOM text.
- Reduce Overview KPI clutter to the few questions an operator needs first.

Evidence:

- Pointer and keyboard node/edge selection tests.
- Reduced-motion and paused-state assertions.
- Small-screen Details mode and desktop map screenshots.
- No raw prompt or synthetic SSN fragments rendered in the map.

### Slice 4: Truthful states and approval workflow

Primary files:

- `console/src/views/Queue.tsx`
- `console/src/views/Queue.css`
- `console/src/components/queue/*`
- `console/src/lib/api.ts`
- `console/src/components/Panel.tsx`

Work:

- Distinguish initial loading, empty, filtered-empty, unavailable, stale,
  permission denied, mutation success, and partial failure.
- Never translate a failed queue fetch into "queue clear."
- Improve queue list/detail behavior at tablet and mobile sizes.
- Keep password/OIDC step-up, redaction, reveal truthfulness, assignment,
  bulk-decision, and audit-history behavior unchanged.
- Verify dialog containment, Escape behavior, labels, action ordering, and focus
  restoration.

Evidence:

- Existing approval-release flow passes.
- New queue failure and stale-snapshot browser tests pass.
- Keyboard-only single and bulk-decision workflows pass.

### Slice 5: Policy and Command Center progressive disclosure

Primary files:

- `console/src/views/Policy.tsx`
- `console/src/views/Policy.css`
- `console/src/views/Monitor.tsx`
- new focused components under `console/src/components/policy/` and
  `console/src/components/monitor/`

Work:

- Extract maintainable sections from both monoliths.
- Policy first view: readiness, active mode, key thresholds, destinations,
  approval routing, test, impact preview, and save state.
- Put advanced JSON, detailed fleet, MCP patterns, scopes, exceptions, and
  retention operations behind clear labeled disclosures without changing the
  submitted policy shape.
- Command Center first view: enforcement health, urgent action queue, active
  policy/scope, sensor coverage, and evidence freshness.
- Collapse repeated empty cards into concise grouped readiness states.
- Preserve drill-throughs, live posture actions, feedback, SIEM package,
  notification, charts, and SSE behavior.

Evidence:

- Existing policy parity and Command Center route tests pass.
- Draft, test, impact, discard, template, save, and purge controls call the same
  endpoints with unchanged payloads.
- Empty, partial, and populated screenshots are reviewed.

### Slice 6: Supported backend coverage expansion

Primary files:

- `console/src/views/Compliance.tsx`
- `console/src/views/Audit.tsx`
- `console/src/views/Integrations.tsx` or `console/src/views/Activity.tsx`
- focused API helpers under `console/src/api/`
- Playwright tests and focused Node route-contract tests where useful

Work:

- Add role-correct Security Trust Package export.
- Add bounded receipt verification with explicit valid, invalid, malformed,
  unavailable, and permission states.
- Add admin-only ticket-status synchronization with progress and result counts.
- Hide or explain actions that the signed-in role cannot perform.
- Do not add routes, storage, or network behavior to the backend.

Evidence:

- Each action reaches the intended existing endpoint.
- Auditor/operator/admin permission matrices match server behavior.
- Error text contains no submitted receipt, credential, or provider response.

### Slice 7: Remaining routes and secondary auth surfaces

Primary files:

- remaining `console/src/views/*`
- `server/public/login.html`
- `server/public/accept-invite.html`
- shared auth-surface CSS if introduced
- extension UI files only when a visible inconsistency remains

Work:

- Apply tokens and shared states without rebuilding already proven workflows.
- Preserve Identity and Licensing functionality introduced in `b0b3552`.
- Standardize tables, forms, tabs, dialogs, drawers, filters, notifications,
  loading, empty, error, success, and permission states.
- Make sign-in minimal and reassuring with no decorative gradient or marketing
  clutter.
- Keep invitation token handling in fragments and preserve existing security
  tests.

Evidence:

- Every route resolves its loader without console/page/API errors.
- All major interactive surfaces have keyboard, mobile, and permission proof.

### Slice 8: Final integration, review, and delivery

Work:

- Wait for the backend session to commit and validate its isolated change.
- Sync updated `main` into the UI branch without overwriting either diff.
- Resolve conflicts by preserving backend security semantics and UI contracts.
- Run a fresh-context skeptical review and security review.
- Remove ignored build output, test output, screenshots, temp profiles, and
  secrets from the tracked diff.
- Commit in scoped, reviewable increments.
- Push the feature branch, verify GitHub CI, and merge only after protections,
  review, and checks pass.

## Responsive and screenshot matrix

Run the major routes and critical workflows at:

- 320 x 568, narrow reflow
- 390 x 844, large mobile
- 768 x 1024, tablet portrait
- 1024 x 600, short laptop
- 1366 x 768, laptop
- 1440 x 900, standard desktop baseline
- 1920 x 1080, desktop
- 2560 x 1440, wide desktop

Also validate:

- 200% browser text zoom
- 320 CSS-pixel reflow / 400% zoom condition
- portrait and landscape
- reduced motion
- forced colors / high contrast where supported
- dark and light themes
- admin, operator, and auditor roles
- loading, empty, populated, unavailable, stale, permission, success, partial
  failure, and destructive-confirmation states

Keep two-dimensional scrolling local to maps and comparison tables. No route may
create an unexpected page-level horizontal scrollbar.

## Accessibility acceptance

- All functions are keyboard-operable with logical order and no traps.
- Focus is visible, has at least a two-pixel visual perimeter equivalent, and is
  not hidden by sticky UI.
- Dialogs and drawers contain focus, close with Escape, and restore focus.
- Text contrast is at least 4.5:1 and essential UI/graphics contrast is 3:1.
- State never relies on color alone.
- Controls meet WCAG 2.2 24px minimum targets and use 44px targets for primary
  mobile/icon controls.
- Status, loading, error, and success changes are announced without flooding
  assistive technology.
- Hover content also works on focus and is dismissible, hoverable, and
  persistent.
- Charts and the map provide semantic summaries and data/details alternatives.
- Motion can be paused and is suppressed under reduced-motion preference.

Primary references:

- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [WAI ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/patterns/)
- [WAI complex images](https://www.w3.org/WAI/tutorials/images/complex/)
- [USWDS tables](https://designsystem.digital.gov/components/table/)
- [USWDS data visualizations](https://designsystem.digital.gov/components/data-visualizations/)

## Exact acceptance evidence

Run targeted checks after each slice, then run the full sequence from the final
synced commit:

```powershell
npm run console:check
npm run console:build
node scripts/run-playwright.js console-design.spec.js
node scripts/run-playwright.js admin-console-app.spec.js
node scripts/run-playwright.js console-parity.spec.js
npm run test:browser
npm run suite:smoke
npm run simulate
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
npm run review:ci
git diff --check
git status --short --branch
```

Add focused Playwright specs for responsive shell, accessibility mechanics, map
controls, truthful failure states, and the three backend-coverage workflows.
`npm run review:ci` is the authoritative local gate and may not be weakened.

GitHub delivery evidence:

- Feature branch and scoped commit ids.
- Pull request diff contains only intended UI, test, and documentation changes.
- Required checks pass on the synced commit.
- CI and review status are recorded before merge.
- Merge commit or exact blocker is reported.

## Completion gate

The goal is complete only when:

- All 18 React routes and secondary auth surfaces are audited.
- Design tokens and shared states are documented and reused.
- The shell is responsive and keyboard-accessible.
- The exposure map is preserved, improved, controllable, and has a semantic
  details alternative.
- Queue and permission failures cannot look like success or empty data.
- Policy and Command Center are task-focused and maintainable.
- The three supported backend gaps are covered or a concrete server-contract
  blocker is documented.
- Critical workflows pass end to end for the correct roles.
- Screenshot evidence covers the required viewport, theme, and state matrix.
- Production build, full local gate, audit verification, and GitHub CI pass.
- No secrets, generated bundles, screenshots, temporary files, or unrelated
  backend changes are tracked.
- The backend security work has passed its own Windows/Postgres durability gate.
- The feature branch is merged safely, or left clean, tested, pushed, and
  merge-ready with the exact external blocker documented.

## Goal-loop budget

Budget: up to 60 working turns. Stop only when the completion gate passes, a
required user decision would materially change product behavior, or the same
external blocker remains after three consecutive goal turns with no safe
in-scope path forward.

## Resume log — 2026-07-10, post-usage-limit continuation

A follow-up session resumed the goal after the original session hit its usage
limit mid-validation. State of the evidence at handoff:

Passing in this worktree (all uncommitted work included):

- `npm run console:check` (tsc, clean)
- `npm run console:build` (production bundle builds; route chunks emitted)
- `npm run docs:demo-guide:check`, `npm run ai-domains:check`,
  `npm run native:check`, `npm run sync-check` (all exit 0)
- `npm run eval` (all detection floors met)
- `verifyAuditChain()` → `ok:true`
- `git diff --check` (clean); no secrets, binaries, or screenshots tracked
- Targeted node tests over every redesign-touched module:
  `posture`, `frontend-csp`, `asset-budget`, `leak-map-traffic`,
  `playwright-env` pass; the redesign's own `db.test.js` stats/`held`
  assertions pass in isolation.

Fixed in this session:

- `scripts/playwright-server.js`: the isolated `REDACTWALL_DATA_DIR` pointed at
  the pre-seeded mkdtemp directory, so first-boot trust could not be
  established and preflight failed with `PRIVATE_DIRECTORY_UNTRUSTED_STATE`
  (`policy_signing_key`). The data dir is now an unborn `data/` subdirectory
  the server creates and trusts on boot; the copied policy file stays outside
  it.

Known-blocked (backend-owned, per the integration boundary above):

- `test/access-roles.test.js` "deploy downloads" fails 500: after any posture
  mutation, the audit checkpoint publication leaves
  `REDACTWALL_AUDIT_CHECKPOINT_UNHEALTHY` (thrown by
  `server/audit-anchor.js` `requireMutationReady`), freezing later audit
  appends. Reproduced identically at the branch base `b0b3552` with zero UI
  changes, so it is inherited, not a redesign regression. The backend
  session's uncommitted main-worktree diff already fixes it (the same test
  pair passes there), along with `ticket-sync` and `webapp-qa-1000`;
  their `db.test.js` tamper-evidence tests are still red in their own
  worktree (work in progress).
- Because `.githooks` pre-commit runs the full unweakenable gate, this branch
  cannot be committed until the backend fix lands on `main`. Delivery
  sequence stands: backend lands → merge updated `main` (conflicts expected:
  `CHANGELOG.md`, `scripts/edm-fingerprint.js`, `server/db.js` `held` field)
  → full `npm run review:ci` from a clean process → scoped commits → push →
  GitHub CI → merge.

### Browser-suite addendum (same session, after the preflight fix)

With `scripts/playwright-server.js` fixed, the e2e server boots and the freeze
is now precisely characterized. Direct probe on this branch's isolated server:
`POST /api/login` → 200, then `POST /api/v1/gate` → **500** (the ingest
mutation itself dies during checkpoint publication), then `POST /api/login` →
**500** (frozen). The identical probe against the backend session's worktree
returns 200/200/200 — their uncommitted fix cures the gate path as well.

Isolated per-spec results (fresh server per file):

- `auth-surface.spec.js` — 2/2 passed.
- `console-responsive-matrix.spec.js` — the full critical-workflow viewport
  matrix passed (1.7m); the reduced-motion/200%-zoom test fails only because
  the preceding test's queue mutations froze the server and its login 500s.
- `queue-states.spec.js`, `policy-progressive-disclosure.spec.js` — the pure
  render-state test in each passed; all mutation-dependent tests cascade-fail.
- `overview-map`, `command-center`, `console-evidence-workflows`,
  `console-design` — each seeds via gate/posture/policy writes, so the file's
  first mutation freezes its server and the rest cascade, including the
  console-design screenshot pass.

No browser-test failure has been traced to a UI defect. The complete browser
suite, the screenshot evidence matrix, and the full `review:ci` gate are all
runnable only after the backend session lands; rerun them from the merged
commit before any push.

## Continuation audit — 2026-07-11

The next goal-loop session verified the separate worktree and re-audited the
implementation instead of relying on the prior zero-defect summary. The branch
still starts at `b0b3552`; freshly fetched `origin/main` is `eedda77` and is
three commits ahead on the remote side. The concurrent backend durability work
remains uncommitted in the main worktree and must be integrated before browser
proof can be trusted.

Additional gaps found and closed in the UI worktree:

- All console JSON and byte responses now use bounded streamed readers with
  declared-size checks, fatal UTF-8 decoding, read deadlines, cancellation,
  and single-consumption error caching. Auth pages use a dependency-free 16 KiB
  reader and credential-bearing requests reject redirects.
- The MFA field now accepts both six-digit authenticators and the actual
  eleven-character recovery-code format. Sign-in and invitation failures focus
  the invalid control, malformed success bodies do not produce success copy,
  and keyboard retry/success states have browser coverage.
- Queue and Activity share a strict public-query decoder. Per-query audit UI
  distinguishes a complete retained search from a bounded recent window. The
  real approval test now reads back `FLAGGED` and `APPROVED` audit evidence for
  the exact query without prompt or identity leakage.
- A loopback-only real policy test applies an additive blocked destination,
  verifies UI/API/audit readback, and restores the exact original policy in a
  `finally` block. Mandatory `alwaysBlock` controls are never submitted.
- Command Center, Policy readiness, Integrations, Updates, NCUA exports, and
  detector feedback now validate complete response families and match server
  role boundaries instead of rendering missing values as zero or exposing
  unauthorized controls.
- Table sorting/pagination, stale/partial/unavailable states, destructive
  confirmation, permissions, forced colors, contrast, focus visibility,
  mobile touch targets, map pan/zoom/fit/reset, reduced motion, and a
  representative map render/frame measurement now have focused Playwright
  coverage. Fixed sleeps were removed from the extension suite.
- The integrated built console currently measures 762,502 bytes raw and
  228,498 bytes gzip across all lazy routes. The 801,000/240,000 aggregate
  ceilings retain about five percent measured headroom. Separate ceilings for
  the initial shell, Command Center, and Policy chunks retain comparable
  headroom so aggregate growth cannot hide a first-load regression.

Current focused evidence:

- `npm run console:check` passes; `npm run console:build` passes.
- Focused frontend/posture, auth, CSP, CSRF, bounded-reader, and asset-budget
  Node suites pass.
- The complete serial Chromium run passes all 169 tests in 19 files, including
  five accessibility-contract tests, 21 live extension flows, and the real
  policy/audit workflows.
- `git diff --check` passes. Generated app bundles and screenshot evidence
  remain ignored.

Still required before delivery:

1. Close the final fresh-review truthfulness, cancellation, and storage-migration
   findings with focused regression proof.
2. Commit and merge the redesign into the already integrated audit-hardened
   `main`, then resolve the owner-platform integration without weakening either
   contract.
3. Regenerate and visually inspect the final dark/light, eight-viewport, state,
   auth, reduced-motion, forced-colors, and map evidence on the merged tree.
4. Run the complete local review gate, dependency/security checks, audit-chain
   verification, and a fresh diff/privacy review before pushing `main`.
