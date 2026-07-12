# RedactWall frontend design system

## Product direction

RedactWall is an examiner-facing security instrument for regulated financial
institutions. The interface should feel calm, precise, and operational. It uses
hairline boundaries, compact but readable type, restrained elevation, and
purposeful motion. Iris identifies interaction and selection. Status colors are
reserved for meaning and are always paired with text, shape, or an icon.

The console uses the system font stack and repository-owned inline SVGs. It has
no third-party visual assets, fonts, or design-system dependencies.

## Token authority and load order

`server/public/console-theme.css` is the only design-token authority. Do not
redeclare tokens in `console-base.css`, `app.css`, or view styles.

The React document loads styles in this order:

1. `console-base.css`: framework-agnostic legacy-compatible component rules.
2. `console-theme.css`: tokens, light and dark themes, shared presentation
   patterns, accessibility rules, and compatibility refinements.
3. `console/src/app.css`: React shell geometry and responsive behavior.
4. View styles imported by individual React views.

Tokens resolve at computed-value time, so the base sheet can consume tokens
declared by the theme sheet that follows it.

## Foundation tokens

| Family | Tokens | Use |
| --- | --- | --- |
| Type | `--font-ui`, `--font-mono`, `--text-xs` through `--text-2xl`, `--leading-*` | Interface copy, evidence values, headings |
| Space | `--space-0`, `--space-1`, `--space-2`, `--space-3`, `--space-4`, `--space-5`, `--space-6`, `--space-8`, `--space-10`, `--space-12` | Layout rhythm in 4px-based increments |
| Size | `--size-control`, `--size-target`, `--size-rail`, `--size-topbar` | Controls, 44px touch targets, and shell geometry |
| Shape | `--radius-xs`, `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-pill` | Small controls through dialog surfaces |
| Elevation | `--shadow`, `--shadow-raised`, `--shadow-pop` | Nested surfaces and modal separation only |
| Motion | `--motion-instant`, `--motion-fast`, `--motion-standard`, `--motion-expressive` | State, drawer, and purposeful spatial changes |
| Layer | `--z-sticky`, `--z-backdrop`, `--z-dialog` | Sticky shell and modal stacking |

Existing compatibility aliases such as `--radius` and `--fast` map to the
foundation scale. New code should prefer the explicit family tokens.

## Color and status

Theme colors are defined for `body[data-theme="light"]` and
`body[data-theme="dark"]`. Dark remains the default. The persisted preference
is applied by `console/src/lib/theme.ts`.

| Meaning | Foreground | Background | Required non-color cue |
| --- | --- | --- | --- |
| Information or live | `--status-info` | `--status-info-bg` | Label plus dot or information icon |
| Safe or success | `--status-safe` | `--status-safe-bg` | Label plus check or stable-state icon |
| Warning or review | `--status-warning` | `--status-warning-bg` | Label plus triangle or review icon |
| Critical or block | `--status-critical` | `--status-critical-bg` | Label plus diamond, stop, or block icon |

Do not use status color for decoration. Do not infer a backend decision from a
color or substitute a neutral empty state for a failed request.

## Shared presentation patterns

The shared CSS API is intentionally small:

- `.system-page-header` holds a page title, concise purpose, and optional
  action toolbar.
- `.system-toolbar` groups related controls and wraps at narrow widths.
- `.system-button` uses the existing `primary`, `secondary`, and `ghost`
  variants.
- `.system-field` binds a visible label, control, help, and error text.
- `.system-status[data-tone]` presents a text-and-icon semantic status.
- `.system-state` is the state container. Add exactly one of
  `.system-empty`, `.system-unavailable`, `.system-stale`,
  `.system-permission`, or `.system-success`.

Example:

```html
<section class="system-state system-permission" role="status">
  <strong>Auditor access required</strong>
  <p>This evidence action is not available for the current role.</p>
</section>
```

State meaning must remain explicit:

- Loading means the request has not produced a verified result yet. It must not
  reuse a previous success label or render zero-valued evidence.
- Empty means a successful request returned no records.
- Unavailable means no trustworthy result is available.
- Stale means the last verified result is still shown after refresh failure.
- Last verified is the visible label for retained stale evidence. It never means
  current, live, secure, or monitoring.
- Partial means the response is verified for the requested scope, but one or
  more required evidence families or fields were not reported. Partial
  snapshots must not use a live, complete, or all-clear label.
- Not reported means the server omitted a specific evidence family or value.
  Render an em dash or explicit copy, never an invented zero.
- Permission means the server does not authorize the current role.
- Success confirms a completed action, not merely an attempted request.

Mutation feedback must be based on the validated response or an authoritative
readback. A 2xx status with a malformed or incomplete body is an unverifiable
outcome, not success.

## Shell and navigation

Desktop uses a persistent 240px navigation rail. The route list owns the
scrolling region, so brand and system context remain stable on short displays.
At 900px and below, navigation becomes a modal drawer with a backdrop, Escape
close, outside close, focus containment, and focus restoration. Selecting a
route closes the drawer. Route labels and role filtering continue to come from
the single route table in `console/src/App.tsx`.

The top bar shows the active route, the Texas FCU authenticated-console
context, live telemetry, current identity and role, theme, command palette,
and sign-out controls. At 420px, sign-out retains its accessible name while
the visible label collapses to its icon.

Responsive checks use these boundaries:

- More than 900px: persistent rail.
- 900px and below: modal drawer and 44px touch targets.
- 420px and below: compact top-bar labels for 320px reflow.
- 760px height and below on desktop: compact rail spacing with scrollable
  routes.
- 600px height and below on mobile: supplemental rail status yields space to
  primary navigation.

## Authentication surfaces

`server/public/auth-surface.css` is the shared presentation layer for sign-in
and invitation acceptance. These pages remain server-delivered, dependency-free
HTML with external scripts so their CSP and token-fragment security contracts do
not depend on the React bundle. Reuse the console theme tokens loaded before the
auth sheet, keep the primary form first in the reading order, and preserve a
44px minimum target for every credential or invitation action.

Load `auth-response.js` before either auth consumer. Login options, failed login
details, and invitation results use its bounded, deadline-limited JSON reader;
auth pages must not buffer an untrusted response with `response.json()`. The MFA
field accepts either a six-digit authenticator code or the documented
eleven-character recovery-code form and focuses itself when MFA is required.
Credential-bearing auth requests reject redirects so submitted passwords and
invitation tokens cannot be replayed to a redirected origin.

Do not place invitation tokens in query strings, inline scripts, analytics, or
visible reassurance copy. Authentication errors use the existing live alert
region and must never echo credentials, provider responses, or submitted token
bytes.

## Exposure map semantics

The map is a control-path visualization, not a network-delivery trace. An
outbound leg may render only from the server-provided continued aggregate,
which represents an explicit policy-authorized continuation. It must never be
inferred from total events minus blocked events and must never be described as
delivery confirmation. Initial warnings, paste coaching, shadow sightings,
unknown outcomes, and held or blocked events have no outbound leg.

Aggregated counts are not evidence that the same event belongs to both sets.
Use the server's `uncontrolledContinued` intersection before styling an outbound
leg as sensitive continuation. Keep uncontrolled observation copy neutral and
report the independent continuation count separately.

Keep ingress and continuation tones independent for mixed paths. Every visual
path also needs a keyboard-selectable relationship and an equivalent Details
row. Loading, unavailable, stale, verified-empty, and filtered-empty states
remain distinct.

## Accessibility contract

- WCAG 2.2 Level AA is the acceptance baseline.
- The first keyboard target is a skip link that focuses `#main-content`
  without replacing the hash route.
- Every interactive element has a visible focus indicator and scroll margin
  for sticky UI.
- Modal surfaces contain focus, close with Escape, and restore focus to the
  launcher. Background scrolling is locked while a modal is open.
- The active route uses `aria-current="page"`. The drawer launcher exposes
  `aria-controls` and `aria-expanded`.
- Touch targets are at least 44px at mobile widths. Desktop targets remain at
  least 24px.
- `prefers-reduced-motion` collapses animations and transitions.
- `forced-colors` retains focus, borders, status markers, and selection cues.
- Status, permission, failure, and success are never communicated by color
  alone.

Primary implementation references are the [WCAG 2.2 target-size
criterion](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html),
the [WAI-ARIA modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/),
and the [WAI guidance for complex-image text
equivalents](https://www.w3.org/WAI/tutorials/images/complex/).

## Review checklist

Before adding or changing a frontend pattern:

1. Reuse a token or shared pattern before adding a local value.
2. Preserve route hashes, role filtering, API contracts, and server authority.
3. Verify dark and light themes, 320px reflow, short-height behavior, keyboard
   order, reduced motion, and forced colors where available.
4. Keep prompt bodies, raw member data, tokens, secrets, and sensitive local
   paths out of screenshots, fixtures, logs, and error copy.
5. Run `npm run console:check`, `npm run console:build`, focused Playwright
   coverage, and `git diff --check`.
