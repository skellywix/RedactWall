# Credit-Union Pricing — model + DRAFT figure

> ⚠️ **DRAFT — the dollar figures below are a recommendation, NOT a committed or
> published price.** A published per-seat number is a business decision for the
> owner to set and sign off before any customer-facing use. This document defines
> the pricing *model*; the number is a placeholder pending confirmation.

## Positioning (why this shape)
- **Transparent, per-seat, annual.** Credit unions buy on board-approvable,
  predictable pricing — not opaque "contact sales" quotes.
- **Below the incumbent band.** Independent reviews put enforcement-first AI-DLP
  incumbents around **~$25–60K/yr**; a Microsoft Purview path requires an **E5**
  license uplift. The target is to land **clearly under** both for a comparable
  credit-union deployment.
- **Single-tenant AWS customer silo** is the first paid shape (per `DECISIONS.md`),
  not shared SaaS.

## Model
| SKU | What's included | DRAFT per-seat / yr |
| --- | --- | --- |
| **Air-gapped (on-device)** | Browser + endpoint + MCP sensors, control plane, examiner pack, EDM, audit | **$[90–120]** *(confirm)* |
| **Connected delta** | + enforced LLM gateway, second-layer scanner, remote semantic seam | **+$[30–45]** *(confirm)* |

Illustrative (DRAFT): a 150-seat credit union on the air-gapped SKU at the low end
lands near **~$15K/yr** — under the incumbent band and far under an E5 uplift.

## Seat accounting (matches `server/tenant.js`)
- **Default: no seat enforcement.** With `REDACTWALL_SEAT_LIMIT` unset (the
  default), overage is a billing/true-up conversation at renewal; nothing is
  blocked.
- **Hard cap is opt-in** (`REDACTWALL_SEAT_LIMIT`, SaaS multi-tenant mode):
  when set, a **new** over-cap user is denied sensor access (HTTP 402,
  `seat_limit_blocked`); already-registered users keep working. There is no
  separate warn-only enforcement mode today.
- For **existing** seats, detection, enforcement, approvals, and audit never
  stop on a seat overage or a license grace lapse — only the admin console
  goes read-only past grace.
- Never describe the product as "blocking when you exceed seats" — with the
  cap unset nothing blocks, and even with the opt-in cap only new over-cap
  users are denied.

## Owner sign-off required before publishing
- [ ] Confirm the per-seat air-gapped number and the connected delta.
- [ ] Confirm minimum-seat / floor pricing for very small credit unions.
- [ ] Confirm term (annual vs. multi-year) and any pilot-to-paid conversion credit.
- [ ] Confirm whether the number is list price or a CUSO/league channel rate.

Until these are confirmed, treat every figure here as an internal planning
placeholder, not a quote.
