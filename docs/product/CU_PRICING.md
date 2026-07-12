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

## Seat accounting (matches `server/license.js`)
- **Default: warn-and-true-up.** Going over the licensed seat count **warns** and
  reconciles at renewal; it does **not** block detection/enforcement/approvals.
- **Hard cap is opt-in** (`REDACTWALL_ENFORCE_SEAT_LIMIT`), never the default.
- Detection, enforcement, approvals, and audit **never stop** on a seat overage or
  a license grace lapse — only the admin console goes read-only past grace.
- Never describe the product as "blocking when you exceed seats" — that is the
  opt-in exception, not the model.

## Owner sign-off required before publishing
- [ ] Confirm the per-seat air-gapped number and the connected delta.
- [ ] Confirm minimum-seat / floor pricing for very small credit unions.
- [ ] Confirm term (annual vs. multi-year) and any pilot-to-paid conversion credit.
- [ ] Confirm whether the number is list price or a CUSO/league channel rate.

Until these are confirmed, treat every figure here as an internal planning
placeholder, not a quote.
