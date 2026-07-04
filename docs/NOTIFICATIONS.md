# Email & Digest Notifications

PromptWall delivers human notifications — held-prompt alerts, posture
events, and the daily digest — through the same prompt-free subscription
pipeline that feeds SIEM destinations. This guide is the operator setup and
troubleshooting reference for the email channel. Console home: the
**Email & Digest** panel on the Integrations tab.

## 1. Configure the SMTP relay (environment)

| Variable | Required | Meaning |
| --- | --- | --- |
| `SMTP_HOST` | yes | Relay hostname. Email is disabled until this is set. |
| `SMTP_PORT` | no | Default `587`. |
| `SMTP_SECURE` | no | `starttls` (default), `tls` (implicit, use with port 465), or `none` (test relays only). |
| `SMTP_FROM` | no | From address; defaults to `promptwall@<SMTP_HOST>`. |
| `SMTP_USER` / `SMTP_PASS` | no | Enables AUTH LOGIN when set. |

The sender is dependency-free (`server/email.js`). It never logs message
content, strips header injection from subjects, filters invalid recipients,
and dot-stuffs bodies per RFC 5321.

## 2. Add email destinations (config/subscriptions.json)

```json
{
  "destinations": [
    {
      "id": "ciso-inbox",
      "name": "CISO inbox",
      "type": "email",
      "to": ["ciso@example.test", "soc@example.test"],
      "eventTypes": ["digest", "BLOCKED", "SENSOR_STALE"],
      "minSeverity": 3,
      "maxPerHour": 30
    }
  ]
}
```

- `to` — one or more recipients (required for `type: "email"`; no `url`).
- `eventTypes` / `minRisk` / `minSeverity` — the same floors SIEM
  destinations use. Note the digest event has risk/severity 0, so a digest
  destination must leave those floors unset (or use a dedicated
  digest-only destination as above with `eventTypes` doing the filtering).
- `maxPerHour` — alert-storm guard (default 30, range 1–500). Overflow is
  recorded in delivery history as `failed / rate_limited`; it is never
  silently dropped and the relay never sees the burst.

Message bodies are prompt-free: security events send the same sanitized
event JSON the SIEM adapters send; the daily digest sends readable prose
(pending / blocked today / approved / denied / total).

## 3. Verify from the console

On **Integrations → Email & Digest** (Security Admin):

1. The status grid shows the relay (host, port, mode, from, auth) —
   credentials never leave the server.
2. **Send test email** delivers a fixed prompt-free message; the result
   shows inline and the recipient is written to the audit chain masked
   (`EMAIL_TEST_SENT: c***@example.test`).
3. **Send digest now** dispatches the digest immediately and shows
   delivered/total; the scheduled digest runs every 24 hours from server
   start.

## 4. Troubleshooting

| Symptom (delivery history `lastError`) | Meaning / fix |
| --- | --- |
| `smtp_not_configured` | `SMTP_HOST` unset on the server process. |
| `smtp_connect: ...` | Host/port unreachable — check egress rules to the relay. |
| `smtp_tls: ...` | STARTTLS failed — try `SMTP_SECURE=tls` with port 465, or fix the relay cert. |
| `smtp_535` / `smtp_530` | Relay rejected AUTH — check `SMTP_USER`/`SMTP_PASS`. |
| `rate_limited` | The storm guard held the destination under `maxPerHour`; raise it or tighten the destination's floors. |
| `no_valid_recipients` | Every address in `to` failed basic validation. |

Delivery outcomes (delivered / failed / deduped) appear in the delivery
history table with attempts and the last error — never with message
bodies. Duplicate events within five minutes are deduped per destination.
