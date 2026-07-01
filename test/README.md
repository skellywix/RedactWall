# Tests

The default test command runs the Node test suite serially:

```bash
npm test
```

The full repo gate is:

```bash
npm run review:ci
```

That gate runs whitespace checks, generated demo-doc drift checks, AI-domain
coverage checks, the full Node test suite, the Playwright browser suite,
detector sync checks, and the held-out detection eval.

## Useful Focused Checks

| Surface | Command |
|---------|---------|
| Browser extension static and package tests | `node --test --test-concurrency=1 test/extension.test.js test/adapters.test.js test/extension-package.test.js` |
| Endpoint install and AI tool inventory | `node --test --test-concurrency=1 test/endpoint-install-check.test.js test/endpoint-ai-tool-inventory.test.js` |
| Coverage and evidence export | `node --test --test-concurrency=1 test/coverage.test.js test/evidence.test.js` |
| Browser-level flows | `npm run test:browser` |
| Admin console browser flows | `npm run test:admin-console` |
| Detection quality | `npm run eval` |
| Shared engine copy parity | `npm run sync-check` |

Use synthetic values only. Never add real customer, member, patient,
cardholder, employee, prompt, file, OCR, or clipboard content to fixtures.
