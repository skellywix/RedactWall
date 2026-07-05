'use strict';
/** Site adapters + Man-in-the-Prompt scanner (detection-engine/adapters.js). node --test */
const test = require('node:test');
const assert = require('node:assert');
const A = require('../detection-engine/adapters');

test('send-button selectors are site-specific then generic', () => {
  const sel = A.sendButtonSelectors('chatgpt.com');
  assert.ok(sel[0].includes('data-testid="send-button"'), 'site-specific first');
  assert.ok(sel.includes('button[type="submit"]'), 'generic fallback present');
  // unknown host still gets the generic set
  assert.deepStrictEqual(A.sendButtonSelectors('unknown.example'), A.GENERIC_SEND);
});

test('governance + AI-host matching handles subdomains', () => {
  assert.ok(A.isGoverned('chatgpt.com', ['chatgpt.com']));
  assert.ok(A.isGoverned('sub.openai.com', ['openai.com']), 'subdomain governed');
  assert.ok(A.isGoverned('team.openai.com', ['*.openai.com']), 'wildcard subdomain governed');
  assert.ok(A.isGoverned('openai.com', ['*openai.com']), 'suffix wildcard governs root');
  assert.ok(A.isGoverned('labs.openai.com', ['*openai.com']), 'suffix wildcard governs subdomain');
  assert.ok(A.isGoverned('anything.example', ['*']), 'catch-all governs any normalized host');
  assert.strictEqual(A.normalizeHost('https://%'), 'https:');
  assert.ok(!A.isGoverned('evil.com', ['openai.com']));
  assert.ok(!A.hostMatches('openai.com', ''), 'empty base does not govern');
  assert.ok(A.isAiHost('claude.ai') && A.isAiHost('chat.deepseek.com'));
  assert.ok(!A.isAiHost('example.com'));
});

test('injection scanner flags + strips hidden characters', () => {
  const clean = A.scanInjection('normal prompt text');
  assert.strictEqual(clean.suspicious, false);

  const zw = A.scanInjection('hello​world');               // zero-width
  assert.ok(zw.suspicious && zw.stripped === 'helloworld');

  const bidi = A.scanInjection('pay ‮evil‬ now');     // bidi override
  assert.ok(bidi.suspicious && bidi.reasons.some((r) => /bidi/i.test(r)));

  const tag = A.scanInjection('hi 󠁁 there');         // unicode tag char
  assert.ok(tag.suspicious && tag.reasons.some((r) => /tag/i.test(r)));
});

test('classifyAccount precedence and privacy (N4)', () => {
  const org = ['examplecu.org'];
  const t = (ctx) => A.classifyAccount(ctx, org);
  assert.deepStrictEqual(t({ host: 'chatgpt.com', emails: ['jane@gmail.com'] }), { type: 'personal', signal: 'personal_email_domain' });
  assert.deepStrictEqual(t({ host: 'chatgpt.com', emails: ['jane@examplecu.org'] }), { type: 'corporate', signal: 'org_email_domain' });
  assert.deepStrictEqual(t({ host: 'chatgpt.com', badgeText: 'ChatGPT Team workspace' }), { type: 'corporate', signal: 'workspace_badge' });
  assert.deepStrictEqual(t({ host: 'claude.ai', badgeText: 'Free plan' }), { type: 'personal', signal: 'consumer_badge' });
  // Unmatched domain must be UNKNOWN, never guessed personal.
  assert.deepStrictEqual(t({ host: 'chatgpt.com', emails: ['jane@contractor.co'] }), { type: 'unknown', signal: 'unrecognized_email_domain' });
  assert.deepStrictEqual(t({ host: 'chatgpt.com', emails: [] }), { type: 'unknown', signal: 'none' });
  // Corporate badge wins over a personal email.
  assert.strictEqual(t({ host: 'chatgpt.com', emails: ['jane@gmail.com'], badgeText: 'ChatGPT Enterprise' }).type, 'corporate');
  // The result object never contains an email.
  const r = t({ host: 'chatgpt.com', emails: ['jane@gmail.com'] });
  assert.ok(!JSON.stringify(r).includes('@'), 'result must not contain an email');
});
