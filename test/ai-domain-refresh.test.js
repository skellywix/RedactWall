'use strict';
/** AI destination refresh guard should fail closed when the watchlist drifts. */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const adapters = require('../detection-engine/adapters');
const checker = require('../scripts/check-ai-domain-coverage');

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('reviewed AI destination watchlist is covered by canonical adapters', () => {
  const watchlist = checker.readJson(path.join(__dirname, '..', 'config', 'ai-domain-watchlist.json'));
  const manifest = checker.readJson(path.join(__dirname, '..', 'sensors', 'browser-extension', 'manifest.json'));
  const result = checker.checkCoverage({ watchlist, adapterHosts: adapters.AI_HOSTS, manifest });

  assert.deepStrictEqual(result.missingDomains, []);
  assert.deepStrictEqual(result.missingManifestDomains, []);
  assert.deepStrictEqual(result.unknownServices, []);
  assert.ok(result.checkedDomains.includes('tiangong.kunlun.com'));
  assert.ok(result.checkedDomains.includes('genspark.ai'));
});

test('AI domain checker reports adapter hosts missing from browser manifest coverage', () => {
  const result = checker.checkCoverage({
    adapterHosts: ['chatgpt.com', 'new-ai.example'],
    watchlist: {
      candidateDomains: ['chatgpt.com', 'new-ai.example'],
      serviceDomainMap: {},
    },
    manifest: {
      host_permissions: ['https://chatgpt.com/*'],
      content_scripts: [{ matches: ['https://chatgpt.com/*'] }],
    },
  });

  assert.deepStrictEqual(result.missingDomains, []);
  assert.deepStrictEqual(result.missingManifestDomains, ['new-ai.example']);
});

test('AI domain checker reports missing hosts and unmapped Radar services', () => {
  const result = checker.checkCoverage({
    adapterHosts: ['chatgpt.com'],
    watchlist: {
      candidateDomains: ['chatgpt.com', 'new-ai.example'],
      serviceDomainMap: {
        ChatGPT: ['chatgpt.com'],
      },
    },
    radarServices: ['ChatGPT', 'Unknown AI Service'],
  });

  assert.deepStrictEqual(result.missingDomains, ['new-ai.example']);
  assert.deepStrictEqual(result.unknownServices, ['Unknown AI Service']);
});

test('Cloudflare Radar response maps top services into service names', async () => {
  const calls = [];
  const radar = await checker.fetchRadarServices({
    token: 'unit-token',
    serviceCategory: 'Generative AI',
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      return jsonResponse(200, {
        success: true,
        result: {
          top_0: [
            { rank: 1, service: 'ChatGPT' },
            { rank: 2, service: 'Claude' },
          ],
        },
      });
    },
  });

  assert.deepStrictEqual(radar, { skipped: false, services: ['ChatGPT', 'Claude'] });
  assert.match(calls[0].url, /\/radar\/ranking\/internet_services\/top/);
  assert.match(calls[0].url, /serviceCategory=Generative\+AI/);
  assert.strictEqual(calls[0].options.headers.Authorization, 'Bearer unit-token');
  assert.strictEqual(calls[0].options.redirect, 'error');
});

test('AI domain helpers normalize manifests, mapped services, and Radar failures', async () => {
  assert.deepStrictEqual(checker.collectCandidateDomains({
    candidateDomains: ['https://www.ChatGPT.com/*', 'www.claude.ai', 'unknown', 'chatgpt.com'],
    serviceDomainMap: {
      'Perplexity AI': ['www.perplexity.ai'],
    },
  }, ['perplexity ai']).domains, ['chatgpt.com', 'claude.ai', 'perplexity.ai']);
  assert.deepStrictEqual(checker.serviceDomains('PERPLEXITY AI', {
    'Perplexity AI': ['perplexity.ai'],
  }), ['perplexity.ai']);
  assert.strictEqual(checker.hostCovered('team.chatgpt.com', ['chatgpt.com']), true);
  assert.strictEqual(checker.manifestCovered('chatgpt.com', {
    host_permissions: ['https://*.chatgpt.com/*'],
    content_scripts: [{ matches: ['https://www.claude.ai/*'] }],
  }), true);
  assert.deepStrictEqual(checker.manifestHosts({
    host_permissions: ['https://*.chatgpt.com/*'],
    content_scripts: [{ matches: ['https://www.claude.ai/*'] }],
  }), ['chatgpt.com', 'claude.ai']);

  assert.deepStrictEqual(await checker.fetchRadarServices({ token: '' }), { skipped: true, services: [] });
  await assert.rejects(() => checker.fetchRadarServices({ token: 'unit-token', fetchImpl: null }), /fetch unavailable/);
  await assert.rejects(() => checker.fetchRadarServices({
    token: 'unit-token',
    limit: 999,
    fetchImpl: async (url) => {
      assert.match(String(url), /limit=200/);
      return jsonResponse(403, { success: false, errors: [{ message: 'bad token' }] });
    },
  }), /HTTP 403/);
  await assert.rejects(() => checker.fetchRadarServices({
    token: 'unit-token',
    serviceCategory: '',
    limit: 0,
    fetchImpl: async (url) => {
      assert.match(String(url), /limit=100/);
      assert.doesNotMatch(String(url), /serviceCategory=/);
      return jsonResponse(500, null);
    },
  }), /HTTP 500/);
});

test('AI domain CLI main reports success, drift, and Radar errors through injected console', async () => {
  const logs = [];
  const errors = [];
  const exits = [];
  const io = {
    log: (line) => logs.push(String(line)),
    error: (line) => errors.push(String(line)),
  };
  const files = {
    watchlist: {
      candidateDomains: ['chatgpt.com', 'missing.example'],
      serviceDomainMap: { ChatGPT: ['chatgpt.com'] },
    },
    manifest: {
      host_permissions: ['https://chatgpt.com/*'],
      content_scripts: [{ matches: ['https://chatgpt.com/*'] }],
    },
  };
  const readJson = (file) => (String(file).includes('watchlist') ? files.watchlist : files.manifest);
  const result = await checker.main(['--watchlist', 'watchlist.json'], {
    console: io,
    readJson,
    fetchRadarServices: async () => ({ skipped: false, services: ['ChatGPT', 'Unknown AI'] }),
    setExitCode: (code) => exits.push(code),
  });
  assert.deepStrictEqual(result.missingDomains, ['missing.example']);
  assert.deepStrictEqual(result.unknownServices, ['Unknown AI']);
  assert.ok(errors.some((line) => /services need mapping/.test(line)));
  assert.ok(errors.some((line) => /missing.example/.test(line)));
  assert.ok(exits.includes(1));

  logs.length = 0;
  errors.length = 0;
  exits.length = 0;
  const ok = await checker.main([], {
    console: io,
    readJson: () => ({
      candidateDomains: ['chatgpt.com'],
      serviceDomainMap: {},
      host_permissions: ['https://chatgpt.com/*'],
      content_scripts: [{ matches: ['https://chatgpt.com/*'] }],
    }),
    fetchRadarServices: async () => ({ skipped: true, services: [] }),
    checkCoverage: () => ({
      checkedDomains: ['chatgpt.com'],
      missingDomains: [],
      missingManifestDomains: [],
      unknownServices: [],
    }),
    setExitCode: (code) => exits.push(code),
  });
  assert.deepStrictEqual(ok.checkedDomains, ['chatgpt.com']);
  assert.ok(logs.some((line) => /Cloudflare Radar skipped/.test(line)));
  assert.ok(logs.some((line) => /AI domain coverage current/.test(line)));
  assert.deepStrictEqual(exits, []);

  const failed = await checker.main([], {
    console: io,
    readJson: () => ({}),
    fetchRadarServices: async () => { throw new Error('radar offline'); },
    setExitCode: (code) => exits.push(code),
  });
  assert.strictEqual(failed, null);
  assert.ok(errors.some((line) => /radar offline/.test(line)));
  assert.ok(exits.includes(1));
});
