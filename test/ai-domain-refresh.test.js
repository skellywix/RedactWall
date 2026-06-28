'use strict';
/** AI destination refresh guard should fail closed when the watchlist drifts. */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const adapters = require('../detection-engine/adapters');
const checker = require('../scripts/check-ai-domain-coverage');

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
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            success: true,
            result: {
              top_0: [
                { rank: 1, service: 'ChatGPT' },
                { rank: 2, service: 'Claude' },
              ],
            },
          };
        },
      };
    },
  });

  assert.deepStrictEqual(radar, { skipped: false, services: ['ChatGPT', 'Claude'] });
  assert.match(calls[0].url, /\/radar\/ranking\/internet_services\/top/);
  assert.match(calls[0].url, /serviceCategory=Generative\+AI/);
  assert.strictEqual(calls[0].options.headers.Authorization, 'Bearer unit-token');
});
