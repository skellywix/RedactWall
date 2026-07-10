'use strict';

const PROVIDER_NAMES = Object.freeze([
  'openai',
  'anthropic',
  'internal-http',
  'mock',
]);
const PROVIDERS = new Set(PROVIDER_NAMES);
const EXPLICIT_UPSTREAM_PROVIDERS = new Set(['internal-http']);
const CREDENTIAL_REQUIRED_PROVIDERS = new Set(['openai', 'anthropic']);

function normalizeProvider(value) {
  const raw = value == null || String(value).trim() === '' ? 'openai' : String(value);
  const provider = raw.trim().toLowerCase();
  if (!PROVIDERS.has(provider)) {
    throw new Error(`gateway provider must be one of: ${PROVIDER_NAMES.join(', ')}`);
  }
  return provider;
}

function validateProviderConfig(value, upstreamBaseUrl, options = {}) {
  const provider = normalizeProvider(value);
  if (provider === 'mock' && options.production === true) {
    throw new Error('mock gateway provider is not allowed in production');
  }
  if (EXPLICIT_UPSTREAM_PROVIDERS.has(provider)
      && (typeof upstreamBaseUrl !== 'string' || !upstreamBaseUrl.trim())) {
    throw new Error(`${provider} gateway provider requires GATEWAY_UPSTREAM_URL`);
  }
  return provider;
}

function validateProviderCredentials(value, upstreamApiKey) {
  const provider = normalizeProvider(value);
  if (CREDENTIAL_REQUIRED_PROVIDERS.has(provider)
      && (typeof upstreamApiKey !== 'string' || !upstreamApiKey.trim())) {
    throw new Error(`${provider} gateway provider requires GATEWAY_UPSTREAM_API_KEY`);
  }
  return provider;
}

module.exports = {
  PROVIDER_NAMES,
  normalizeProvider,
  validateProviderConfig,
  validateProviderCredentials,
};
