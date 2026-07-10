'use strict';
/** Provider adapter registry for the AI Gateway. */
const openai = require('./openai');
const anthropic = require('./anthropic');
const mock = require('./mock');
const { normalizeProvider } = require('../providers');

const ADAPTERS = { openai, anthropic, mock, 'internal-http': openai };

function getAdapter(provider) {
  return ADAPTERS[normalizeProvider(provider)];
}

module.exports = { getAdapter, ADAPTERS };
