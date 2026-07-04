'use strict';
/** Provider adapter registry for the AI Gateway. */
const openai = require('./openai');
const anthropic = require('./anthropic');
const mock = require('./mock');

const ADAPTERS = { openai, anthropic, mock, 'azure-openai': openai, 'internal-http': openai };

function getAdapter(provider) {
  return ADAPTERS[String(provider || 'openai').toLowerCase()] || openai;
}

module.exports = { getAdapter, ADAPTERS };
