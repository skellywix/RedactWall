'use strict';
/**
 * Server detection entry point. Delegates to the shared, browser-safe engine
 * (../shared/detect.js) so the server, browser extension, endpoint agent, and
 * MCP guard all detect identically. Kept as a thin wrapper for back-compat.
 */
module.exports = require('../shared/detect');
