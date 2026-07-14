'use strict';

// Customer packaging imports this deliberately narrow entry point.  It exposes
// only customer-silo state and the customer witness reference adapter.  Vendor
// intelligence, signing, ledger, and compaction authorities are never exported.
const {
  openCustomerShadowAiSqliteStorage,
  openShadowAiAnchorSqliteStorage,
} = require('./customer-shadow-ai-storage');
const {
  CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY,
} = require('./shadow-ai-catalog-state');

module.exports = Object.freeze({
  CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY,
  openCustomerShadowAiSqliteStorage,
  openShadowAiAnchorSqliteStorage,
});
