'use strict';

// Compatibility facade for root tests and transitional vendor relocation.
// Customer runtime code imports customer-shadow-ai-sqlite instead, so this
// mixed dispatcher is never part of the customer package dependency closure.
const {
  MAX_STATE_BYTES,
  REFERENCE_BLOB_ASSURANCE,
  SQLITE_SCHEMA_VERSION,
  storageError,
} = require('./shadow-ai-sqlite-core');
const customerStorage = require('./customer-shadow-ai-storage');
const vendorStorage = require('./vendor-shadow-ai-sqlite');

function openShadowAiStorage(options = {}) {
  const driver = String(options.driver || 'sqlite').toLowerCase();
  if (driver === 'postgres' || driver === 'postgresql') {
    throw storageError('shadow_ai_postgres_adapter_not_implemented');
  }
  if (driver !== 'sqlite') throw storageError('shadow_ai_storage_driver_invalid');
  if (options.kind === 'customer') {
    return customerStorage.openCustomerShadowAiSqliteStorage(options);
  }
  if (options.kind === 'vendor') {
    return vendorStorage.openVendorShadowAiSqliteStorage(options);
  }
  if (options.kind === 'anchor') {
    return customerStorage.openShadowAiAnchorSqliteStorage(options);
  }
  throw storageError('shadow_ai_storage_kind_invalid');
}

module.exports = Object.freeze({
  MAX_STATE_BYTES,
  REFERENCE_BLOB_ASSURANCE,
  SQLITE_SCHEMA_VERSION,
  ...customerStorage,
  ...vendorStorage,
  openShadowAiStorage,
});
