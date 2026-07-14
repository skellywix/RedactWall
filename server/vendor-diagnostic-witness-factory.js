'use strict';

const PRODUCTION_WITNESS_ASSURANCE = 'independent_monotonic_exact_cas_v1';
const PRODUCTION_WITNESS_PROVIDER_CONTRACT = 'vendor-diagnostic-witness-provider-v1';
const TEST_WITNESS_ASSURANCE = 'test_reference_only';
const brandedProductionAuthorities = new WeakSet();
// Production providers must be compiled into this module after their durability and exact-CAS
// implementation has been reviewed. Runtime configuration cannot register a provider.
const productionProviders = new Map();

function createProductionVendorDiagnosticWitnessFactory(providerId) {
  if (typeof providerId !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,63}$/.test(providerId)) {
    throw witnessFactoryError('vendor_diagnostic_witness_provider_invalid');
  }
  const createAuthority = productionProviders.get(providerId);
  if (!createAuthority) {
    throw witnessFactoryError('vendor_diagnostic_production_witness_not_implemented');
  }
  return Object.freeze({
    contractVersion: PRODUCTION_WITNESS_PROVIDER_CONTRACT,
    providerId,
    create(options) {
      const authority = checkedAuthority(createAuthority(options));
      const branded = Object.freeze({
        assurance: PRODUCTION_WITNESS_ASSURANCE,
        providerId,
        read: authority.read,
        compareAndSwap: authority.compareAndSwap,
      });
      brandedProductionAuthorities.add(branded);
      return branded;
    },
  });
}

function checkedAuthority(value) {
  const descriptors = value && typeof value === 'object' && !Array.isArray(value)
    ? Object.getOwnPropertyDescriptors(value) : {};
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !descriptors.read || !Object.hasOwn(descriptors.read, 'value')
      || descriptors.read.get || descriptors.read.set
      || !descriptors.compareAndSwap || !Object.hasOwn(descriptors.compareAndSwap, 'value')
      || descriptors.compareAndSwap.get || descriptors.compareAndSwap.set
      || typeof descriptors.read.value !== 'function'
      || typeof descriptors.compareAndSwap.value !== 'function') {
    throw witnessFactoryError('vendor_diagnostic_witness_authority_invalid');
  }
  return Object.freeze({
    read: descriptors.read.value.bind(value),
    compareAndSwap: descriptors.compareAndSwap.value.bind(value),
  });
}

function isProductionVendorDiagnosticWitnessAuthority(value) {
  return Boolean(value && brandedProductionAuthorities.has(value));
}

function witnessFactoryError(code) {
  const error = new Error('vendor diagnostic witness factory rejected');
  error.code = code;
  return error;
}

module.exports = {
  PRODUCTION_WITNESS_ASSURANCE,
  PRODUCTION_WITNESS_PROVIDER_CONTRACT,
  TEST_WITNESS_ASSURANCE,
  createProductionVendorDiagnosticWitnessFactory,
  isProductionVendorDiagnosticWitnessAuthority,
};
