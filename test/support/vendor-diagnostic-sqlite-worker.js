'use strict';

const {
  createVendorDiagnosticKeyFactory,
} = require('../../server/vendor-diagnostic-key-factory');
const {
  createVendorDiagnosticRuntime,
} = require('../../server/vendor-diagnostic-runtime');
const {
  createCustomerDeletionIntentKeyRegistry,
} = require('../../server/vendor-diagnostic-customer-key-registry');
const {
  FileDiagnosticWitness,
} = require('./vendor-diagnostic-reference-adapter');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', async () => {
  let runtime;
  try {
    const request = JSON.parse(input);
    const keyFactory = createVendorDiagnosticKeyFactory({
      ...request.keyFactory,
      now: Date.now,
    });
    runtime = createVendorDiagnosticRuntime({
      allowTestWitness: true,
      directory: request.directory,
      deletionIntentKeyRegistry: createCustomerDeletionIntentKeyRegistry({
        entries: request.deletionRegistryEntries,
        now: Date.now,
      }),
      keyFactory,
      witnessAuthority: new FileDiagnosticWitness(request.witnessDirectory),
      currentPrincipal: () => request.principal,
      retentionDays: 30,
      dailyEventLimit: 100_000,
    });
    let result;
    if (request.operation === 'ingest') {
      result = await runtime.intelligence.ingest(request.command);
    } else if (request.operation === 'health') {
      result = runtime.health();
    } else {
      throw Object.assign(new Error('unknown worker operation'), { code: 'WORKER_OPERATION_INVALID' });
    }
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      ok: false,
      code: error && error.code ? error.code : 'WORKER_FAILED',
      message: error && error.message ? error.message : 'worker failed',
    })}\n`);
  } finally {
    try { await runtime?.close(); } catch {}
  }
});
