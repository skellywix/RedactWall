'use strict';
/**
 * Print a secret-free SCIM/OIDC setup handoff for a customer IdP.
 */
const { buildIdentitySetupGuide, renderTextGuide } = require('../server/identity-setup');

function parseArgs(argv = process.argv.slice(2)) {
  const opts = {
    provider: 'entra',
    baseUrl: 'https://promptwall.customer.example',
    tenantId: '',
    format: 'text',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--provider') opts.provider = argv[++i] || '';
    else if (arg === '--base-url') opts.baseUrl = argv[++i] || '';
    else if (arg === '--tenant-id' || arg === '--tenant' || arg === '--okta-domain') opts.tenantId = argv[++i] || '';
    else if (arg === '--format') opts.format = argv[++i] || 'text';
    else if (arg === '--json') opts.format = 'json';
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown option: ${arg}`);
  }
  opts.format = String(opts.format || 'text').toLowerCase();
  if (!['text', 'json'].includes(opts.format)) throw new Error('--format must be text or json');
  return opts;
}

function printHelp() {
  console.log([
    'Usage: npm run identity:setup -- [options]',
    '',
    'Options:',
    '  --provider <entra|okta>     Identity provider to prepare',
    '  --base-url <url>            Public PromptWall console URL',
    '  --tenant-id <value>         Entra tenant id/domain or Okta org domain/issuer',
    '  --okta-domain <domain>      Alias for --tenant-id with Okta',
    '  --format <text|json>        Output format',
  ].join('\n'));
}

function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    printHelp();
    return 0;
  }
  const guide = buildIdentitySetupGuide(opts);
  if (opts.format === 'json') {
    console.log(JSON.stringify(guide, null, 2));
  } else {
    process.stdout.write(renderTextGuide(guide));
  }
  return 0;
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (e) {
    console.error('Identity setup failed: ' + (e && e.message ? e.message : e));
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs };
