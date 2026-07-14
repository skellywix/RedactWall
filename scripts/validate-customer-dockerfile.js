'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { IMAGE_SCAN_ROOTS } = require('./verify-customer-image-content');

const APPROVED_STAGE_BASES = Object.freeze([
  'node:22-bookworm-slim AS node-runtime-source',
  'node:22-bookworm-slim AS production-dependencies',
  'node:22-bookworm-slim AS artifact-builder',
  'postgres:17-bookworm AS runtime',
]);
const APPROVED_SYNTAX_DIRECTIVE = '# syntax=docker/dockerfile:1.7';
const APPROVED_RUNTIME_COPIES = Object.freeze([
  '--from=node-runtime-source /usr/local/bin/node /usr/local/bin/node',
  '--from=node-runtime-source /usr/local/lib/node_modules/npm/ /usr/local/lib/node_modules/npm/',
  '--from=production-dependencies --chown=node:node /app/node_modules ./node_modules',
  '--from=artifact-builder --chown=node:node /tmp/customer-runtime/ ./',
]);
const APPROVED_POST_SCAN_TAIL = Object.freeze([
  'user node',
  'expose 4000',
  'volume ["/data", "/gateway-data"]',
  'healthcheck --interval=30s --timeout=4s --start-period=5s --retries=3 CMD node -e "fetch(\'http://localhost:\'+(process.env.PORT||4000)+\'/readyz\').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"',
  'entrypoint ["sh", "scripts/docker-entrypoint.sh"]',
  'cmd ["node", "server/app.js"]',
]);
const SCAN_COMMAND = [
  'node scripts/verify-customer-image-content.js',
  ...IMAGE_SCAN_ROOTS.map((root) => `--root ${root}`),
].join(' ');

function approvedDockerInstructions() {
  return Object.freeze([
    'from node:22-bookworm-slim AS node-runtime-source',
    'from node:22-bookworm-slim AS production-dependencies',
    'workdir /app',
    'run apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*',
    'copy package.json package-lock.json ./',
    'run --mount=type=cache,target=/root/.npm npm ci --omit=dev --omit=optional',
    'from node:22-bookworm-slim AS artifact-builder',
    'workdir /app',
    'copy console/package.json console/package-lock.json ./console/',
    'run --mount=type=cache,target=/root/.npm npm ci --prefix console',
    'copy scripts/build-customer-console.js ./scripts/build-customer-console.js',
    'copy console/ ./console/',
    'run node scripts/build-customer-console.js',
    'copy . .',
    'run node scripts/validate-customer-dockerfile.js Dockerfile',
    'run node scripts/stage-customer-runtime.js --out /tmp/customer-runtime',
    'from postgres:17-bookworm AS runtime',
    'arg REDACTWALL_LICENSE_PUBLIC_KEY_B64=""',
    'run groupadd --gid 1000 node && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin node',
    'copy --from=node-runtime-source /usr/local/bin/node /usr/local/bin/node',
    'copy --from=node-runtime-source /usr/local/lib/node_modules/npm/ /usr/local/lib/node_modules/npm/',
    'run ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx',
    'run node --version && npm --version && pg_dump --version && pg_restore --version',
    'env NODE_ENV=production PORT=4000 REDACTWALL_DB_PATH=/data/redactwall.db REDACTWALL_DATA_DIR=/data REDACTWALL_POLICY_PATH=/data/policy.json REDACTWALL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json REDACTWALL_LICENSE_PUBLIC_KEY_B64=${REDACTWALL_LICENSE_PUBLIC_KEY_B64} NPM_CONFIG_CACHE=/tmp/.npm NPM_CONFIG_UPDATE_NOTIFIER=false',
    'workdir /app',
    'copy --from=production-dependencies --chown=node:node /app/node_modules ./node_modules',
    'copy --from=artifact-builder --chown=node:node /tmp/customer-runtime/ ./',
    'run rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem /usr/local/lib/node_modules/npm/.npmrc',
    'run if [ -n "$REDACTWALL_LICENSE_PUBLIC_KEY_B64" ]; then node scripts/check-license-trust-anchor.js; fi',
    'run mkdir -p /data /gateway-data /license /app/data /tmp/redactwall && chown -R node:node /data /gateway-data /license /app /tmp/redactwall && chmod 700 /data /gateway-data /license /tmp/redactwall',
    `run ${SCAN_COMMAND}`,
    ...APPROVED_POST_SCAN_TAIL,
  ]);
}

function dockerfileError(message) {
  return new Error(`customer Dockerfile rejected: ${message}`);
}

function validateParserDirectives(source) {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  if (lines[0] !== APPROVED_SYNTAX_DIRECTIVE) {
    throw dockerfileError('Docker syntax directive differs from the exact allowlist');
  }
  if (lines.slice(1).some((line) => /^\s*#\s*(?:syntax|escape|check)\s*=/i.test(line))) {
    throw dockerfileError('additional Docker parser directives are forbidden');
  }
}

function logicalDockerInstructions(source) {
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > 128 * 1024) {
    throw dockerfileError('source is invalid or oversized');
  }
  if (/^\s*#\s*escape\s*=/im.test(source)) throw dockerfileError('custom escape directives are forbidden');
  const instructions = [];
  let pending = '';
  let startLine = 0;
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!pending && (!line.trim() || /^\s*#/.test(line))) continue;
    if (!pending) startLine = index + 1;
    if (/\\\s*$/.test(line)) {
      pending += `${line.replace(/\\\s*$/, '')} `;
      continue;
    }
    const logical = `${pending}${line}`.trim();
    pending = '';
    const match = logical.match(/^([a-z]+)\s+([\s\S]+)$/i);
    if (!match) throw dockerfileError(`invalid instruction at line ${startLine}`);
    instructions.push(Object.freeze({
      args: match[2].replace(/\s+/g, ' ').trim(),
      line: startLine,
      name: match[1].toLowerCase(),
    }));
  }
  if (pending) throw dockerfileError(`unterminated continuation at line ${startLine}`);
  return Object.freeze(instructions);
}

function sameArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function runtimeInstructions(source) {
  const instructions = logicalDockerInstructions(source);
  const bases = instructions.filter((instruction) => instruction.name === 'from')
    .map((instruction) => instruction.args);
  if (!sameArray(bases, APPROVED_STAGE_BASES)) {
    throw dockerfileError('stage bases, names, or order differ from the exact allowlist');
  }
  const runtimeIndex = instructions.findIndex((instruction) => (
    instruction.name === 'from' && instruction.args === APPROVED_STAGE_BASES.at(-1)
  ));
  return Object.freeze(instructions.slice(runtimeIndex + 1));
}

function validateScanTail(instructions) {
  const scanIndexes = instructions
    .map((instruction, index) => (
      instruction.name === 'run' && instruction.args === SCAN_COMMAND ? index : -1
    ))
    .filter((index) => index >= 0);
  if (scanIndexes.length !== 1) throw dockerfileError('exactly one final durable-filesystem scan is required');
  const tail = instructions.slice(scanIndexes[0] + 1)
    .map((instruction) => `${instruction.name} ${instruction.args}`);
  if (!sameArray(tail, APPROVED_POST_SCAN_TAIL)) {
    throw dockerfileError('instructions after the authority scan differ from the metadata-only tail');
  }
}

function validateCustomerDockerfile(source) {
  validateParserDirectives(source);
  const instructions = logicalDockerInstructions(source);
  const runtime = runtimeInstructions(source);
  if (instructions.some((instruction) => ['add', 'onbuild'].includes(instruction.name))) {
    throw dockerfileError('ADD and ONBUILD are forbidden in every stage');
  }
  validateScanTail(instructions);
  const actual = instructions.map((instruction) => `${instruction.name} ${instruction.args}`);
  if (!sameArray(actual, approvedDockerInstructions())) {
    throw dockerfileError('complete builder and runtime instructions differ from the exact allowlist');
  }
  const runtimeCopies = runtime.filter((instruction) => instruction.name === 'copy')
    .map((instruction) => instruction.args);
  if (!sameArray(runtimeCopies, APPROVED_RUNTIME_COPIES)) {
    throw dockerfileError('runtime COPY inventory differs from the exact allowlist');
  }
  return Object.freeze({ instructions, runtime, scanCommand: SCAN_COMMAND });
}

function main(argv = process.argv.slice(2), consoleImpl = console) {
  try {
    if (argv.length !== 1) throw dockerfileError('Usage: validate-customer-dockerfile.js <Dockerfile>');
    const dockerfilePath = path.resolve(argv[0]);
    const source = fs.readFileSync(dockerfilePath, 'utf8');
    validateCustomerDockerfile(source);
    consoleImpl.log('Customer Dockerfile builder ingress, runtime source, and post-scan gates verified');
    return 0;
  } catch (error) {
    consoleImpl.error(error.message);
    return 1;
  }
}

if (require.main === module) process.exitCode = main();

module.exports = {
  APPROVED_POST_SCAN_TAIL,
  APPROVED_RUNTIME_COPIES,
  APPROVED_STAGE_BASES,
  APPROVED_SYNTAX_DIRECTIVE,
  SCAN_COMMAND,
  approvedDockerInstructions,
  logicalDockerInstructions,
  main,
  runtimeInstructions,
  validateCustomerDockerfile,
  validateParserDirectives,
};
