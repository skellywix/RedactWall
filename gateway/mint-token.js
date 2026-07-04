'use strict';
/**
 * Mint an AI Gateway agent token. Prints the raw token ONCE; only its hash is
 * persisted. Revoke with `--revoke <id>`; list with `--list`.
 *
 *   node gateway/mint-token.js --user agent@app.example --org acme --label "billing bot"
 *   node gateway/mint-token.js --list
 *   node gateway/mint-token.js --revoke tok_ab12cd34
 */
const tokens = require('./tokens');
const { config } = require('./config');

function arg(name) {
  const i = process.argv.indexOf('--' + name);
  return i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[i + 1] : undefined;
}

function main() {
  const tokensPath = config().agentTokensPath;
  if (process.argv.includes('--list')) {
    for (const t of tokens.listTokens(tokensPath)) {
      process.stdout.write(`${t.id}\t${t.revoked ? 'REVOKED' : 'active'}\t${t.user}\t${t.orgId || '-'}\t${t.label}\n`);
    }
    return;
  }
  const revoke = arg('revoke');
  if (revoke) {
    process.stdout.write(tokens.revokeToken(revoke, tokensPath) ? `revoked ${revoke}\n` : `no active token ${revoke}\n`);
    return;
  }
  const minted = tokens.mintToken({ user: arg('user'), orgId: arg('org'), label: arg('label') }, tokensPath);
  process.stdout.write(
    `Agent token minted (store this now — it is not shown again):\n\n  ${minted.token}\n\n`
    + `  id:   ${minted.id}\n  user: ${minted.user}\n  org:  ${minted.orgId || '-'}\n\n`
    + `Use it as: Authorization: Bearer ${minted.token}\n`,
  );
}

main();
