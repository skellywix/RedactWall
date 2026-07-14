'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const childProcess = require('node:child_process');

const root = path.join(__dirname, '..');
const template = fs.readFileSync(path.join(root, 'infra', 'aws', 'customer-silo.yml'), 'utf8');
const dataTemplate = fs.readFileSync(path.join(root, 'infra', 'aws', 'customer-data-volume.yml'), 'utf8');
const docs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'AWS_SAAS_DEPLOYMENT.md'), 'utf8');
const technicianDocs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'TECHNICIAN_DEPLOYMENT_GUIDE.md'), 'utf8');
const launchDocs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'PRODUCTION_LAUNCH_GUIDE.md'), 'utf8');
const connectedDocs = fs.readFileSync(path.join(root, 'docs', 'process', 'CONNECTED_DEPLOYMENT.md'), 'utf8');
const licensingConsole = fs.readFileSync(path.join(root, 'console', 'src', 'views', 'Licensing.tsx'), 'utf8');
const deployScriptSource = fs.readFileSync(path.join(root, 'infra', 'aws', 'scripts', 'redactwall-deploy.sh'), 'utf8').replace(/\r\n/g, '\n');
const metadata = template.match(/    Metadata:\r?\n(?<body>[\s\S]*?)\n    Properties:/);
assert.ok(metadata, 'AppInstance CloudFormation init metadata is present');
const deployment = metadata.groups.body;

function deployFunction(name, nextName) {
  const start = deployment.indexOf(`                ${name}() {`);
  const end = nextName ? deployment.indexOf(`                ${nextName}() {`, start) : deployment.length;
  assert.ok(start >= 0 && end > start, `${name} deployment function is present`);
  return deployment.slice(start, end);
}

function deployFunctionToMarker(name, marker) {
  const start = deployment.indexOf(`                ${name}() {`);
  const end = deployment.indexOf(marker, start);
  assert.ok(start >= 0 && end > start, `${name} deployment function is present before ${marker}`);
  return deployment.slice(start, end);
}

function bashExecutable() {
  const candidates = process.platform === 'win32'
    ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'bash.exe']
    : ['bash'];
  return candidates.find((candidate) => {
    const probe = childProcess.spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    return !probe.error && probe.status === 0;
  }) || null;
}

function metadataFileScript(filePath) {
  const marker = `            ${filePath}:`;
  const start = template.indexOf(marker);
  const content = template.indexOf('\n', template.indexOf('content:', start)) + 1;
  const end = template.indexOf("\n              mode: '000700'", content);
  assert.ok(start >= 0 && content > start && end > content, `${filePath} metadata script is present`);
  return template.slice(content, end).split(/\r?\n/)
    .map((line) => line.startsWith('                ') ? line.slice(16) : line).join('\n');
}

function deployScriptFromTemplate() {
  const contentStart = template.indexOf('              content: !Sub |');
  const scriptStart = template.indexOf('\n', contentStart) + 1;
  const scriptEnd = template.indexOf("\n              mode: '000700'", scriptStart);
  assert.ok(contentStart >= 0 && scriptStart > contentStart && scriptEnd > scriptStart);
  return `${template.slice(scriptStart, scriptEnd).replace(/^ {16}/gm, '')}\n`.replace(/\r\n/g, '\n');
}

function deployScriptForSyntaxCheck() {
  return deployScriptFromTemplate()
    .replaceAll('${LicenseSecretVersionId}', '12345678-1234-1234-1234-123456789012')
    .replaceAll('${DeploymentId}', 'dep_0123456789abcdef0123456789abcdef')
    .replaceAll('${DataStackName}', 'redactwall-cu-test-data')
    .replaceAll('${DataVolumeId}', 'vol-0123456789abcdef0')
    .replaceAll('${SourceDataVolumeId}', '')
    .replaceAll('${PublicHostname}', 'cu-test.redactwall.example')
    .replaceAll('${SecretArn}', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall')
    .replaceAll('${AWS::Region}', 'us-east-1')
    .replaceAll('${TenantId}', 'cu-test')
    .replaceAll('${ImageUri}', `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`)
    .replaceAll('${DesiredConfigSha256}', 'b'.repeat(64))
    .replaceAll('${DeploymentTemplateSha256}', 'c'.repeat(64))
    .replaceAll('${DeploymentProtocolSha256}', 'd'.repeat(64))
    .replaceAll('${AppLogGroup}', 'redactwall-log');
}

test('AWS deploy protocol is an extracted testable script with zero template drift', () => {
  assert.strictEqual(deployScriptFromTemplate(), deployScriptSource);
});

function parameterAllowedPattern(name) {
  const block = template.match(new RegExp(`  ${name}:\\r?\\n(?<body>[\\s\\S]*?)(?=\\n  [A-Za-z][A-Za-z0-9]+:)`));
  assert.ok(block, `${name} parameter block is present`);
  const pattern = block.groups.body.match(/AllowedPattern: '([^']+)'/);
  assert.ok(pattern, `${name} has an AllowedPattern`);
  return new RegExp(pattern[1]);
}

test('AWS customer-silo template enforces immutable connected tenant and deployment parameters without static seats', () => {
  assert.match(template, /TenantId:/);
  assert.match(template, /DeploymentId:[\s\S]*AllowedPattern: '\^dep_\[a-f0-9\]\{32\}\$'/);
  assert.doesNotMatch(template, /^  SeatLimit:/m);
  assert.doesNotMatch(template, /^  LicenseMode:/m);
  assert.match(template, /REDACTWALL_SAAS_MODE=true/);
  assert.match(template, /REDACTWALL_TENANT_ID=\$\{TenantId\}/);
  assert.match(template, /REDACTWALL_CONNECTED_DEPLOYMENT_ID=\$\{DeploymentId\}/);
  assert.match(template, /REDACTWALL_LICENSE_MODE=connected/);
  assert.doesNotMatch(template, /REDACTWALL_SEAT_LIMIT=/);
  assert.match(template, /REDACTWALL_REQUIRE_TENANT_CONTEXT=true/);
  assert.match(template, /REDACTWALL_REQUIRE_USER_IDENTITY=true/);
  assert.match(template, /TRUST_PROXY=1/, 'ALB client IPs must not collapse into one login lockout bucket');
});

test('AWS customer-silo template uses local EBS-backed data and Secrets Manager', () => {
  assert.match(template, /VolumeType: gp3/);
  assert.match(template, /Encrypted: true/);
  assert.match(template, /-v \/var\/lib\/redactwall\/runtime:\/data/);
  assert.match(template, /REDACTWALL_POLICY_PATH=\/data\/policy\.json/);
  assert.match(template, /REDACTWALL_CUSTOM_DETECTORS_PATH=\/data\/custom-detectors\.json/);
  assert.match(template, /secretsmanager:GetSecretValue/);
  assert.match(template, /HealthCheckPath: \/readyz/);
  assert.match(template, /install -d -m 700 -o 1000 -g 1000 \/var\/lib\/redactwall\/runtime/,
    'the non-root image must own its private persistent data directory before bind mount');
});

test('AWS evidence state uses a retained encrypted volume with boot-time identity enforcement', () => {
  const volume = dataTemplate.match(/  CustomerDataVolume:\r?\n(?<body>[\s\S]*?)\nOutputs:/);
  assert.ok(volume);
  assert.match(volume.groups.body, /DeletionPolicy: Retain/);
  assert.match(volume.groups.body, /UpdateReplacePolicy: Retain/);
  assert.match(volume.groups.body, /AvailabilityZone: !Ref AvailabilityZone/);
  assert.match(volume.groups.body, /Encrypted: true/);
  assert.doesNotMatch(template, /Type: AWS::EC2::Volume\s/,
    'the replaceable application stack never creates a new data authority');
  assert.match(template, /DataVolumeId:[\s\S]*AllowedPattern: '\^vol-/);
  assert.match(template, /CustomerDataVolumeAttachment:[\s\S]*VolumeId: !Ref DataVolumeId/);
  assert.match(template, /redactwall-verify-data-volume/);
  assert.match(template, /RequiresMountsFor=\/var\/lib\/redactwall/);
  assert.match(template, /\.redactwall-volume-identity\.json/);
  assert.match(template, /source_serial[\s\S]*DATA_VOLUME_SERIAL/);
  assert.match(template, /ec2:DescribeVolumes/);
  assert.match(template, /describe-volumes --volume-ids "\$DATA_VOLUME_ID"/);
  assert.match(template, /SnapshotId == null[\s\S]*CreateTime/);
  assert.ok(template.indexOf('describe-volumes --volume-ids "$DATA_VOLUME_ID"')
    < template.indexOf('mkfs.xfs -f -L REDACTWALL_DATA'),
  'formatting occurs only after the blank device is proven to be a fresh no-snapshot stack volume');
  assert.doesNotMatch(template, /defaults,nofail/);
  assert.match(template, /DataVolumeId:[\s\S]*Value: !Ref DataVolumeId/);
  assert.match(dataTemplate, /SnapshotId:[\s\S]*SourceDataVolumeId:/);
  assert.match(dataTemplate, /SnapshotContinuityPair:/);
  assert.match(template, /sourceVolumeId[\s\S]*tenantId[\s\S]*version:4/,
    'an explicit snapshot restore preserves marker lineage while rebinding the exact new volume id');
  assert.match(template, /FORMATTED_FRESH=1[\s\S]*version:3[\s\S]*tenantId/,
    'only a freshly formatted no-snapshot volume can receive the first tenant-bound marker');
  assert.match(template, /now_epoch - created_epoch[\s\S]*-gt 3600/,
    'automatic formatting is limited to the documented one-hour fresh-volume window');
  assert.match(template, /MultiAttachEnabled == false/);
  assert.match(template, /RedactWallAuthority[\s\S]*retained-external/);
  assert.match(template, /cloudformation:DescribeStacks/);
  assert.match(template, /aws:cloudformation:stack-id/);
  assert.match(template, /DeleteOnTermination: true/,
    'replaceable OS roots must not masquerade as the retained customer store');
});

test('AWS host requires IMDSv2 and prevents container-hop credential access', () => {
  assert.match(template, /MetadataOptions:[\s\S]*HttpTokens: required/);
  assert.match(template, /MetadataOptions:[\s\S]*HttpPutResponseHopLimit: 1/);
  assert.match(template, /MetadataOptions:[\s\S]*InstanceMetadataTags: disabled/);
});

test('AWS application logs survive stack deletion and replacement', () => {
  const logGroup = template.match(/  AppLogGroup:\r?\n(?<body>[\s\S]*?)\n  InstanceRole:/);
  assert.ok(logGroup, 'AppLogGroup resource is present');
  assert.match(logGroup.groups.body, /^    DeletionPolicy: Retain$/m);
  assert.match(logGroup.groups.body, /^    UpdateReplacePolicy: Retain$/m);
  assert.doesNotMatch(logGroup.groups.body, /LogGroupName:/, 'retained log group must not block stack recreation with a fixed name');
  assert.match(template, /Resource: !Sub \$\{AppLogGroup\.Arn\}:\*/);
  assert.match(template, /--log-opt awslogs-group='\$\{AppLogGroup\}'/);
  assert.match(template, /^  LogGroupName:\r?\n[\s\S]*?^    Value: !Ref AppLogGroup$/m);
});

test('AWS customer-silo container runs with hardened Docker flags', () => {
  assert.match(template, /--hostname redactwall/);
  assert.match(template, /--init/);
  assert.match(template, /--read-only/);
  assert.match(template, /--tmpfs \/tmp:rw,noexec,nosuid,size=64m/);
  assert.match(template, /--cap-drop ALL/);
  assert.match(template, /--security-opt no-new-privileges/);
  assert.match(template, /--stop-timeout 30/);
});

test('AWS bootstrap failure-signals and waits for container health plus readyz before one success signal', () => {
  const metadata = template.match(/    Metadata:\r?\n(?<body>[\s\S]*?)\n    Properties:/);
  assert.ok(metadata, 'AppInstance CloudFormation init metadata is present');
  const deployment = metadata.groups.body;
  const userData = template.match(/Fn::Base64: !Sub \|(?<body>[\s\S]*?)\n  LoadBalancer:/);
  assert.ok(userData, 'AppInstance UserData is present');
  const bootstrap = userData.groups.body;
  assert.match(bootstrap, /trap bootstrap_failed EXIT/);
  assert.match(bootstrap, /cfn-signal[^\n]+--exit-code "?\$exit_code"?/);
  assert.match(bootstrap, /cfn-init[^\n]+--resource AppInstance/);
  assert.match(deployment, /for attempt in \$\(seq 1 60\)/);
  assert.match(deployment, /docker inspect[^\n]+\.State\.Status/);
  assert.match(deployment, /docker inspect[^\n]+\.State\.Health\.Status/);
  assert.match(deployment, /exited\|dead\|restarting\|missing\)[\s\S]*?exit 1/);
  assert.match(deployment, /curl[^\n]+--max-time 3[^\n]+127\.0\.0\.1:4000\/readyz/);
  assert.match(deployment, /if \[ "\$READY" -ne 1 \]; then[\s\S]*?exit 1/);

  const successSignals = [...bootstrap.matchAll(/cfn-signal[^\n]+--exit-code 0/g)];
  assert.strictEqual(successSignals.length, 1, 'bootstrap emits exactly one success signal');
  assert.ok(successSignals[0].index > bootstrap.indexOf('cfn-init'), 'success signal occurs only after cfn-init deployment succeeds');
  assert.ok(bootstrap.lastIndexOf('trap - EXIT') > successSignals[0].index, 'failure trap remains armed until success signal completes');
});

test('AWS image and immutable secret-version updates are applied by cfn-hup with readiness rollback', () => {
  const userData = template.match(/Fn::Base64: !Sub \|(?<body>[\s\S]*?)\n  LoadBalancer:/);
  assert.ok(metadata && userData);
  assert.match(metadata.groups.body, /AWS::CloudFormation::Init/);
  assert.match(metadata.groups.body, /DESIRED_IMAGE_URI='\$\{ImageUri\}'/);
  assert.match(metadata.groups.body, /docker pull "\$IMAGE_URI"/);
  assert.match(metadata.groups.body, /LICENSE_SECRET_VERSION_ID='\$\{LicenseSecretVersionId\}'/);
  assert.match(metadata.groups.body, /--version-id "\$LICENSE_SECRET_VERSION_ID"/);
  assert.match(metadata.groups.body, /PREVIOUS_CONTAINER_NAME="redactwall-previous-\$TX_ID"/);
  assert.match(metadata.groups.body, /rollback_deploy\(\)[\s\S]*rollback_transaction/);
  assert.match(userData.groups.body, /triggers=post\.update/);
  assert.match(userData.groups.body, /path=Resources\.AppInstance\.Metadata\.AWS::CloudFormation::Init/);
  assert.match(userData.groups.body, /action=\/usr\/local\/sbin\/redactwall-cfn-update/);
  assert.match(metadata.groups.body, /redactwall-cfn-update:[\s\S]*flock -w 30 9[\s\S]*\/opt\/aws\/bin\/cfn-init/);
  assert.match(userData.groups.body, /systemctl enable --now cfn-hup\.service/);
  const recoveryStart = userData.groups.body.indexOf("RECOVERY_BACKUP_NAME='${RecoveryBackupName}'");
  assert.ok(recoveryStart >= 0);
  assert.doesNotMatch(userData.groups.body.slice(0, recoveryStart), /\$\{ImageUri\}/,
    'ordinary image changes stay in metadata and do not rely on one-shot user data');
  assert.match(userData.groups.body.slice(recoveryStart), /docker pull '\$\{ImageUri\}'/,
    'explicit rollback recovery verifies with the exact prior image before metadata can restart it');
  assert.match(metadata.groups.body, /redactwall-apply-and-attest/);
  assert.match(metadata.groups.body, /redactwall-assert-applied/);
  assert.match(metadata.groups.body, /redactwall-validate-release-input/);
  assert.match(metadata.groups.body, /license_root_trust_anchor/);
  assert.match(metadata.groups.body, /applied-deployment\.json/);
  assert.match(metadata.groups.body, /imageUri:\$imageUri[\s\S]*secretArn:\$secretArn[\s\S]*secretVersionId:\$secretVersionId/);
  assert.match(metadata.groups.body, /desiredConfigSha256:\$desiredConfigSha256/);
  assert.match(metadata.groups.body, /\.Config\.Image.*= "\$expected_image"/);
  assert.match(metadata.groups.body, /\/license\/redactwall\.lic.*\/etc\/redactwall\/license\/redactwall\.lic\|false/);
  assert.match(metadata.groups.body, /\.State\.Health\.Status[\s\S]*= healthy/);
  assert.match(metadata.groups.body, /seq 1 12[\s\S]*--max-time 3[\s\S]*127\.0\.0\.1:4000\/readyz/);
  assert.match(metadata.groups.body, /recovery_path=\$\(jq -r '\.recoveryPath \/\/ empty'/);
  assert.match(metadata.groups.body, /if path_present "\$RECOVERY_PARENT"[\s\S]*mkdir -- "\$RECOVERY_DIR"/);
  assert.match(metadata.groups.body, /REDACTWALL_APPLIED_WARNING=/);
});

test('AWS desired-config attestation hashes the same complete rendering contract at commit and readback', () => {
  assert.match(deployment, /DESIRED_CONFIG_SHA256='\$\{DesiredConfigSha256\}'/);
  assert.match(deployment, /TEMPLATE_SHA256='\$\{DeploymentTemplateSha256\}'/);
  assert.match(deployment, /PROTOCOL_SHA256='\$\{DeploymentProtocolSha256\}'/);
  assert.match(deployment, /desiredConfigSha256:\$desiredConfigSha256,templateSha256:\$templateSha256,protocolSha256:\$protocolSha256/);
  const assertion = deployment.match(/\/usr\/local\/sbin\/redactwall-assert-applied:[\s\S]*?mode: '000700'/)?.[0] || '';
  assert.match(assertion, /deployment-contract\.json/);
  assert.match(assertion, /sha256sum \/usr\/local\/sbin\/redactwall-deploy/);
  assert.match(assertion, /\.desiredConfigSha256 == \$config/);
  assert.match(assertion, /\.templateSha256 == \$template/);
  assert.match(assertion, /\.protocolSha256 == \$protocol/);
  const applyAndAttest = deployment.match(/\/usr\/local\/sbin\/redactwall-apply-and-attest:[\s\S]*?mode: '000700'/)?.[0] || '';
  const cfnUpdate = deployment.match(/\/usr\/local\/sbin\/redactwall-cfn-update:[\s\S]*?mode: '000700'/)?.[0] || '';
  assert.match(applyAndAttest, /exec \/usr\/local\/sbin\/redactwall-cfn-update "\$@"/);
  assert.match(cfnUpdate, /cfn-init[\s\S]*redactwall-assert-applied "\$@"/,
    'even an unchanged image or secret rematerializes and verifies the exact template protocol');
});

test('AWS generated root deployment shell is syntactically valid when bash is available', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const result = childProcess.spawnSync(bash, ['-n', '-s'], {
    input: deployScriptForSyntaxCheck(),
    encoding: 'utf8',
  });
  assert.strictEqual(result.status, 0, result.stderr || result.stdout || 'bash syntax check failed');
});

test('AWS maintenance coordination shells are syntactically valid when bash is available', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  for (const script of [
    '/usr/local/sbin/redactwall-cfn-update',
    '/usr/local/sbin/redactwall-maintenance-control',
    '/usr/local/sbin/redactwall-maintenance-drain',
    '/usr/local/sbin/redactwall-maintenance-resume',
    '/usr/local/sbin/redactwall-maintenance-clear',
    '/usr/local/sbin/redactwall-maintenance-status',
    '/usr/local/sbin/redactwall-maintenance-abort',
    '/usr/local/sbin/redactwall-maintenance-checkpoint',
  ]) {
    const result = childProcess.spawnSync(bash, ['-n', '-s'], {
      input: metadataFileScript(script), encoding: 'utf8', timeout: 30_000,
    });
    assert.strictEqual(result.status, 0, `${script}: ${result.stderr || result.stdout || 'bash syntax check failed'}`);
  }
});

test('AWS durable journal survives a real process kill after every published phase', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const jqProbe = childProcess.spawnSync('jq', ['--version'], { encoding: 'utf8' });
  if (jqProbe.error || jqProbe.status !== 0) return t.skip('jq is unavailable');
  const rootDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'redactwall-aws-journal-'));
  t.after(() => fs.rmSync(rootDir, { recursive: true, force: true }));
  const shellRoot = rootDir.replace(/\\/g, '/');
  const journalFunction = deployFunction('journal_write', 'valid_snapshot_json').replace(/^ {16}/gm, '');
  const image = `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`;
  const phases = [
    'prepared', 'previous_moved', 'prior_secured', 'candidate_published', 'license_unchanged',
    'candidate_created', 'candidate_started', 'candidate_ready', 'candidate_named', 'committed',
  ];
  for (const phase of phases) {
    const journal = path.join(rootDir, 'license-deploy-journal.json');
    fs.rmSync(journal, { force: true });
    const harness = `
set -euo pipefail
DEPLOY_STATE_DIR='${shellRoot}'
DEPLOY_JOURNAL="$DEPLOY_STATE_DIR/license-deploy-journal.json"
TX_ID=${'b'.repeat(32)}
TX_PHASE=
IMAGE_URI='${image}'
LICENSE_SECRET_VERSION_ID=12345678-1234-1234-1234-123456789012
PREVIOUS_CONTAINER_ID=
PREVIOUS_CONTAINER_RUNNING=false
PREVIOUS_IMAGE_URI=
CANDIDATE_CONTAINER_ID=${'c'.repeat(64)}
PRIOR_LICENSE_JSON=null
CANDIDATE_LICENSE_JSON='{"dev":"1","ino":"2","nlink":"1","size":"3","uid":"1000","gid":"1000","mode":"400","sha256":"${'d'.repeat(64)}"}'
LICENSE_CHANGED=true
SECRET_ARN='arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall'
CONFIG_SHA256=${'e'.repeat(64)}
TEMPLATE_SHA256=${'f'.repeat(64)}
PROTOCOL_SHA256=${'1'.repeat(64)}
TX_IMAGE_URI="$IMAGE_URI"
TX_SECRET_ARN="$SECRET_ARN"
TX_LICENSE_SECRET_VERSION_ID="$LICENSE_SECRET_VERSION_ID"
TX_CONFIG_SHA256="$CONFIG_SHA256"
TX_TEMPLATE_SHA256="$TEMPLATE_SHA256"
TX_PROTOCOL_SHA256="$PROTOCOL_SHA256"
RECOVERY_BACKUP_NAME=
RECOVERY_MANIFEST_NAME=
${journalFunction}
export REDACTWALL_DEPLOY_TEST_CRASH_AFTER='${phase}'
journal_write '${phase}'
`;
    const result = childProcess.spawnSync(bash, ['-s'], { input: harness, encoding: 'utf8' });
    assert.notStrictEqual(result.status, 0, phase);
    assert.ok(fs.existsSync(journal), `${phase} journal was durably published before the kill`);
    const parsed = JSON.parse(fs.readFileSync(journal, 'utf8'));
    assert.strictEqual(parsed.phase, phase);
    assert.strictEqual(parsed.imageUri, image);
    assert.strictEqual(parsed.secretVersionId, '12345678-1234-1234-1234-123456789012');
    assert.strictEqual(fs.readdirSync(rootDir).some((name) => name.startsWith('.license-deploy-journal.')), false);
  }
});

test('AWS shell-interpolated parameters reject quote breaks and command metacharacters', () => {
  const imagePattern = parameterAllowedPattern('ImageUri');
  const secretPattern = parameterAllowedPattern('SecretArn');
  const versionPattern = parameterAllowedPattern('LicenseSecretVersionId');
  assert.ok(imagePattern.test(`123456789012.dkr.ecr.us-gov-west-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`));
  assert.strictEqual(
    imagePattern.test('123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall/app:release-2026.07'),
    false,
    'mutable tags cannot select host-root bootstrap code',
  );
  assert.ok(secretPattern.test('arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-acme-Ab12_3'));
  assert.ok(versionPattern.test('12345678-1234-1234-1234-123456789012'));

  const attacks = [
    "x'; touch /tmp/pwned; echo 'x",
    'x$(touch /tmp/pwned)',
    'x`touch /tmp/pwned`',
    'x;touch_/tmp/pwned',
    'x\nmalicious',
  ];
  for (const attack of attacks) {
    assert.strictEqual(imagePattern.test(attack), false, `ImageUri rejects ${JSON.stringify(attack)}`);
    assert.strictEqual(secretPattern.test(attack), false, `SecretArn rejects ${JSON.stringify(attack)}`);
    assert.strictEqual(versionPattern.test(attack), false, `LicenseSecretVersionId rejects ${JSON.stringify(attack)}`);
  }
});

test('AWS secret values cannot inject additional env-file records', () => {
  assert.match(template, /secret\(\) \{[\s\S]*jq -er --arg key/);
  assert.ok(template.includes('test("[\\u0000-\\u001f\\u007f]")'));
  assert.match(template, /invalid secret value/);
  assert.doesNotMatch(template, /cat > "\$ENV_TMP" <<EOF/);
  for (const key of [
    'ADMIN_PASSWORD', 'ADMIN_TOTP_SECRET', 'AUDITOR_USER', 'AUDITOR_PASSWORD',
    'REDACTWALL_SECRET', 'REDACTWALL_DATA_KEY', 'INGEST_API_KEY',
    'SIEM_WEBHOOK_URL', 'SIEM_WEBHOOK_TOKEN',
  ]) {
    assert.match(template, new RegExp(`printf '${key}=%s\\\\n' "\\$${key}"`));
  }
  assert.match(template, /sync -f "\$ENV_TMP"[\s\S]*mv -f "\$ENV_TMP" \/etc\/redactwall\/env[\s\S]*sync -f \/etc\/redactwall/);
  assert.match(template, /keys - \[[\s\S]*"REDACTWALL_LICENSE_PUBLIC_KEY_B64"[\s\S]*"OIDC_ISSUER"[\s\S]*"REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64"/,
    'unknown secret fields are rejected instead of silently ignored');
  for (const key of [
    'OPERATOR_USER', 'OPERATOR_PASSWORD', 'APPROVER_USER', 'APPROVER_PASSWORD',
    'SCIM_BEARER_TOKEN', 'OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET',
    'OIDC_REDIRECT_URI', 'OIDC_AUTHORIZATION_ENDPOINT', 'OIDC_TOKEN_ENDPOINT',
    'OIDC_JWKS_URI', 'OIDC_SCOPE', 'REDACTWALL_LICENSE_PUBLIC_KEY_B64',
  ]) assert.match(template, new RegExp(`printf '${key}=%s\\\\n' "\\$${key}"`));
  assert.match(template, /REDACTWALL_PUBLIC_URL=https:\/\/\$\{PublicHostname\}/);
});

test('AWS licensing is connected-only with purpose-specific credentials and complete trust pins', () => {
  assert.doesNotMatch(template, /^  LicenseMode:/m);
  assert.match(deployment, /REDACTWALL_LICENSE_MODE=connected/);
  assert.match(deployment, /REDACTWALL_LICENSE_SERVER_URL=%s/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN=%s/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN=%s/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN=%s/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN=%s/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED=%s/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED=%s/);
  assert.match(deployment, /REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64=%s/);
  assert.match(deployment, /REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64=%s/);
  assert.match(deployment, /REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64=%s/);
  assert.match(deployment, /REDACTWALL_ENTITLEMENT_KEY_ID=%s/);
  assert.match(deployment, /REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64=%s/);
  assert.match(deployment, /REDACTWALL_ENTITLEMENT_NEXT_KEY_ID=%s/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED == "true"[\s\S]*== "false"/);
  assert.match(deployment, /REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED == "true"[\s\S]*== "false"/);
  assert.match(deployment, /has\("REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64"\)[\s\S]*has\("REDACTWALL_ENTITLEMENT_NEXT_KEY_ID"\)/);
  for (const checkId of [
    'connected_license_auth', 'connected_license_optional_channels',
    'connected_license_legacy_auth', 'connected_license_timing',
    'connected_license_deployment_id', 'connected_license_verdict_key',
    'connected_entitlement_keys', 'connected_offline_fallback',
  ]) assert.match(deployment, new RegExp(`"${checkId}"`));
  assert.doesNotMatch(template, /REDACTWALL_LICENSE_SERVER_TOKEN/);
});

test('managed AWS licensing console does not offer the rejected in-app installer', () => {
  assert.match(licensingConsole, /managedExternally\?: boolean/);
  assert.match(licensingConsole, /license\.managedExternally[\s\S]*ManagedLicensePanel[\s\S]*InstallPanel/);
  assert.match(licensingConsole, /immutable deployment workflow/);
});

test('AWS customer-silo requires and durably publishes a deployment-bound active fallback license', () => {
  const metadata = template.match(/    Metadata:\r?\n(?<body>[\s\S]*?)\n    Properties:/);
  assert.ok(metadata, 'AppInstance CloudFormation init metadata is present');
  const deployment = metadata.groups.body;

  assert.match(template, /signed license/);
  assert.match(template, /LicenseSecretVersionId:/);
  assert.match(deployment, /REDACTWALL_LICENSE=\$\(secret REDACTWALL_LICENSE\)/);
  assert.match(deployment, /LICENSE_BYTES=\$\(printf '%s' "\$REDACTWALL_LICENSE" \| wc -c\)/);
  assert.match(deployment, /"\$LICENSE_BYTES" -gt 65535/);
  assert.match(deployment, /REDACTWALL_CONNECTED_DEPLOYMENT_ID=\$\{DeploymentId\}/);
  assert.match(deployment, /\.customerId == \$tenant/);
  assert.match(deployment, /\.deploymentId == \$deployment/);
  assert.match(deployment, /\.status == "active"/);
  assert.doesNotMatch(deployment, /--argjson seats/);
  assert.match(deployment, /REDACTWALL_LICENSE_PATH=\/license\/redactwall\.lic/);
  assert.match(deployment, /REDACTWALL_LICENSE_MANAGED_EXTERNALLY=true/);
  assert.match(deployment, /LICENSE_FINAL=\/etc\/redactwall\/license\/redactwall\.lic/);
  assert.match(deployment, /chown 1000:1000 "\/proc\/\$BASHPID\/fd\/\$license_stage_fd"/);
  assert.match(deployment, /chmod 400 "\/proc\/\$BASHPID\/fd\/\$license_stage_fd"/);
  assert.match(deployment, /--mount type=bind,src="\$LICENSE_FINAL",dst=\/license\/redactwall\.lic,readonly/);
  assert.match(template, /stat -c '%u:%g:%a:%h' \/etc\/redactwall\/license\/redactwall\.lic\)" = '1000:1000:400:1'/);
  assert.doesNotMatch(deployment, /-v \/var\/lib\/redactwall:\/data/);
  assert.match(deployment, /printf '%s\\n' "\$REDACTWALL_LICENSE"[\s\S]*docker run --rm -i/);
  assert.match(deployment, /--network none[\s\S]*--read-only[\s\S]*--cap-drop ALL[\s\S]*--security-opt no-new-privileges/);
  assert.match(deployment, /preflight\.configStatus/);
  assert.match(deployment, /connected_offline_fallback/);
  assert.match(deployment, /connected_license_deployment_id/);
  assert.match(deployment, /connected_entitlement_keys/);
  assert.match(deployment, /failed connected production preflight/);

  assert.match(deployment, /install -d -m 700 -o root -g root \/etc\/redactwall/);
  assert.match(deployment, /LICENSE_STAGE="\$DEPLOY_STATE_DIR\/license\.stage\.\$TX_ID"/);
  assert.match(deployment, /exec \{license_stage_fd\}> "\$LICENSE_STAGE"/);
  assert.match(deployment, /printf '%s\\n' "\$REDACTWALL_LICENSE" >&\$license_stage_fd/);
  assert.match(deployment, /\/proc\/\$BASHPID\/fd\/\$license_stage_fd/);
  assert.doesNotMatch(deployment, /mktemp \/var\/lib\/redactwall/,
    'root must never reopen a staging pathname in the application-owned data directory');

  const artifact = deployFunction('artifact_json', 'artifact_matches');
  assert.match(artifact, /stat -Lc '%d\|%i\|%h\|%s\|%u\|%g\|%a\|%y\|%z'/);
  assert.match(artifact, /sha256sum -- "\$artifact_handle"/);
  assert.match(artifact, /"\$handle_before" != "\$handle_after"/);
  assert.match(artifact, /"\$handle_before" != "\$path_after"/);
  assert.match(deployment, /same_license_bytes[\s\S]*LICENSE_CHANGED=false[\s\S]*CANDIDATE_LICENSE_JSON=\$PRIOR_LICENSE_JSON/,
    'unchanged signed bytes preserve the installed license identity');

  assert.match(deployment, /DEPLOY_JOURNAL=\/etc\/redactwall\/license-deploy-journal\.json/);
  for (const phase of [
    'prepared', 'previous_moved', 'prior_secured', 'candidate_published',
    'candidate_created', 'candidate_started', 'candidate_ready', 'candidate_named', 'committed',
  ]) assert.match(deployment, new RegExp(`journal_write ${phase}`));
  assert.match(deployment, /sync -f -- "\$journal_tmp"[\s\S]*mv -fT -- "\$journal_tmp" "\$DEPLOY_JOURNAL"[\s\S]*sync -f -- "\$DEPLOY_STATE_DIR"/);
  assert.doesNotMatch(deployFunction('journal_write', 'valid_snapshot_json'), /REDACTWALL_LICENSE/,
    'the recovery journal binds only identities and digests, never license bytes');
  assert.match(deployment, /reconcile_existing_transaction[\s\S]*journal_load[\s\S]*TX_PHASE" = committed[\s\S]*rollback_transaction/);

  const rollback = deployFunction('rollback_transaction', 'reconcile_existing_transaction');
  const removeCandidate = rollback.indexOf('remove_candidate_confirmed');
  const restoreLicense = rollback.indexOf('restore_license_transaction');
  const restoreRuntime = rollback.indexOf('restore_runtime_recovery_point');
  const restoreContainer = rollback.indexOf('restore_previous_container');
  assert.ok(removeCandidate >= 0 && removeCandidate < restoreLicense && restoreLicense < restoreRuntime && restoreRuntime < restoreContainer,
    'rollback confirms candidate removal, then restores license and runtime evidence before restarting the prior container');
  const remove = deployFunction('remove_candidate_confirmed', 'quarantine_candidate_license');
  assert.match(remove, /docker rm -f "\$candidate_id"[\s\S]*docker inspect "\$candidate_id"[\s\S]*remaining_candidate_id=\$\(discover_candidate_id\)/);
  assert.doesNotMatch(remove, /docker rm[^\n]+\|\| true/);
  assert.doesNotMatch(deployment, /docker rm -f redactwall-previous/,
    'familiar names are never sufficient authority to delete a recovery container');

  const restore = deployFunction('restore_license_transaction', 'cleanup_rollback_artifacts');
  assert.match(restore, /artifact_matches "\$LICENSE_FINAL" "\$CANDIDATE_LICENSE_JSON"[\s\S]*quarantine_candidate_license/);
  assert.match(restore, /publish_exact_private "\$LICENSE_ROLLBACK" "\$LICENSE_FINAL" "\$PRIOR_LICENSE_JSON"/);
  assert.match(deployment, /mv -nT -- "\$move_source" "\$move_destination"/);
  assert.match(deployment, /mv -nT -- "\$publish_source" "\$publish_destination"/);

  const commit = deployment.indexOf('journal_write committed');
  const cleanup = deployment.indexOf('reconcile_committed_cleanup', commit);
  assert.ok(commit >= 0 && cleanup > commit, 'cleanup starts only after the durable commit record');
  assert.ok(deployment.indexOf('COMMIT_ATTEMPTED=1') < commit,
    'the EXIT path treats a journal-publication error as commit-uncertain');
  assert.match(deployment, /COMMIT_ATTEMPTED" -eq 1[\s\S]*journal_load[\s\S]*TX_PHASE" = committed/);
  assert.match(deployment, /REDACTWALL_APPLIED_WARNING=committed_cleanup_pending/);
  assert.match(deployment, /REDACTWALL_COMMITTED_DEGRADED=committed_cleanup_warning_persistence_failed/);
  assert.match(deployment, /publish_applied_state \|\| return 1/);
  assert.match(deployment, /REDACTWALL_DEPLOY_TEST_CRASH_AFTER/,
    'the durable journal exposes a test-only post-fsync crash seam for every phase');

  assert.doesNotMatch(deployment, /echo[^\n]*\$REDACTWALL_LICENSE/);
  assert.doesNotMatch(deployment, /printf 'REDACTWALL_LICENSE=%s/,
    'the signed envelope belongs in its private file, not the environment file');
  assert.match(deployment, /REDACTWALL_LICENSE_PUBLIC_KEY_B64/,
    'the AWS silo receives the public verification trust anchor');
  assert.doesNotMatch(deployment, /license-signing-key|BEGIN PRIVATE KEY|REDACTWALL_LICENSE_PRIVATE_KEY/,
    'the AWS customer silo must never receive offline private signing-key material');
});

test('AWS deployment journal brackets each destructive crash boundary and reconciles before new input', () => {
  const positions = {
    reconcile: deployment.lastIndexOf('                reconcile_existing_transaction'),
    secretRead: deployment.indexOf('SECRET_JSON=$(aws secretsmanager'),
    recoveryPoint: deployment.lastIndexOf('                create_runtime_recovery_point'),
    prepared: deployment.indexOf('journal_write prepared'),
    stopPrevious: deployment.indexOf('docker stop -t 30'),
    previousMoved: deployment.indexOf('journal_write previous_moved'),
    securePrior: deployment.lastIndexOf('move_exact_to_private "$LICENSE_FINAL" "$LICENSE_ROLLBACK"'),
    priorSecured: deployment.indexOf('journal_write prior_secured'),
    publishCandidate: deployment.indexOf('publish_exact_private "$LICENSE_STAGE"'),
    candidatePublished: deployment.indexOf('journal_write candidate_published'),
    createCandidate: deployment.indexOf('candidate_create_output=$(docker create'),
    candidateCreated: deployment.indexOf('journal_write candidate_created'),
    startCandidate: deployment.indexOf('docker start "$CANDIDATE_CONTAINER_ID"'),
    candidateStarted: deployment.indexOf('journal_write candidate_started'),
    candidateReady: deployment.indexOf('journal_write candidate_ready'),
    renameCandidate: deployment.indexOf('docker rename "$CANDIDATE_CONTAINER_ID" redactwall'),
    candidateNamed: deployment.indexOf('journal_write candidate_named'),
    committed: deployment.indexOf('journal_write committed'),
  };
  for (const [label, position] of Object.entries(positions)) {
    assert.ok(position >= 0, `${label} boundary is present`);
  }
  assert.ok(positions.reconcile < positions.secretRead, 'interrupted state is reconciled before reading a new secret version');
  assert.ok(positions.recoveryPoint < positions.prepared && positions.recoveryPoint < positions.stopPrevious,
    'the old writer creates and verifies its authenticated recovery point before it can be stopped');
  assert.ok(positions.prepared < positions.stopPrevious && positions.stopPrevious < positions.previousMoved);
  assert.ok(positions.previousMoved < positions.securePrior && positions.securePrior < positions.priorSecured);
  assert.ok(positions.priorSecured < positions.publishCandidate && positions.publishCandidate < positions.candidatePublished);
  assert.ok(positions.candidatePublished < positions.createCandidate && positions.createCandidate < positions.candidateCreated);
  assert.ok(positions.candidateCreated < positions.startCandidate && positions.startCandidate < positions.candidateStarted);
  assert.ok(positions.candidateStarted < positions.candidateReady && positions.candidateReady < positions.renameCandidate);
  assert.ok(positions.renameCandidate < positions.candidateNamed && positions.candidateNamed < positions.committed);

  const reconcile = deployFunction('reconcile_existing_transaction');
  assert.match(reconcile, /TX_PHASE" = committed[\s\S]*reconcile_committed_cleanup/);
  assert.match(reconcile, /rollback_transaction/);
  const committedCleanup = deployFunction('cleanup_committed_transaction', 'mark_committed_cleanup_pending');
  assert.match(committedCleanup, /container_id_named redactwall[\s\S]*CANDIDATE_CONTAINER_ID/,
    'a committed journal retains prior artifacts unless its exact candidate still owns the canonical name');
  assert.match(committedCleanup, /if ! applied_state_matches_transaction; then publish_applied_state \|\| return 1; fi/,
    'a retry never republishes an already-current applied state and erases its durable warnings');
  assert.doesNotMatch(committedCleanup, /journal_clear/,
    'the committed journal remains authoritative until exact artifact cleanup succeeds');
  assert.match(
    deployment.replace(/\r\n/g, '\n'),
    /reconcile_existing_transaction\s*\n\s*if desired_contract_applied/,
    'committed cleanup reconciliation runs before the same-config fast exit',
  );
});

test('AWS committed cleanup retries before fast exit and preserves its warning until exact success', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const protocol = [
    deployFunction('cleanup_committed_transaction', 'mark_committed_cleanup_pending'),
    deployFunction('mark_committed_cleanup_pending', 'reconcile_committed_cleanup'),
    deployFunction('reconcile_committed_cleanup', 'rollback_transaction'),
    deployFunctionToMarker('reconcile_existing_transaction', '                # END REDACTWALL_LICENSE_DEPLOY_PROTOCOL'),
  ].join('\n').replace(/^ {16}/gm, '');
  const candidate = 'c'.repeat(64);
  const previous = 'p'.repeat(64);
  const tx = 'b'.repeat(32);
  const harness = `
set -euo pipefail
DEPLOY_JOURNAL=/private/journal
APPLIED_STATE=/private/applied
LICENSE_FINAL=/private/license
LICENSE_ROLLBACK=/private/rollback
LICENSE_STAGE=/private/stage
LICENSE_RETIRED=/private/retired
TX_PHASE=committed
TX_ID=${tx}
CANDIDATE_CONTAINER_ID=${candidate}
PREVIOUS_CONTAINER_ID=${previous}
PRIOR_LICENSE_JSON=null
CANDIDATE_LICENSE_JSON='{"sha256":"${'d'.repeat(64)}"}'
IMAGE_URI=image
SECRET_ARN=secret
LICENSE_SECRET_VERSION_ID=version
CONFIG_SHA256=${'e'.repeat(64)}
TEMPLATE_SHA256=${'f'.repeat(64)}
PROTOCOL_SHA256=${'1'.repeat(64)}
TX_IMAGE_URI="$IMAGE_URI"
TX_SECRET_ARN="$SECRET_ARN"
TX_LICENSE_SECRET_VERSION_ID="$LICENSE_SECRET_VERSION_ID"
TX_CONFIG_SHA256="$CONFIG_SHA256"
TX_TEMPLATE_SHA256="$TEMPLATE_SHA256"
TX_PROTOCOL_SHA256="$PROTOCOL_SHA256"
RECOVERY_DIR=/private/recovery
DEPLOY_STATE_DIR=/private
JOURNAL_PRESENT=1
APPLIED_PRESENT=1
WARNING_PRESENT=0
PREVIOUS_PRESENT=1
CLEANUP_RESULT=1
CLEAR_RESULT=0
ASSERT_RESULT=0
COMMITTED_CLEANUP_PENDING=0
EVENTS=
record() { if [ -n "$EVENTS" ]; then EVENTS="$EVENTS,$1"; else EVENTS=$1; fi; }
path_present() {
  if [ "$1" = "$DEPLOY_JOURNAL" ]; then [ "$JOURNAL_PRESENT" -eq 1 ]; return; fi
  if [ "$1" = "$APPLIED_STATE" ]; then [ "$APPLIED_PRESENT" -eq 1 ]; return; fi
  return 1
}
journal_load() { record load; TX_PHASE=committed; }
journal_clear() { record journal-clear; JOURNAL_PRESENT=0; }
container_id_named() { if [ "$1" = redactwall ]; then printf '%s\n' "$CANDIDATE_CONTAINER_ID"; fi; }
docker() {
  command=$1; shift
  if [ "$command" = inspect ]; then
    if [ "\${1:-}" = -f ]; then
      format=$2; id=$3
      if [ "$id" = "$CANDIDATE_CONTAINER_ID" ] && [[ "$format" == *deploy* ]]; then printf '%s\n' "$TX_ID"; return 0; fi
      if [ "$id" = "$CANDIDATE_CONTAINER_ID" ] && [[ "$format" == *Running* ]]; then printf 'true\n'; return 0; fi
      return 1
    fi
    id=$1
    if [ "$id" = "$CANDIDATE_CONTAINER_ID" ]; then return 0; fi
    if [ "$id" = "$PREVIOUS_CONTAINER_ID" ] && [ "$PREVIOUS_PRESENT" -eq 1 ]; then return 0; fi
    return 1
  fi
  if [ "$command" = rm ]; then
    record cleanup-attempt
    if [ "$CLEANUP_RESULT" -ne 0 ]; then return "$CLEANUP_RESULT"; fi
    PREVIOUS_PRESENT=0
    return 0
  fi
  return 2
}
applied_state_matches_transaction() { return 0; }
publish_applied_state() { record publish; }
applied_warning_present() { [ "$WARNING_PRESENT" -eq 1 ]; }
record_applied_warning() { record warning-add; WARNING_PRESENT=1; }
clear_applied_warning() {
  record warning-clear
  if [ "$CLEAR_RESULT" -ne 0 ]; then return "$CLEAR_RESULT"; fi
  WARNING_PRESENT=0
}
remove_exact_private_artifact() { return 2; }
rollback_transaction() { return 2; }
${protocol}
assert_current() { record assert; return "$ASSERT_RESULT"; }
run_apply() {
  COMMITTED_CLEANUP_PENDING=0
  status=0
  reconcile_existing_transaction || status=$?
  if [ "$status" -ne 0 ]; then return "$status"; fi
  if assert_current; then return 0; fi
  if [ "$COMMITTED_CLEANUP_PENDING" -eq 1 ]; then return 1; fi
  record mutation
  return 2
}
run=1
for scenario in first repeated success changed; do
  EVENTS=
  if [ "$scenario" = success ]; then CLEANUP_RESULT=0; fi
  if [ "$scenario" = changed ]; then
    JOURNAL_PRESENT=1; WARNING_PRESENT=1; PREVIOUS_PRESENT=1; CLEANUP_RESULT=1; ASSERT_RESULT=1
  fi
  status=0
  run_apply || status=$?
  printf 'RESULT=%s|%s|%s|%s|%s|%s\n' "$scenario" "$status" "$JOURNAL_PRESENT" "$WARNING_PRESENT" "$COMMITTED_CLEANUP_PENDING" "$EVENTS"
  run=$((run + 1))
done
`;
  const result = childProcess.spawnSync(bash, ['-s'], { input: harness, encoding: 'utf8' });
  assert.strictEqual(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /RESULT=first\|0\|1\|1\|1\|load,cleanup-attempt,warning-add,assert/);
  assert.match(result.stdout, /RESULT=repeated\|0\|1\|1\|1\|load,cleanup-attempt,warning-add,assert/);
  assert.match(result.stdout, /RESULT=success\|0\|0\|0\|0\|load,cleanup-attempt,journal-clear,warning-clear,assert/);
  assert.match(result.stdout, /RESULT=changed\|1\|1\|1\|1\|load,cleanup-attempt,warning-add,assert/);
  assert.strictEqual((result.stdout.match(/^REDACTWALL_APPLIED_WARNING=committed_cleanup_pending$/gm) || []).length, 3,
    'each failed cleanup retry emits one structured warning while eventual success emits none');
  assert.doesNotMatch(result.stdout, /publish|mutation/,
    'same-config retries preserve the applied warning and changed config cannot mutate while cleanup is pending');
});

test('AWS journal loading cannot replace immutable desired attestation or the next transaction contract', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const jqProbe = childProcess.spawnSync('jq', ['--version'], { encoding: 'utf8' });
  if (jqProbe.error || jqProbe.status !== 0) return t.skip('jq is unavailable');
  const old = {
    image: `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`,
    secret: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/old',
    version: '11111111-1111-1111-1111-111111111111', config: 'b'.repeat(64),
    template: 'c'.repeat(64), protocol: 'd'.repeat(64),
  };
  const next = {
    image: `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'e'.repeat(64)}`,
    secret: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/new',
    version: '22222222-2222-2222-2222-222222222222', config: 'f'.repeat(64),
    template: '1'.repeat(64), protocol: '2'.repeat(64),
  };
  const snapshot = { dev: '1', ino: '2', nlink: '1', size: '3', uid: '1000', gid: '1000', mode: '400', sha256: '3'.repeat(64) };
  const journal = JSON.stringify({
    version: 1, tx: '4'.repeat(32), phase: 'committed', imageUri: old.image, secretArn: old.secret,
    secretVersionId: old.version, desiredConfigSha256: old.config, templateSha256: old.template,
    protocolSha256: old.protocol, previousContainerId: '', previousImageUri: '', previousContainerRunning: false,
    candidateContainerId: '5'.repeat(64), priorLicense: null, candidateLicense: snapshot,
    licenseChanged: false, recoveryBackupName: '', recoveryManifestName: '',
  });
  const protocol = [
    deployFunction('desired_contract_applied', 'reset_transaction_contract_to_desired'),
    deployFunction('reset_transaction_contract_to_desired', 'artifact_json'),
    deployFunction('transaction_paths', 'journal_write'),
    deployFunction('valid_snapshot_json', 'journal_load'),
    deployFunction('journal_load', 'journal_clear'),
    deployFunctionToMarker('reconcile_existing_transaction', '                # END REDACTWALL_LICENSE_DEPLOY_PROTOCOL'),
  ].join('\n').replace(/^ {16}/gm, '');

  function scenario({ name, desired, cleanupFails }) {
    const harness = `
set -euo pipefail
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
DEPLOY_JOURNAL="$ROOT/journal"
DEPLOY_STATE_DIR="$ROOT"
RECOVERY_PARENT="$ROOT/recovery"
APPLIED_STATE="$ROOT/applied"
ASSERT_APPLIED_COMMAND="$ROOT/assert-applied"
CAPTURE_PATH="$ROOT/captured"
printf '%s' '${journal}' > "$DEPLOY_JOURNAL"
cat > "$ASSERT_APPLIED_COMMAND" <<'ASSERT'
#!/bin/bash
printf '%s' "$*" > "$CAPTURE_PATH"
[ "$*" = "$APPLIED_ARGS" ]
ASSERT
chmod 700 "$ASSERT_APPLIED_COMMAND"
export CAPTURE_PATH
APPLIED_ARGS='--image-uri ${old.image} --secret-version-id ${old.version} --config-sha256 ${old.config} --template-sha256 ${old.template} --protocol-sha256 ${old.protocol}'
export APPLIED_ARGS
DEPLOY_DEVICE=1
DESIRED_IMAGE_URI='${desired.image}'
DESIRED_SECRET_ARN='${desired.secret}'
DESIRED_LICENSE_SECRET_VERSION_ID='${desired.version}'
DESIRED_CONFIG_SHA256='${desired.config}'
DESIRED_TEMPLATE_SHA256='${desired.template}'
DESIRED_PROTOCOL_SHA256='${desired.protocol}'
IMAGE_URI="$DESIRED_IMAGE_URI"
SECRET_ARN="$DESIRED_SECRET_ARN"
LICENSE_SECRET_VERSION_ID="$DESIRED_LICENSE_SECRET_VERSION_ID"
CONFIG_SHA256="$DESIRED_CONFIG_SHA256"
TEMPLATE_SHA256="$DESIRED_TEMPLATE_SHA256"
PROTOCOL_SHA256="$DESIRED_PROTOCOL_SHA256"
TX_IMAGE_URI="$DESIRED_IMAGE_URI"
TX_SECRET_ARN="$DESIRED_SECRET_ARN"
TX_LICENSE_SECRET_VERSION_ID="$DESIRED_LICENSE_SECRET_VERSION_ID"
TX_CONFIG_SHA256="$DESIRED_CONFIG_SHA256"
TX_TEMPLATE_SHA256="$DESIRED_TEMPLATE_SHA256"
TX_PROTOCOL_SHA256="$DESIRED_PROTOCOL_SHA256"
COMMITTED_CLEANUP_PENDING=0
DEPLOY_COMMITTED=0
COMMIT_ATTEMPTED=0
ROLLBACK_RECOVERED=0
artifact_json() { printf '{"dev":"1"}'; }
artifact_matches() { return 0; }
path_present() { [ -e "$1" ]; }
applied_warning_present() { return 1; }
clear_applied_warning() { return 0; }
rollback_transaction() { return 2; }
reconcile_committed_cleanup() {
  if [ '${cleanupFails ? '1' : '0'}' -eq 1 ]; then
    COMMITTED_CLEANUP_PENDING=1
    printf 'REDACTWALL_APPLIED_WARNING=committed_cleanup_pending\n'
  else
    rm -f "$DEPLOY_JOURNAL"
    COMMITTED_CLEANUP_PENDING=0
  fi
}
${protocol}
OUTCOME=NEW_TRANSACTION
reconcile_existing_transaction
if desired_contract_applied; then
  OUTCOME=FAST_EXIT
elif [ "$COMMITTED_CLEANUP_PENDING" -eq 1 ]; then
  OUTCOME=BLOCKED
else
  reset_transaction_contract_to_desired
fi
printf 'CASE=${name}|OUTCOME=%s|DESIRED=%s|TX=%s|ATTESTED=%s|NEXT=%s|CANDIDATE=%s\n' \
  "$OUTCOME" "$DESIRED_TEMPLATE_SHA256/$DESIRED_PROTOCOL_SHA256" \
  "$TX_TEMPLATE_SHA256/$TX_PROTOCOL_SHA256" "$(cat "$CAPTURE_PATH")" \
  "$TEMPLATE_SHA256/$PROTOCOL_SHA256" "$CANDIDATE_CONTAINER_ID"
`;
    const result = childProcess.spawnSync(bash, ['-s'], { input: harness, encoding: 'utf8' });
    assert.strictEqual(result.status, 0, result.stderr || result.stdout);
    return result.stdout;
  }

  const changedBlocked = scenario({ name: 'changed-pending', desired: next, cleanupFails: true });
  assert.match(changedBlocked, new RegExp(`CASE=changed-pending\\|OUTCOME=BLOCKED\\|DESIRED=${next.template}/${next.protocol}\\|TX=${old.template}/${old.protocol}`));
  assert.match(changedBlocked, new RegExp(`ATTESTED=--image-uri ${next.image}[\\s\\S]*--template-sha256 ${next.template} --protocol-sha256 ${next.protocol}`));
  assert.doesNotMatch(changedBlocked, /FAST_EXIT|NEW_TRANSACTION/);

  const samePending = scenario({ name: 'same-pending', desired: old, cleanupFails: true });
  assert.match(samePending, /REDACTWALL_APPLIED_WARNING=committed_cleanup_pending/);
  assert.match(samePending, /CASE=same-pending\|OUTCOME=FAST_EXIT/);

  const changedClean = scenario({ name: 'changed-clean', desired: next, cleanupFails: false });
  assert.strictEqual(changedClean.trimEnd(), [
    'CASE=changed-clean', 'OUTCOME=NEW_TRANSACTION',
    `DESIRED=${next.template}/${next.protocol}`, `TX=${next.template}/${next.protocol}`,
    `ATTESTED=--image-uri ${next.image} --secret-version-id ${next.version} --config-sha256 ${next.config} --template-sha256 ${next.template} --protocol-sha256 ${next.protocol}`,
    `NEXT=${next.template}/${next.protocol}`, 'CANDIDATE=',
  ].join('|'));
});

test('AWS changed-config cleanup success resets stale journal fields before a prepared-phase crash', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const jqProbe = childProcess.spawnSync('jq', ['--version'], { encoding: 'utf8' });
  if (jqProbe.error || jqProbe.status !== 0) return t.skip('jq is unavailable');
  const rootDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'redactwall-aws-contract-reset-'));
  t.after(() => fs.rmSync(rootDir, { recursive: true, force: true }));
  const shellRoot = rootDir.replace(/\\/g, '/');
  const image = `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'6'.repeat(64)}`;
  const snapshot = `{"dev":"1","ino":"2","nlink":"1","size":"3","uid":"1000","gid":"1000","mode":"400","sha256":"${'7'.repeat(64)}"}`;
  const resetProtocol = [
    deployFunction('reset_transaction_contract_to_desired', 'artifact_json'),
    deployFunction('transaction_paths', 'journal_write'),
    deployFunction('journal_write', 'valid_snapshot_json'),
  ].join('\n').replace(/^ {16}/gm, '');
  const createHarness = `
set -euo pipefail
DEPLOY_STATE_DIR='${shellRoot}'
DEPLOY_JOURNAL="$DEPLOY_STATE_DIR/license-deploy-journal.json"
RECOVERY_PARENT="$DEPLOY_STATE_DIR/recovery"
DESIRED_IMAGE_URI='${image}'
DESIRED_SECRET_ARN='arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/new'
DESIRED_LICENSE_SECRET_VERSION_ID='66666666-6666-6666-6666-666666666666'
DESIRED_CONFIG_SHA256='${'8'.repeat(64)}'
DESIRED_TEMPLATE_SHA256='${'9'.repeat(64)}'
DESIRED_PROTOCOL_SHA256='${'a'.repeat(64)}'
TX_ID='${'b'.repeat(32)}'
TX_PHASE=committed
PREVIOUS_CONTAINER_ID='${'c'.repeat(64)}'
PREVIOUS_CONTAINER_RUNNING=true
PREVIOUS_IMAGE_URI='${image}'
CANDIDATE_CONTAINER_ID='${'d'.repeat(64)}'
PRIOR_LICENSE_JSON=${snapshot}
CANDIDATE_LICENSE_JSON=${snapshot}
LICENSE_CHANGED=true
RECOVERY_BACKUP_NAME=old.db
RECOVERY_MANIFEST_NAME=old.manifest.json
DEPLOY_COMMITTED=1
COMMIT_ATTEMPTED=1
ROLLBACK_RECOVERED=1
COMMITTED_CLEANUP_PENDING=0
${resetProtocol}
reset_transaction_contract_to_desired
[ -z "$CANDIDATE_CONTAINER_ID" ]
TX_ID='${'e'.repeat(32)}'
transaction_paths
CANDIDATE_LICENSE_JSON='${snapshot}'
export REDACTWALL_DEPLOY_TEST_CRASH_AFTER=prepared
journal_write prepared
`;
  const crashed = childProcess.spawnSync(bash, ['-s'], { input: createHarness, encoding: 'utf8' });
  assert.notStrictEqual(crashed.status, 0, 'prepared-phase crash seam terminates the writer');
  const journalPath = path.join(rootDir, 'license-deploy-journal.json');
  assert.ok(fs.existsSync(journalPath));
  const journal = JSON.parse(fs.readFileSync(journalPath, 'utf8'));
  assert.strictEqual(journal.phase, 'prepared');
  assert.strictEqual(journal.candidateContainerId, '');
  assert.strictEqual(journal.templateSha256, '9'.repeat(64));
  assert.strictEqual(journal.protocolSha256, 'a'.repeat(64));

  const recoveryProtocol = [
    deployFunction('transaction_paths', 'journal_write'),
    deployFunction('valid_snapshot_json', 'journal_load'),
    deployFunction('journal_load', 'journal_clear'),
    deployFunctionToMarker('reconcile_existing_transaction', '                # END REDACTWALL_LICENSE_DEPLOY_PROTOCOL'),
  ].join('\n').replace(/^ {16}/gm, '');
  const recoverHarness = `
set -euo pipefail
DEPLOY_STATE_DIR='${shellRoot}'
DEPLOY_JOURNAL="$DEPLOY_STATE_DIR/license-deploy-journal.json"
RECOVERY_PARENT="$DEPLOY_STATE_DIR/recovery"
APPLIED_STATE="$DEPLOY_STATE_DIR/applied"
DEPLOY_DEVICE=1
ROLLBACK_RECOVERED=0
COMMITTED_CLEANUP_PENDING=0
ROLLBACK_CALLED=0
artifact_json() { printf '{"dev":"1"}'; }
artifact_matches() { return 0; }
path_present() { [ -e "$1" ]; }
rollback_transaction() {
  [ -z "$CANDIDATE_CONTAINER_ID" ] || return 1
  ROLLBACK_CALLED=1
  rm -f "$DEPLOY_JOURNAL"
}
reconcile_committed_cleanup() { return 2; }
applied_warning_present() { return 1; }
clear_applied_warning() { return 1; }
${recoveryProtocol}
reconcile_existing_transaction
printf 'ROLLBACK=%s|CANDIDATE=%s|TEMPLATE=%s|PROTOCOL=%s' \
  "$ROLLBACK_CALLED" "$CANDIDATE_CONTAINER_ID" "$TX_TEMPLATE_SHA256" "$TX_PROTOCOL_SHA256"
`;
  const recovered = childProcess.spawnSync(bash, ['-s'], { input: recoverHarness, encoding: 'utf8' });
  assert.strictEqual(recovered.status, 0, recovered.stderr || recovered.stdout);
  assert.strictEqual(recovered.stdout, `ROLLBACK=1|CANDIDATE=|TEMPLATE=${'9'.repeat(64)}|PROTOCOL=${'a'.repeat(64)}`);
});

test('AWS executable recovery state machine stops before license rollback when candidate removal is uncertain', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const protocol = [
    deployFunction('rollback_transaction', 'reconcile_existing_transaction'),
    deployFunctionToMarker('reconcile_existing_transaction', '                # END REDACTWALL_LICENSE_DEPLOY_PROTOCOL'),
  ].join('\n').replace(/^ {16}/gm, '');

  function scenario({ mode = 'reconcile', phase = 'candidate_started', remove = 0, cleanup = 0, load = 0 }) {
    const harness = `
set -euo pipefail
EVENTS=""
record() { if [ -n "$EVENTS" ]; then EVENTS="$EVENTS,$1"; else EVENTS=$1; fi; }
DEPLOY_JOURNAL=/private/journal
TX_PHASE=${phase}
SCENARIO_PHASE=${phase}
REMOVE_RESULT=${remove}
CLEANUP_RESULT=${cleanup}
LOAD_RESULT=${load}
ROLLBACK_RECOVERED=0
path_present() { return 0; }
journal_load() { record load; if [ "$LOAD_RESULT" -ne 0 ]; then return "$LOAD_RESULT"; fi; TX_PHASE=$SCENARIO_PHASE; }
cleanup_committed_transaction() { record cleanup; return "$CLEANUP_RESULT"; }
reconcile_committed_cleanup() { record cleanup; return "$CLEANUP_RESULT"; }
remove_candidate_confirmed() { record candidate; return "$REMOVE_RESULT"; }
restore_license_transaction() { record license; }
restore_runtime_recovery_point() { record runtime; }
restore_previous_container() { record container; }
cleanup_rollback_artifacts() { record cleanup; return "$CLEANUP_RESULT"; }
journal_clear() { record clear; }
${protocol}
status=0
if [ "${mode}" = rollback ]; then
  rollback_transaction || status=$?
else
  reconcile_existing_transaction || status=$?
fi
printf '%s|%s' "$status" "$EVENTS"
`;
    const result = childProcess.spawnSync(bash, ['-s'], { input: harness, encoding: 'utf8' });
    assert.strictEqual(result.status, 0, result.stderr || result.stdout);
    return result.stdout;
  }

  assert.strictEqual(
    scenario({ mode: 'rollback', remove: 1 }),
    '1|candidate',
    'an unconfirmed candidate removal performs no license, container, or journal mutation',
  );
  assert.strictEqual(
    scenario({ mode: 'rollback' }),
    '0|candidate,license,runtime,container,cleanup,clear',
    'a confirmed rollback restores license and runtime evidence before the prior container and clears its journal last',
  );
  assert.strictEqual(
    scenario({ mode: 'rollback', cleanup: 1 }),
    '1|candidate,license,runtime,container,cleanup',
    'cleanup failure retains the journal only after the prior deployment is restored',
  );
  for (const phase of [
    'prepared', 'previous_moved', 'prior_secured', 'candidate_published', 'license_unchanged',
    'candidate_created', 'candidate_started', 'candidate_ready', 'candidate_named',
  ]) {
    assert.strictEqual(
      scenario({ phase }),
      '0|load,candidate,license,runtime,container,cleanup,clear',
      `restart from ${phase} performs the exact pre-commit rollback protocol`,
    );
  }
  assert.strictEqual(scenario({ phase: 'committed' }), '0|load,cleanup');
  assert.strictEqual(
    scenario({ phase: 'committed', cleanup: 1 }),
    '1|load,cleanup',
    'a later run preserves a committed journal when exact cleanup cannot finish',
  );
  assert.strictEqual(
    scenario({ load: 1 }),
    '1|load',
    'an invalid private journal fails closed before any recovery artifact changes',
  );
});

test('AWS executable candidate cleanup requires Docker to prove the exact labeled container is absent', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const candidateFunctions = [
    deployFunction('discover_candidate_id', 'remove_candidate_confirmed'),
    deployFunction('remove_candidate_confirmed', 'quarantine_candidate_license'),
  ].join('\n').replace(/^ {16}/gm, '');
  const id = 'a'.repeat(64);
  const tx = 'b'.repeat(32);

  function scenario({ rmStatus = 0, sticky = 0 }) {
    const harness = `
set -euo pipefail
TX_ID=${tx}
CANDIDATE_CONTAINER_ID=${id}
EXISTS=1
RM_STATUS=${rmStatus}
STICKY=${sticky}
docker() {
  command=$1
  shift
  case "$command" in
    ps) if [ "$EXISTS" -eq 1 ]; then printf '%s\\n' "$CANDIDATE_CONTAINER_ID"; fi ;;
    inspect)
      if [ "$EXISTS" -ne 1 ]; then return 1; fi
      if [ "$1" = -f ]; then printf '%s\\n' "$TX_ID"; fi
      ;;
    rm)
      if [ "$RM_STATUS" -ne 0 ]; then return "$RM_STATUS"; fi
      if [ "$STICKY" -ne 1 ]; then EXISTS=0; fi
      printf '%s\\n' "$CANDIDATE_CONTAINER_ID"
      ;;
    *) return 2 ;;
  esac
}
${candidateFunctions}
status=0
remove_candidate_confirmed || status=$?
printf '%s|%s' "$status" "$EXISTS"
`;
    const result = childProcess.spawnSync(bash, ['-s'], { input: harness, encoding: 'utf8' });
    assert.strictEqual(result.status, 0, result.stderr || result.stdout);
    return result.stdout;
  }

  assert.strictEqual(scenario({ rmStatus: 1 }), '1|1', 'a Docker removal error leaves the candidate and fails rollback');
  assert.strictEqual(scenario({ sticky: 1 }), '1|1', 'a nominal remove that leaves the exact ID visible fails rollback');
  assert.strictEqual(scenario({}), '0|0', 'rollback proceeds only after Docker proves the labeled candidate is absent');
});

test('AWS customer-silo requires TLS and never exposes a login-breaking HTTP-only stack', () => {
  const certificateParameter = template.match(/  CertificateArn:\r?\n(?<body>[\s\S]*?)  InstanceType:/);
  assert.ok(certificateParameter, 'CertificateArn parameter block is present');
  assert.match(certificateParameter.groups.body, /MinLength: 1/);
  assert.doesNotMatch(certificateParameter.groups.body, /Default:\s*''/);
  const hostnameParameter = template.match(/  PublicHostname:\r?\n(?<body>[\s\S]*?)  InstanceType:/);
  assert.ok(hostnameParameter, 'PublicHostname parameter block is present');
  assert.match(hostnameParameter.groups.body, /MinLength: 1/);
  assert.match(hostnameParameter.groups.body, /AllowedPattern:/);
  assert.doesNotMatch(template, /NoCertificate|HttpForwardListener/);
  assert.match(template, /HttpRedirectListener:[\s\S]*Protocol: HTTPS/);
  assert.match(template, /HttpsListener:[\s\S]*CertificateArn: !Ref CertificateArn/);
  assert.match(template, /HttpsListener:[\s\S]*SslPolicy: ELBSecurityPolicy-TLS13-1-2-Res-2021-06/);
  assert.match(template, /Url:[\s\S]*Value: !Sub 'https:\/\/\$\{PublicHostname\}'/);
  assert.match(template, /LoadBalancerDnsName:[\s\S]*Value: !GetAtt LoadBalancer\.DNSName/);
});

test('AWS customer-silo template bootstraps recurring examiner evidence packs', () => {
  assert.match(template, /docker cp redactwall:\/app\/scripts\/run-evidence-pack\.sh \/usr\/local\/bin\/redactwall-run-evidence-pack/);
  assert.match(template, /docker cp redactwall:\/app\/config\/evidence-schedule\.example\.json \/var\/lib\/redactwall\/runtime\/evidence-schedule\.json/);
  assert.match(template, /REDACTWALL_EVIDENCE_MODE='docker'/);
  assert.match(template, /REDACTWALL_EVIDENCE_CONFIG='\/data\/evidence-schedule\.json'/);
  assert.match(template, /REDACTWALL_EVIDENCE_CONTAINER='redactwall'/);
  assert.match(template, /ExecStart=\/usr\/local\/bin\/redactwall-run-evidence-pack/);
  assert.match(template, /OnCalendar=quarterly/);
  assert.match(template, /Persistent=true/);
  assert.match(template, /systemctl enable --now redactwall-evidence-pack\.timer/);
  assert.match(template, /REDACTWALL_COMMITTED_DEGRADED=evidence_scheduler_warning_persistence_failed/);
  assert.match(template, /record_applied_warning evidence_scheduler_setup_failed/);
  const unitEnv = template.match(/cat > \/etc\/redactwall\/evidence-pack\.env <<'EOF'([\s\S]*?)EOF/);
  assert.ok(unitEnv);
  assert.doesNotMatch(unitEnv[1], /REDACTWALL_SECRET|REDACTWALL_DATA_KEY|INGEST_API_KEY|ADMIN_PASSWORD|AUDITOR_PASSWORD/);
});

test('AWS SaaS deployment docs include launch and validation steps', () => {
  assert.match(docs, /customer-silo model/);
  assert.match(docs, /aws ecr create-repository/);
  assert.match(docs, /npm run silo:deploy/);
  assert.match(docs, /npm run --silent silo:artifacts:init/);
  assert.match(docs, /--artifact-bucket "\$ARTIFACT_BUCKET"/);
  assert.match(docs, /--data-stack-name redactwall-cu-acme-data/);
  assert.match(docs, /--ami-id "\$AMI_ID"/);
  assert.doesNotMatch(docs, /--template-body file:\/\/infra\/aws\/customer-silo\.yml/);
  assert.match(docs, /silo:maintenance -- --mode replace-instance/);
  assert.match(docs, /silo:maintenance -- --mode restore-volume/);
  assert.match(docs, /customer-data-volume\.yml/);
  assert.match(docs, /--data-volume-id "\$DATA_VOLUME_ID"/);
  assert.match(docs, /\/api\/billing\/seats/);
  assert.match(docs, /Do not run this app on Fargate with SQLite over EFS/);
  assert.match(docs, /redactwall-evidence-pack\.timer/);
  assert.match(docs, /\/var\/lib\/redactwall\/runtime\/evidence-schedule\.json/);
  assert.match(docs, /CertificateArn.*required/is);
  assert.match(docs, /PublicHostname/);
  assert.match(docs, /hostname to `redactwall`/);
  assert.match(docs, /cfn-hup/);
  assert.match(docs, /failed\s+candidate restores the exact runtime evidence and identity-proven prior license/i);
  assert.match(docs, /signed\s+connected-fallback license[\s\S]*REDACTWALL_LICENSE/i);
  assert.match(docs, /--deployment-id dep_[a-f0-9]{32}/);
  assert.doesNotMatch(docs, /--license-mode|--seat-limit|REDACTWALL_LICENSE_SERVER_TOKEN\":/);
  assert.match(docs, /Never copy the private\s+signing key/i);
  assert.match(docs, /device, inode, link count, size, and SHA-256/i);
  assert.match(docs, /LicenseSecretVersionId/);
  assert.match(docs, /Do not install a renewal through the customer console/i);
  assert.match(docs, /pre-`DeploymentId` AWS stack/);
  assert.match(docs, /aws-legacy-connected-migrate\.js plan/);
  assert.match(docs, /aws-legacy-connected-migrate\.js freeze/);
  assert.match(docs, /aws-legacy-connected-migrate\.js cutover/);
  assert.match(docs, /aws-legacy-connected-migrate\.js cleanup-failed-candidate/);
  assert.match(docs, /aws-legacy-connected-migrate\.js commit/);
  assert.match(docs, /REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256/);
  assert.match(docs, /jq -n[\s\S]*--deployment-id[\s\S]*deploy-args\.json/);
  assert.match(docs, /does not claim that it can cryptographically disable a manually[\s\S]*obsolete image/i);
  assert.match(docs, /Create the exact customer and deployment enrollment in Owner/);
  assert.match(docs, /authenticated evidence[\s\S]*root-owned[\s\S]*retained storage/i);
  assert.match(docs, /nonzero monotonic registry generation[\s\S]*delivered ACK[\s\S]*applied ACK/i);
  assert.match(docs, /fsynced maintenance latch[\s\S]*same lock[\s\S]*`cfn-hup`/i);
  assert.match(connectedDocs, /AWS stacks created before `DeploymentId`/);
  assert.match(connectedDocs, /This is reprovisioning, not an in-place update/);
  assert.match(connectedDocs, /cleanup-failed-candidate/);
  assert.match(connectedDocs, /Deregister the only writer[\s\S]*stop that exact writer[\s\S]*final backup/i);
  assert.match(connectedDocs, /not a claim that[\s\S]*cryptographically disable a manually reconstructed obsolete image/i);
  assert.match(connectedDocs, /Downtime begins when the legacy writer is stopped/);
  assert.match(connectedDocs, /nonzero monotonic registry generation[\s\S]*delivered then applied acknowledgement acceptance/i);
  assert.match(docs, /server_host_permission=false/);
  assert.doesNotMatch(docs, /do not pass `CertificateArn`/i);
  assert.match(technicianDocs, /--public-hostname \$PublicHostname/);
  assert.match(technicianDocs, /OutputKey=='LoadBalancerDnsName'/);
  assert.match(technicianDocs, /OutputKey=='LogGroupName'/);
  assert.match(technicianDocs, /aws logs tail \$LogGroupName/);
  assert.match(technicianDocs, /REDACTWALL_LICENSE = \$LicenseText/);
  assert.match(technicianDocs, /--secret-version-id \$LicenseSecretVersionId/);
  assert.match(technicianDocs, /--instance-availability-zone \$InstanceAvailabilityZone/);
  assert.match(technicianDocs, /--data-volume-id \$DataVolumeId/);
  assert.match(technicianDocs, /--data-stack-name \$DataStackName/);
  assert.match(technicianDocs, /--artifact-bucket \$ArtifactBucket/);
  assert.match(technicianDocs, /--ami-id \$AmiId/);
  assert.match(technicianDocs, /--deployment-id \$DeploymentId/);
  assert.doesNotMatch(technicianDocs, /--license-mode|--seat-limit|REDACTWALL_LICENSE_SERVER_TOKEN\s*=/);
  assert.doesNotMatch(technicianDocs, /--template-body file:\/\/infra\/aws\/customer-silo\.yml/);
  assert.match(technicianDocs, /license:trust-check/);
  assert.match(technicianDocs, /applied-state|apply-and-attest/i);
  assert.match(technicianDocs, /Owner-signed connected entitlements are the plan, seat, feature, pause, and\s+revoke authority/i);
  assert.match(technicianDocs, /Never add the private signing key/i);
  assert.match(technicianDocs, /Licensing tab.*`active`/is);
  assert.doesNotMatch(technicianDocs, /aws logs tail "\/redactwall\/\$TenantId"/);
  assert.match(launchDocs, /`LogGroupName` stack output/);
  assert.doesNotMatch(launchDocs, /\/redactwall\/<tenant>/);
  assert.doesNotMatch(launchDocs, /exposes plain HTTP/i);
});
