'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const template = fs.readFileSync(path.join(root, 'infra', 'aws', 'customer-silo.yml'), 'utf8');
const docs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'AWS_SAAS_DEPLOYMENT.md'), 'utf8');
const technicianDocs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'TECHNICIAN_DEPLOYMENT_GUIDE.md'), 'utf8');
const launchDocs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'PRODUCTION_LAUNCH_GUIDE.md'), 'utf8');

function parameterAllowedPattern(name) {
  const block = template.match(new RegExp(`  ${name}:\\r?\\n(?<body>[\\s\\S]*?)(?=\\n  [A-Za-z][A-Za-z0-9]+:)`));
  assert.ok(block, `${name} parameter block is present`);
  const pattern = block.groups.body.match(/AllowedPattern: '([^']+)'/);
  assert.ok(pattern, `${name} has an AllowedPattern`);
  return new RegExp(pattern[1]);
}

test('AWS customer-silo template enforces tenant and seat parameters', () => {
  assert.match(template, /TenantId:/);
  assert.match(template, /SeatLimit:/);
  assert.match(template, /REDACTWALL_SAAS_MODE=true/);
  assert.match(template, /REDACTWALL_TENANT_ID=\$\{TenantId\}/);
  assert.match(template, /REDACTWALL_SEAT_LIMIT=\$\{SeatLimit\}/);
  assert.match(template, /REDACTWALL_REQUIRE_TENANT_CONTEXT=true/);
  assert.match(template, /REDACTWALL_REQUIRE_USER_IDENTITY=true/);
  assert.match(template, /TRUST_PROXY=1/, 'ALB client IPs must not collapse into one login lockout bucket');
});

test('AWS customer-silo template uses local EBS-backed data and Secrets Manager', () => {
  assert.match(template, /VolumeType: gp3/);
  assert.match(template, /Encrypted: true/);
  assert.match(template, /-v \/var\/lib\/redactwall:\/data/);
  assert.match(template, /REDACTWALL_POLICY_PATH=\/data\/policy\.json/);
  assert.match(template, /REDACTWALL_CUSTOM_DETECTORS_PATH=\/data\/custom-detectors\.json/);
  assert.match(template, /secretsmanager:GetSecretValue/);
  assert.match(template, /HealthCheckPath: \/readyz/);
  assert.match(template, /install -d -m 700 -o 1000 -g 1000 \/var\/lib\/redactwall/,
    'the non-root image must own its private persistent data directory before bind mount');
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
  const metadata = template.match(/    Metadata:\r?\n(?<body>[\s\S]*?)\n    CreationPolicy:/);
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

test('AWS ImageUri updates are applied by cfn-hup with readiness rollback', () => {
  const metadata = template.match(/    Metadata:\r?\n(?<body>[\s\S]*?)\n    CreationPolicy:/);
  const userData = template.match(/Fn::Base64: !Sub \|(?<body>[\s\S]*?)\n  LoadBalancer:/);
  assert.ok(metadata && userData);
  assert.match(metadata.groups.body, /AWS::CloudFormation::Init/);
  assert.match(metadata.groups.body, /docker pull '\$\{ImageUri\}'/);
  assert.match(metadata.groups.body, /docker rename redactwall redactwall-previous/);
  assert.match(metadata.groups.body, /rollback_deploy\(\)[\s\S]*docker rename redactwall-previous redactwall/);
  assert.match(userData.groups.body, /triggers=post\.update/);
  assert.match(userData.groups.body, /path=Resources\.AppInstance\.Metadata\.AWS::CloudFormation::Init/);
  assert.match(userData.groups.body, /action=\/opt\/aws\/bin\/cfn-init[^\n]+--resource AppInstance/);
  assert.match(userData.groups.body, /systemctl enable --now cfn-hup\.service/);
  assert.doesNotMatch(userData.groups.body, /\$\{ImageUri\}/, 'image changes stay in metadata and do not rely on one-shot user data');
});

test('AWS shell-interpolated parameters reject quote breaks and command metacharacters', () => {
  const imagePattern = parameterAllowedPattern('ImageUri');
  const secretPattern = parameterAllowedPattern('SecretArn');
  assert.ok(imagePattern.test(`123456789012.dkr.ecr.us-gov-west-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`));
  assert.strictEqual(
    imagePattern.test('123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall/app:release-2026.07'),
    false,
    'mutable tags cannot select host-root bootstrap code',
  );
  assert.ok(secretPattern.test('arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-acme-Ab12_3'));

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
  }
});

test('AWS secret values cannot inject additional env-file records', () => {
  assert.match(template, /secret\(\) \{[\s\S]*jq -er --arg key/);
  assert.match(template, /test\("\[\\u0000\\r\\n\]"\)/);
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
  assert.match(template, /docker cp redactwall:\/app\/config\/evidence-schedule\.example\.json \/var\/lib\/redactwall\/evidence-schedule\.json/);
  assert.match(template, /REDACTWALL_EVIDENCE_MODE='docker'/);
  assert.match(template, /REDACTWALL_EVIDENCE_CONFIG='\/data\/evidence-schedule\.json'/);
  assert.match(template, /REDACTWALL_EVIDENCE_CONTAINER='redactwall'/);
  assert.match(template, /ExecStart=\/usr\/local\/bin\/redactwall-run-evidence-pack/);
  assert.match(template, /OnCalendar=quarterly/);
  assert.match(template, /Persistent=true/);
  assert.match(template, /systemctl enable --now redactwall-evidence-pack\.timer/);
  const unitEnv = template.match(/cat > \/etc\/redactwall\/evidence-pack\.env <<'EOF'([\s\S]*?)EOF/);
  assert.ok(unitEnv);
  assert.doesNotMatch(unitEnv[1], /REDACTWALL_SECRET|REDACTWALL_DATA_KEY|INGEST_API_KEY|ADMIN_PASSWORD|AUDITOR_PASSWORD/);
});

test('AWS SaaS deployment docs include launch and validation steps', () => {
  assert.match(docs, /customer-silo model/);
  assert.match(docs, /aws ecr create-repository/);
  assert.match(docs, /aws cloudformation deploy/);
  assert.match(docs, /\/api\/billing\/seats/);
  assert.match(docs, /Do not run this app on Fargate with SQLite over EFS/);
  assert.match(docs, /redactwall-evidence-pack\.timer/);
  assert.match(docs, /\/var\/lib\/redactwall\/evidence-schedule\.json/);
  assert.match(docs, /CertificateArn.*required/is);
  assert.match(docs, /PublicHostname/);
  assert.match(docs, /hostname to `redactwall`/);
  assert.match(docs, /cfn-hup/);
  assert.match(docs, /previous container is restored/i);
  assert.match(docs, /server_host_permission=false/);
  assert.doesNotMatch(docs, /do not pass `CertificateArn`/i);
  assert.match(technicianDocs, /PublicHostname=\$PublicHostname/);
  assert.match(technicianDocs, /OutputKey=='LoadBalancerDnsName'/);
  assert.match(technicianDocs, /OutputKey=='LogGroupName'/);
  assert.match(technicianDocs, /aws logs tail \$LogGroupName/);
  assert.doesNotMatch(technicianDocs, /aws logs tail "\/redactwall\/\$TenantId"/);
  assert.match(launchDocs, /`LogGroupName` stack output/);
  assert.doesNotMatch(launchDocs, /\/redactwall\/<tenant>/);
  assert.doesNotMatch(launchDocs, /exposes plain HTTP/i);
});
