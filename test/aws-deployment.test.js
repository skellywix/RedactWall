'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const template = fs.readFileSync(path.join(root, 'infra', 'aws', 'customer-silo.yml'), 'utf8');
const docs = fs.readFileSync(path.join(root, 'docs', 'AWS_SAAS_DEPLOYMENT.md'), 'utf8');

test('AWS customer-silo template enforces tenant and seat parameters', () => {
  assert.match(template, /TenantId:/);
  assert.match(template, /SeatLimit:/);
  assert.match(template, /REDACTWALL_SAAS_MODE=true/);
  assert.match(template, /REDACTWALL_TENANT_ID=\$\{TenantId\}/);
  assert.match(template, /REDACTWALL_SEAT_LIMIT=\$\{SeatLimit\}/);
  assert.match(template, /REDACTWALL_REQUIRE_TENANT_CONTEXT=true/);
  assert.match(template, /REDACTWALL_REQUIRE_USER_IDENTITY=true/);
});

test('AWS customer-silo template uses local EBS-backed data and Secrets Manager', () => {
  assert.match(template, /VolumeType: gp3/);
  assert.match(template, /Encrypted: true/);
  assert.match(template, /-v \/var\/lib\/redactwall:\/data/);
  assert.match(template, /REDACTWALL_POLICY_PATH=\/data\/policy\.json/);
  assert.match(template, /REDACTWALL_CUSTOM_DETECTORS_PATH=\/data\/custom-detectors\.json/);
  assert.match(template, /secretsmanager:GetSecretValue/);
  assert.match(template, /HealthCheckPath: \/readyz/);
});

test('AWS customer-silo container runs with hardened Docker flags', () => {
  assert.match(template, /--init/);
  assert.match(template, /--read-only/);
  assert.match(template, /--tmpfs \/tmp:rw,noexec,nosuid,size=64m/);
  assert.match(template, /--cap-drop ALL/);
  assert.match(template, /--security-opt no-new-privileges/);
  assert.match(template, /--stop-timeout 30/);
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
});
