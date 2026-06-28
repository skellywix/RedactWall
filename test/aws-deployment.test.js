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
  assert.match(template, /SENTINEL_SAAS_MODE=true/);
  assert.match(template, /SENTINEL_TENANT_ID=\$\{TenantId\}/);
  assert.match(template, /SENTINEL_SEAT_LIMIT=\$\{SeatLimit\}/);
  assert.match(template, /SENTINEL_REQUIRE_TENANT_CONTEXT=true/);
  assert.match(template, /SENTINEL_REQUIRE_USER_IDENTITY=true/);
});

test('AWS customer-silo template uses local EBS-backed data and Secrets Manager', () => {
  assert.match(template, /VolumeType: gp3/);
  assert.match(template, /Encrypted: true/);
  assert.match(template, /-v \/var\/lib\/promptwall:\/data/);
  assert.match(template, /secretsmanager:GetSecretValue/);
  assert.match(template, /HealthCheckPath: \/readyz/);
});

test('AWS SaaS deployment docs include launch and validation steps', () => {
  assert.match(docs, /customer-silo model/);
  assert.match(docs, /aws ecr create-repository/);
  assert.match(docs, /aws cloudformation deploy/);
  assert.match(docs, /\/api\/billing\/seats/);
  assert.match(docs, /Do not run this app on Fargate with SQLite over EFS/);
});
