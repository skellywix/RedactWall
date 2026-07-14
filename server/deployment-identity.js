'use strict';

const DEPLOYMENT_ID_RE = /^dep_[a-f0-9]{32}$/;

function isDeploymentId(value) {
  return typeof value === 'string' && value.length === 36 && DEPLOYMENT_ID_RE.test(value);
}

module.exports = Object.freeze({
  DEPLOYMENT_ID_RE,
  isDeploymentId,
});
