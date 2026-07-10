'use strict';

function sameIdentity(left, right) {
  return String(left || '').trim() === String(right || '').trim();
}

function normalizedIssuer(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function staticSessionInvalid(session, deps) {
  const account = deps.auth.listStaticAccounts()
    .find((candidate) => sameIdentity(candidate.user, session.user));
  if (!account) return null;
  return deps.roles.normalizeRole(account.role) !== session.role;
}

function oidcSessionInvalid(session, deps) {
  if (!session.scimUserId || !session.idpSubject || !session.idpIssuer) return true;
  const subjectMatches = deps.db.listScimUsers().filter((candidate) => (
    candidate.active !== false && sameIdentity(candidate.externalId, session.idpSubject)
  ));
  if (subjectMatches.length !== 1 || subjectMatches[0].id !== session.scimUserId) return true;
  const user = subjectMatches[0];
  if (!sameIdentity(user.userName, session.user)) return true;
  if (!sameIdentity(user.externalId, session.idpSubject)) return true;
  if (deps.roles.normalizeRole(deps.scim.effectiveUserRole(user)) !== session.role) return true;
  const current = deps.oidcConfig();
  return !current.enabled || normalizedIssuer(current.issuer) !== normalizedIssuer(session.idpIssuer);
}

function localDynamicSessionInvalid(session, deps) {
  const staticInvalid = staticSessionInvalid(session, deps);
  if (staticInvalid !== null) return staticInvalid;
  if (deps.db.getScimUserByUserName(session.user)) return true;
  const user = deps.db.getAdminUserByUserName(session.user);
  if (!user || user.active === false) return true;
  return deps.roles.normalizeRole(user.role) !== session.role;
}

function createSessionAuthorizationCheck(deps) {
  return (session) => {
    if (deps.db.identityRevokedSince(session.user, session.iat)) return true;
    if (session.jti && deps.db.identityRevokedSince(`session:${session.jti}`, session.iat)) return true;
    if (session.provider === 'oidc') return oidcSessionInvalid(session, deps);
    return localDynamicSessionInvalid(session, deps);
  };
}

module.exports = {
  createSessionAuthorizationCheck,
  _internal: { localDynamicSessionInvalid, oidcSessionInvalid, staticSessionInvalid },
};
