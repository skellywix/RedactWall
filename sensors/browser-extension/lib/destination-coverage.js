(function (root) {
  'use strict';

  const BLOCK_RULE_START = 9_100_000;
  const BLOCK_RULE_END = BLOCK_RULE_START + 5_000;
  const DYNAMIC_SCRIPT_ID = 'redactwall-policy-destinations';
  const POLICY_DESTINATION_FIELDS = [
    'governedDestinations',
    'allowedDestinations',
    'blockedDestinations',
    'blockedFileUploadDestinations',
  ];

  function policyDestinationValues(policy = {}) {
    const values = POLICY_DESTINATION_FIELDS.flatMap((field) => (
      Array.isArray(policy[field]) ? policy[field] : []
    ));
    for (const rule of Array.isArray(policy.blockedBrowserActions) ? policy.blockedBrowserActions : []) {
      if (!rule || rule.enabled === false || !String(rule.action || '').trim()) continue;
      values.push(...(Array.isArray(rule.destinations) ? rule.destinations : []));
    }
    return values;
  }

  function rawPolicyHost(value) {
    let raw = String(value || '').trim().toLowerCase();
    const wildcardOnly = raw === '*';
    if (!raw || wildcardOnly) return { raw, wildcardOnly, wildcard: false, host: '' };
    const wildcard = raw.startsWith('*.') || raw.startsWith('*');
    raw = raw.replace(/^\*\.?/, '');
    try {
      const url = raw.includes('://') ? new URL(raw) : new URL('https://' + raw);
      if (url.protocol !== 'https:') return { raw, wildcardOnly, wildcard, host: '', invalid: 'non_https_destination' };
      if (url.username || url.password) return { raw, wildcardOnly, wildcard, host: '', invalid: 'credentialed_destination' };
      return { raw, wildcardOnly, wildcard, host: String(url.hostname || '').replace(/^www\./, '') };
    } catch (_) {
      return { raw, wildcardOnly, wildcard, host: '', invalid: 'invalid_destination' };
    }
  }

  function validBrowserHost(host) {
    const value = String(host || '');
    if (!value || value.length > 253 || !value.includes('.')) return false;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
      return value.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
    }
    return value.split('.').every((label) => (
      label.length >= 1
      && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ));
  }

  function dangerousBroadHost(host) {
    return String(host || '').split('.').length < 2 || String(host || '').length < 4;
  }

  function permissionPattern(host) {
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return `https://${host}/*`;
    return `https://*.${host}/*`;
  }

  function parseHttpsMatch(pattern) {
    const match = /^https:\/\/(\*\.)?([^/*]+)\/.*$/i.exec(String(pattern || ''));
    if (!match) return null;
    return { wildcard: !!match[1], host: match[2].toLowerCase().replace(/^www\./, '') };
  }

  function manifestPatterns(manifest = {}) {
    return (manifest.content_scripts || []).flatMap((script) => (
      Array.isArray(script.matches) ? script.matches : []
    ));
  }

  function staticCoverage(host, manifest = {}) {
    let root = false;
    let descendants = false;
    for (const rawPattern of manifestPatterns(manifest)) {
      const pattern = parseHttpsMatch(rawPattern);
      if (!pattern) continue;
      if (pattern.wildcard && (host === pattern.host || host.endsWith('.' + pattern.host))) {
        root = true;
        descendants = true;
      }
      if (!pattern.wildcard && host === pattern.host) root = true;
    }
    return { root, descendants };
  }

  function mergePolicyHosts(values) {
    const hosts = new Map();
    const unsupported = [];
    for (const value of values) {
      const parsed = rawPolicyHost(value);
      if (parsed.wildcardOnly) {
        unsupported.push({ type: 'all_https', value: '*' });
        continue;
      }
      if (parsed.invalid || !validBrowserHost(parsed.host)) {
        unsupported.push({ type: parsed.invalid || 'invalid_destination' });
        continue;
      }
      if (dangerousBroadHost(parsed.host)) {
        unsupported.push({ type: 'broad_host', host: parsed.host });
        continue;
      }
      const prior = hosts.get(parsed.host);
      hosts.set(parsed.host, { host: parsed.host, includeRoot: (prior && prior.includeRoot) || !parsed.wildcard });
    }
    return { hosts: [...hosts.values()].sort((a, b) => a.host.localeCompare(b.host)), unsupported };
  }

  function buildCoverageModel(policy = {}, manifest = {}) {
    const parsed = mergePolicyHosts(policyDestinationValues(policy));
    const dynamic = [];
    const staticHosts = [];
    for (const item of parsed.hosts) {
      const covered = staticCoverage(item.host, manifest);
      if (covered.descendants && (!item.includeRoot || covered.root)) {
        staticHosts.push(item.host);
        continue;
      }
      dynamic.push({
        host: item.host,
        origin: permissionPattern(item.host),
        blockSubdomainsOnly: !item.includeRoot || covered.root,
      });
    }
    return { dynamic, staticHosts, unsupported: parsed.unsupported };
  }

  function escapeRegex(value) {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function blockingRule(item, index) {
    const condition = { resourceTypes: ['main_frame'] };
    if (item.type === 'all_https') condition.urlFilter = '|https://';
    else if (item.blockSubdomainsOnly) {
      condition.regexFilter = `^https:\\/\\/(?:[^./]+\\.)+${escapeRegex(item.host)}(?::[0-9]+)?(?:\\/|$)`;
    } else {
      condition.requestDomains = [item.host];
    }
    return { id: BLOCK_RULE_START + index, priority: 10, action: { type: 'block' }, condition };
  }

  function blockingRules(items) {
    const source = items.some((item) => item && item.type && !item.host)
      ? [{ type: 'all_https' }]
      : items;
    return source.slice(0, BLOCK_RULE_END - BLOCK_RULE_START).map(blockingRule);
  }

  function ownsBlockingRule(rule) {
    return !!rule && Number(rule.id) >= BLOCK_RULE_START && Number(rule.id) < BLOCK_RULE_END;
  }

  function tabMatchesItem(url, item) {
    let parsed;
    try { parsed = new URL(String(url || '')); } catch (_) { return false; }
    if (parsed.protocol !== 'https:') return false;
    if (item.type === 'all_https') return true;
    const host = parsed.hostname.toLowerCase();
    if (item.blockSubdomainsOnly) return host !== item.host && host.endsWith('.' + item.host);
    return host === item.host || host.endsWith('.' + item.host);
  }

  root.RedactWallDestinationCoverage = {
    BLOCK_RULE_START,
    BLOCK_RULE_END,
    DYNAMIC_SCRIPT_ID,
    policyDestinationValues,
    rawPolicyHost,
    validBrowserHost,
    permissionPattern,
    staticCoverage,
    buildCoverageModel,
    blockingRules,
    ownsBlockingRule,
    tabMatchesItem,
  };
})(typeof self !== 'undefined' ? self : globalThis);
