/*
 * RedactWall shared detection engine (browser-safe, zero deps).
 *
 * Plugin architecture (inspired by Strac's auditor): detection is a REGISTRY of
 * self-describing detectors, each with { id, severity, score, scan(text) }.
 * Add a detector by pushing to DETECTORS; enable/disable per policy via opts.
 *
 *   - Structured detectors → regex + validators (SSN, cards, IBAN, VIN, …)
 *   - Category detectors    → semantic classifier (source code, legal, …)
 *
 * analyze(text, opts) returns: { findings, categories, maxSeverity,
 *   maxSeverityLabel, riskScore, entityCounts }.
 *
 * Exposed as CommonJS (Node) and window.PSDetect (browser).
 */
(function (root) {
  'use strict';

  // ---------- validators -----------------------------------------------------
  function luhnValid(num) {
    const d = num.replace(/[^0-9]/g, '');
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }
  function ssnPlausible(raw) {
    const d = raw.replace(/[^0-9]/g, '');
    if (d.length !== 9) return false;
    const a = d.slice(0, 3), g = d.slice(3, 5), s = d.slice(5);
    if (a === '000' || a === '666' || a[0] === '9') return false;
    if (g === '00' || s === '0000') return false;
    return true;
  }
  function abaValid(m) {
    const d = m.replace(/\D/g, '');
    if (d.length !== 9 || d === '000000000') return false;
    const w = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let s = 0; for (let i = 0; i < 9; i++) s += +d[i] * w[i];
    return s % 10 === 0;
  }
  function ibanValid(m) {
    const v = m.replace(/\s+/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(v)) return false;
    const re = v.slice(4) + v.slice(0, 4);
    let rem = 0;
    for (const ch of re) {
      const code = ch >= 'A' && ch <= 'Z' ? (ch.charCodeAt(0) - 55).toString() : ch;
      for (const dch of code) rem = (rem * 10 + (+dch)) % 97;
    }
    return rem === 1;
  }
  function vinValid(m) {
    const v = m.toUpperCase();
    if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(v)) return false; // no I,O,Q
    const map = { A:1,B:2,C:3,D:4,E:5,F:6,G:7,H:8,J:1,K:2,L:3,M:4,N:5,P:7,R:9,S:2,T:3,U:4,V:5,W:6,X:7,Y:8,Z:9 };
    const w = [8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2];
    let sum = 0;
    for (let i = 0; i < 17; i++) { const c = v[i]; const val = /\d/.test(c) ? +c : map[c]; if (val === undefined) return false; sum += val * w[i]; }
    const check = sum % 11; const cd = check === 10 ? 'X' : String(check);
    return v[8] === cd;
  }
  function bankAccountPlausible(m) {
    const d = String(m || '').replace(/\D/g, '');
    if (d.length < 6 || d.length > 17) return false;
    if (/^(\d)\1+$/.test(d)) return false;
    return true;
  }
  function compactDigits(value) {
    return String(value || '').replace(/\D/g, '');
  }
  function idValuePlausible(value, minDigits, maxChars) {
    const v = String(value || '').trim().replace(/\s+/g, '');
    const d = compactDigits(v);
    if (v.length < 5 || v.length > (maxChars || 32)) return false;
    if (d.length < (minDigits || 4)) return false;
    if (/^([A-Z0-9])\1+$/i.test(v.replace(/[-_]/g, ''))) return false;
    return true;
  }
  function itinPlausible(raw) {
    const d = compactDigits(raw);
    if (!/^9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])\d{4}$/.test(d)) return false;
    return ssnPlausible(d) === false;
  }
  function npiValid(raw) {
    const d = compactDigits(raw);
    if (!/^\d{10}$/.test(d) || /^(\d)\1+$/.test(d)) return false;
    return luhnValid('80840' + d);
  }
  function datePlausible(raw) {
    const m = String(raw || '').match(/^(\d{1,2})[/-](\d{1,2})[/-]((?:19|20)\d{2})$/);
    if (!m) return false;
    const mm = +m[1], dd = +m[2], yy = +m[3];
    const nowYear = new Date().getFullYear();
    if (yy < 1900 || yy > nowYear) return false;
    const days = [31, yy % 4 === 0 && (yy % 100 !== 0 || yy % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    return mm >= 1 && mm <= 12 && dd >= 1 && dd <= days[mm - 1];
  }
  // UK National Insurance number — prefix rules per HMRC (no D/F/I/Q/U/V in
  // either letter, no O second, and a short list of never-issued pairs).
  function ninoValid(raw) {
    const v = String(raw || '').replace(/\s+/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{6}[A-D]$/.test(v)) return false;
    if (/[DFIQUV]/.test(v.slice(0, 2)) || v[1] === 'O') return false;
    return !['BG', 'GB', 'KN', 'NK', 'NT', 'TN', 'ZZ'].includes(v.slice(0, 2));
  }
  // UK NHS number — 10 digits, weighted mod-11 check digit.
  function nhsValid(raw) {
    const d = compactDigits(raw);
    if (d.length !== 10 || /^(\d)\1+$/.test(d)) return false;
    let sum = 0; for (let i = 0; i < 9; i++) sum += +d[i] * (10 - i);
    const check = 11 - (sum % 11);
    return (check === 11 ? 0 : check) === +d[9] && check !== 10;
  }
  // Canadian Social Insurance Number — 9 digits, Luhn (8xx never issued).
  function sinValid(raw) {
    const d = compactDigits(raw);
    if (d.length !== 9 || d[0] === '8' || /^(\d)\1+$/.test(d)) return false;
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      let n = +d[i]; if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; } sum += n;
    }
    return sum % 10 === 0;
  }
  // Australian Tax File Number — 8-9 digits, weighted mod-11 checksum.
  function tfnValid(raw) {
    const d = compactDigits(raw);
    if ((d.length !== 8 && d.length !== 9) || /^(\d)\1+$/.test(d)) return false;
    const w = d.length === 9 ? [1, 4, 3, 7, 5, 8, 6, 9, 10] : [10, 7, 8, 4, 6, 3, 5, 1];
    let sum = 0; for (let i = 0; i < d.length; i++) sum += +d[i] * w[i];
    return sum % 11 === 0;
  }
  // India Aadhaar — 12 digits (first 2-9), Verhoeff checksum.
  const VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
  const VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
  function aadhaarValid(raw) {
    const d = compactDigits(raw);
    if (!/^[2-9]\d{11}$/.test(d) || /^(\d)\1+$/.test(d)) return false;
    let c = 0;
    for (let i = 0; i < 12; i++) c = VERHOEFF_D[c][VERHOEFF_P[i % 8][+d[11 - i]]];
    return c === 0;
  }
  function ipv6Valid(raw) {
    const v = String(raw || '').toLowerCase();
    if (!/^[0-9a-f:]+$/.test(v) || !v.includes(':')) return false;
    if ((v.match(/::/g) || []).length > 1) return false;
    const halves = v.split('::');
    const groups = halves.flatMap((part) => part ? part.split(':') : []);
    if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return false;
    return halves.length === 2 ? groups.length < 8 : groups.length === 8;
  }
  // Issuer Identification Number (BIN) check — a string passing Luhn is only a
  // real card if its prefix + length match a known network. Cuts the ~10% of
  // random 16-digit numbers that pass Luhn alone down to near zero.
  function cardNetwork(num) {
    const d = num.replace(/\D/g, ''); const len = d.length;
    const p2 = +d.slice(0, 2), p3 = +d.slice(0, 3), p4 = +d.slice(0, 4);
    if (d[0] === '4' && (len === 13 || len === 16 || len === 19)) return 'visa';
    if (((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) && len === 16) return 'mastercard';
    if ((p2 === 34 || p2 === 37) && len === 15) return 'amex';
    if ((p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649) || p3 === 622) && len >= 16 && len <= 19) return 'discover';
    if ((p2 === 36 || p2 === 38 || (p3 >= 300 && p3 <= 305)) && len === 14) return 'diners';
    if (p4 >= 3528 && p4 <= 3589 && len >= 16 && len <= 19) return 'jcb';
    return null;
  }
  const CARD_CTX = /\b(card|credit|debit|visa|master\s?card|amex|american\s?express|discover|cvv|cvc|exp(?:iry|iration)?|card\s?number|pan)\b/i;

  // ---------- severity -------------------------------------------------------
  const SEVERITY = {
    US_SSN: 4, CREDIT_CARD: 4, BANK_ACCOUNT: 4, ROUTING_NUMBER: 3, IBAN: 3,
    US_PASSPORT: 4, US_TIN_EIN: 3, US_ITIN: 4, US_NPI: 3, US_DRIVERS_LICENSE: 3,
    US_LICENSE_PLATE: 2, VIN: 1, MEMBER_ID: 3, LOAN_NUMBER: 3, MEDICAL_RECORD_NUMBER: 3,
    HEALTH_INSURANCE_ID: 3, SWIFT_BIC: 2,
    UK_NINO: 4, UK_NHS_NUMBER: 4, CANADA_SIN: 4, AUSTRALIA_TFN: 4, INDIA_AADHAAR: 4, INDIA_PAN: 3,
    SECRET_KEY: 4, PRIVATE_KEY: 4, CANARY_TOKEN: 4, PASSWORD: 3, DOB: 3, EXACT_MATCH: 4,
    EMAIL_ADDRESS: 2, PHONE_NUMBER: 2, IP_ADDRESS: 1, IPV6_ADDRESS: 1, US_ADDRESS: 2, PERSON_NAME: 1,
    SOURCE_CODE: 3, LEGAL_CONTRACT: 3, CREDENTIALS: 4, CONFIDENTIAL_BUSINESS: 3, HEALTH_RECORD: 3,
    PROMPT_ATTACK: 3, FINANCIAL_STATEMENT: 3, TAX_FILING: 3, HR_RECORD: 3,
  };
  const SEVERITY_LABEL = { 0: 'none', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
  // Which laws/frameworks make each detection sensitive. These drive the
  // examiner-facing "why was this blocked" rationale in sensors and console.
  // Citations are the obligation the data falls under, not legal advice.
  const REGULATIONS = Object.freeze({
    US_SSN: Object.freeze(['GLBA 501(b)', 'NCUA 12 CFR 748', 'FTC Safeguards Rule']),
    CREDIT_CARD: Object.freeze(['PCI-DSS Req 3', 'GLBA 501(b)']),
    BANK_ACCOUNT: Object.freeze(['GLBA 501(b)', 'NCUA 12 CFR 748']),
    ROUTING_NUMBER: Object.freeze(['GLBA 501(b)', 'NCUA 12 CFR 748']),
    IBAN: Object.freeze(['GLBA 501(b)', 'GDPR Art. 32']),
    SWIFT_BIC: Object.freeze(['GLBA 501(b)']),
    MEMBER_ID: Object.freeze(['GLBA 501(b)', 'NCUA 12 CFR 748']),
    LOAN_NUMBER: Object.freeze(['GLBA 501(b)', 'NCUA 12 CFR 748']),
    US_TIN_EIN: Object.freeze(['IRS Pub 1075', 'GLBA 501(b)']),
    US_ITIN: Object.freeze(['IRS Pub 1075', 'GLBA 501(b)']),
    US_PASSPORT: Object.freeze(['GLBA 501(b)', 'state breach-notification laws']),
    US_DRIVERS_LICENSE: Object.freeze(['DPPA 18 USC 2721', 'state breach-notification laws']),
    US_LICENSE_PLATE: Object.freeze(['DPPA 18 USC 2721']),
    DOB: Object.freeze(['GLBA 501(b)', 'GDPR Art. 4']),
    MEDICAL_RECORD_NUMBER: Object.freeze(['HIPAA 45 CFR 164']),
    HEALTH_INSURANCE_ID: Object.freeze(['HIPAA 45 CFR 164']),
    HEALTH_RECORD: Object.freeze(['HIPAA 45 CFR 164']),
    US_NPI: Object.freeze(['HIPAA 45 CFR 164 (context)']),
    UK_NINO: Object.freeze(['UK GDPR / DPA 2018']),
    UK_NHS_NUMBER: Object.freeze(['UK GDPR special category']),
    CANADA_SIN: Object.freeze(['PIPEDA']),
    AUSTRALIA_TFN: Object.freeze(['Privacy Act 1988 (TFN Rule)']),
    INDIA_AADHAAR: Object.freeze(['Aadhaar Act 2016']),
    INDIA_PAN: Object.freeze(['India IT Act']),
    EMAIL_ADDRESS: Object.freeze(['GDPR Art. 4', 'CCPA']),
    PHONE_NUMBER: Object.freeze(['GDPR Art. 4', 'CCPA']),
    US_ADDRESS: Object.freeze(['GDPR Art. 4', 'CCPA']),
    PERSON_NAME: Object.freeze(['GDPR Art. 4']),
    IP_ADDRESS: Object.freeze(['GDPR Art. 4 (online identifier)']),
    IPV6_ADDRESS: Object.freeze(['GDPR Art. 4 (online identifier)']),
    SECRET_KEY: Object.freeze(['GLBA Safeguards', 'SOC 2 CC6']),
    PRIVATE_KEY: Object.freeze(['GLBA Safeguards', 'SOC 2 CC6']),
    CREDENTIALS: Object.freeze(['GLBA Safeguards', 'SOC 2 CC6']),
    PASSWORD: Object.freeze(['GLBA Safeguards', 'SOC 2 CC6']),
    CANARY_TOKEN: Object.freeze(['internal security control']),
    EXACT_MATCH: Object.freeze(['organization-designated sensitive data']),
    SOURCE_CODE: Object.freeze(['trade secret (DTSA)', 'company confidentiality']),
    LEGAL_CONTRACT: Object.freeze(['company confidentiality', 'attorney-client privilege risk']),
    CONFIDENTIAL_BUSINESS: Object.freeze(['trade secret (DTSA)', 'company confidentiality']),
    VIN: Object.freeze(['DPPA 18 USC 2721']),
    PROMPT_ATTACK: Object.freeze(['AI security guardrail']),
    FINANCIAL_STATEMENT: Object.freeze(['GLBA 501(b)', 'company confidentiality']),
    TAX_FILING: Object.freeze(['IRS Pub 1075', 'GLBA 501(b)']),
    HR_RECORD: Object.freeze(['company confidentiality', 'state employment-privacy laws']),
  });
  const NO_REGULATIONS = Object.freeze([]);
  function regulationsFor(type) { return REGULATIONS[type] || NO_REGULATIONS; }
  // Graded confidence per finding (cf. Nightfall's Possible/Likely/Very Likely),
  // so an operator can tune policy on confidence, not just severity.
  const CONFIDENCE_LABEL = { 1: 'possible', 2: 'likely', 3: 'very_likely' };
  function confidenceTier(score) { return score >= 0.9 ? 3 : score >= 0.7 ? 2 : 1; }

  // Vendor attribution for SECRET_KEY findings (cf. Nightfall's vendor
  // labeling), derived offline from the matched value's shape. Never verified
  // against vendor APIs — live-key probing would ship a captured secret
  // off-box (see DECISIONS.md). Order matters: more specific prefixes first
  // (sk-ant- before sk-, sk_live_ before nothing else claims sk_).
  const _sv = (vendor, label) => Object.freeze({ vendor, label });
  const SECRET_VENDOR_PREFIXES = Object.freeze([
    ['sk-ant-', _sv('anthropic', 'Anthropic API key')],
    ['sk_live_', _sv('stripe', 'Stripe secret key (live)')],
    ['sk_test_', _sv('stripe', 'Stripe secret key (test)')],
    ['sk-', _sv('openai', 'OpenAI-style API key')],
    ['rk_live_', _sv('stripe', 'Stripe restricted key (live)')],
    ['rk_test_', _sv('stripe', 'Stripe restricted key (test)')],
    ['AKIA', _sv('aws', 'AWS access key id')],
    ['ASIA', _sv('aws', 'AWS temporary access key id')],
    ['github_pat_', _sv('github', 'GitHub fine-grained token')],
    ['ghp_', _sv('github', 'GitHub personal access token')],
    ['glpat-', _sv('gitlab', 'GitLab personal access token')],
    ['xapp-', _sv('slack', 'Slack app-level token')],
    ['xox', _sv('slack', 'Slack token')],
    ['SG.', _sv('sendgrid', 'SendGrid API key')],
    ['AIza', _sv('google', 'Google API key')],
    ['ya29.', _sv('google', 'Google OAuth access token')],
    ['npm_', _sv('npm', 'npm access token')],
    ['hf_', _sv('huggingface', 'Hugging Face token')],
    ['dop_v1_', _sv('digitalocean', 'DigitalOcean token')],
    ['shpat_', _sv('shopify', 'Shopify private app token')],
    ['shpss_', _sv('shopify', 'Shopify shared secret')],
    ['pypi-', _sv('pypi', 'PyPI API token')],
    ['PMAK-', _sv('postman', 'Postman API key')],
    ['dapi', _sv('databricks', 'Databricks token')],
  ]);
  const SECRET_VENDOR_TWILIO = _sv('twilio', 'Twilio API key');
  const SECRET_VENDOR_TERRAFORM = _sv('terraform', 'Terraform Cloud token');
  const SECRET_VENDOR_JWT = _sv('jwt', 'JSON Web Token');
  function secretVendor(value) {
    const v = String(value || '');
    for (const entry of SECRET_VENDOR_PREFIXES) { if (v.startsWith(entry[0])) return entry[1]; }
    if (v.startsWith('eyJ')) return SECRET_VENDOR_JWT;
    if (v.indexOf('.atlasv1.') !== -1) return SECRET_VENDOR_TERRAFORM;
    if (/^SK[0-9a-fA-F]{32}$/.test(v)) return SECRET_VENDOR_TWILIO;
    return null;
  }

  // ---------- structured detector registry -----------------------------------
  // Each: { id, score, re, validate?(match,fullText)?, ctx?:RegExp (requires nearby word) }
  const DETECTORS = [
    // SSN — high confidence: written with separators (123-45-6789 / 123 45 6789).
    { id: 'US_SSN', score: 0.92, re: /\b(?!000|666|9\d\d)\d{3}[- .](?!00)\d{2}[- .](?!0000)\d{4}\b/g, validate: (m) => ssnPlausible(m) },
    // SSN — bare 9 digits ONLY with nearby context, so ordinary 9-digit ids
    // (account/member/transaction numbers) don't become critical hard-blocks.
    { id: 'US_SSN', score: 0.85, re: /\b(?!000|666|9\d\d)\d{3}(?!00)\d{2}(?!0000)\d{4}\b/g, ctx: /\b(ssn|ss#|social\s*security|social\s*sec(?:urity)?\s*(?:no|number|#)?|taxpayer)\b/i, validate: (m) => ssnPlausible(m) },
    // Credit card — Luhn AND a valid issuer prefix, AND (separators OR card
    // context). Stops random 16-digit ids that merely pass Luhn (~10%).
    { id: 'CREDIT_CARD', score: 0.95, re: /\b(?:\d[ -]?){13,19}\b/g, validate: (m, text) => luhnValid(m) && !!cardNetwork(m) && (/[ -]/.test(m.trim()) || CARD_CTX.test(text || '')) },
    // Match a contiguous IBAN body OR canonical space-grouped chunks, but never
    // absorb a following plain word (which greedily fails mod-97 and hid the IBAN).
    { id: 'IBAN', score: 0.9, re: /\b[A-Za-z]{2}\d{2}(?:[A-Za-z0-9]{10,30}|(?: [A-Z0-9]{2,4}){3,9})\b/g, validate: (m) => ibanValid(m) },
    // Routing/ABA — valid checksum AND banking context (a bare 9-digit number is
    // far more often an id than a routing number).
    { id: 'ROUTING_NUMBER', score: 0.6, re: /\b\d{9}\b/g, ctx: /\b(routing|aba|rtn|transit|ach|wire|direct\s*deposit|bank)\b/i, validate: (m) => abaValid(m) },
    // Bank account numbers have no universal checksum, so require explicit
    // banking/account context and a plausible 6-17 digit value.
    { id: 'BANK_ACCOUNT', score: 0.72, re: /\b(?:bank|checking|savings|deposit|ach|wire|direct\s*deposit|debit)\s+(?:account|acct)(?:\s*(?:number|no\.?|#))?\s*[:#-]?\s*((?:\d[ -]?){6,17})\b/gi, group: 1, validate: (m) => bankAccountPlausible(m) },
    { id: 'BANK_ACCOUNT', score: 0.68, re: /\b(?:account|acct)\s*(?:number|no\.?|#)\s*[:#-]?\s*((?:\d[ -]?){6,17})\b/gi, group: 1, ctx: /\b(bank|checking|savings|deposit|ach|wire|loan|member)\b/i, validate: (m) => bankAccountPlausible(m) },
    { id: 'US_TIN_EIN', score: 0.7, re: /\b\d{2}-\d{7}\b/g, ctx: /\b(ein|employer id|tax\s?id|tin|taxpayer)\b/i },
    { id: 'US_ITIN', score: 0.88, re: /\b9\d{2}[- ]?(?:5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])[- ]?\d{4}\b/g, ctx: /\b(itin|individual taxpayer|taxpayer id|tax id|tin)\b/i, validate: (m) => itinPlausible(m) },
    { id: 'US_PASSPORT', score: 0.7, re: /\b[A-Z]?\d{8,9}\b/g, ctx: /\bpassport\b/i },
    { id: 'US_NPI', score: 0.82, re: /\b(?:npi|national provider identifier)(?:\s*(?:number|no\.?|#))?\s*[:#-]?\s*(\d{10})\b/gi, group: 1, validate: (m) => npiValid(m) },
    { id: 'VIN', score: 0.85, re: /\b[A-HJ-NPR-Z0-9]{17}\b/g, validate: (m) => vinValid(m) },
    // group:1 anchors the value to the id (not the label word), and the digit
    // check stops ordinary words after "license" (e.g. "license agreement").
    { id: 'US_DRIVERS_LICENSE', score: 0.7, re: /\b(?:DL|driver'?s?\s*licen[cs]e|license)\s*(?:number|no\.?|#|id)?\s*[:#]?\s*([A-Z0-9]{6,12})\b/gi, group: 1, validate: (m) => /[0-9]/.test(m) },
    { id: 'US_LICENSE_PLATE', score: 0.55, re: /\b[A-Z0-9]{5,8}\b/g, ctx: /\b(license plate|plate (?:no|number|#)|tag number)\b/i, validate: (m) => /[A-Z]/.test(m) && /\d/.test(m) },
    { id: 'MEMBER_ID', score: 0.76, re: /\b(?:member|customer|client|account holder)\s*(?:id|number|no\.?|#)\s*[:#-]?\s*([A-Z0-9][A-Z0-9_-]{4,24})\b/gi, group: 1, validate: (m) => idValuePlausible(m, 4, 28) },
    { id: 'LOAN_NUMBER', score: 0.74, re: /\b(?:loan|mortgage|application|case)\s*(?:id|number|no\.?|#)\s*[:#-]?\s*([A-Z0-9][A-Z0-9_-]{4,24})\b/gi, group: 1, validate: (m) => idValuePlausible(m, 4, 28) },
    { id: 'MEDICAL_RECORD_NUMBER', score: 0.78, re: /\b(?:mrn|medical record|patient record|chart)\s*(?:id|number|no\.?|#)?\s*[:#-]?\s*([A-Z0-9][A-Z0-9_-]{5,24})\b/gi, group: 1, validate: (m) => idValuePlausible(m, 4, 28) },
    { id: 'HEALTH_INSURANCE_ID', score: 0.79, re: /\b(?:health|medical|insurance|subscriber|policy|group)\s*(?:member\s*)?(?:id|number|no\.?|#)\s*[:#-]?\s*([A-Z0-9][A-Z0-9_-]{5,24})\b/gi, group: 1, ctx: /\b(health|medical|insurance|subscriber|policy|group|plan)\b/i, validate: (m) => idValuePlausible(m, 4, 28) },
    { id: 'SWIFT_BIC', score: 0.7, re: /\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g, ctx: /\b(swift|bic|international wire|wire transfer)\b/i },
    // International government identifiers — checksum-validated AND context-
    // anchored, so ordinary ids/reference codes never fire them.
    { id: 'UK_NINO', score: 0.85, re: /\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g, ctx: /\b(national insurance|nino|ni number|ni no\.?|hmrc)\b/i, validate: (m) => ninoValid(m) },
    { id: 'UK_NHS_NUMBER', score: 0.85, re: /\b\d{3}[- ]?\d{3}[- ]?\d{4}\b/g, ctx: /\b(nhs)\b/i, validate: (m) => nhsValid(m) },
    { id: 'CANADA_SIN', score: 0.85, re: /\b\d{3}[- ]?\d{3}[- ]?\d{3}\b/g, ctx: /\b(sin|social insurance)\b/i, validate: (m) => sinValid(m) },
    { id: 'AUSTRALIA_TFN', score: 0.85, re: /\b\d{3}[- ]?\d{3}[- ]?\d{2,3}\b/g, ctx: /\b(tfn|tax file number)\b/i, validate: (m) => tfnValid(m) },
    { id: 'INDIA_AADHAAR', score: 0.85, re: /\b[2-9]\d{3}[- ]?\d{4}[- ]?\d{4}\b/g, ctx: /\b(aadhaar|aadhar|uidai)\b/i, validate: (m) => aadhaarValid(m) },
    { id: 'INDIA_PAN', score: 0.8, re: /\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b/g, ctx: /\b(pan|permanent account number|income tax)\b/i },
    { id: 'EMAIL_ADDRESS', score: 0.95, re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
    { id: 'PHONE_NUMBER', score: 0.7, re: /(?:\+?1[ .-]?)?\(?\b\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b/g, validate: (m) => /[()\-. ]/.test(m) || m.length === 10 },
    { id: 'IP_ADDRESS', score: 0.85, re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
    // Admit compressed '::' forms (empty groups) too; ipv6Valid does the strict
    // filtering. Bounded {0,4}/{2,7} so there is no catastrophic backtracking.
    { id: 'IPV6_ADDRESS', score: 0.75, re: /(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])/g, validate: (m) => ipv6Valid(m) },
    { id: 'DOB', score: 0.72, re: /\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b/g, ctx: /\b(dob|date of birth|birthdate|born|birthday|patient|member|customer)\b/i, validate: (m) => datePlausible(m) },
    { id: 'PRIVATE_KEY', score: 0.99, re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g },
    { id: 'SECRET_KEY', score: 0.95, re: /\b(?:sk-(?:live|test|proj)?-?[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z\-_]{20,}|ya29\.[A-Za-z0-9_-]{30,}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}|dop_v1_[a-f0-9]{64}|shp(?:at|ss)_[a-fA-F0-9]{32}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}|PMAK-[0-9a-f]{24}-[0-9a-f]{34}|dapi[0-9a-f]{32}(?:-\d)?|[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{40,}|SK[0-9a-fA-F]{32}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
    { id: 'SECRET_KEY', score: 0.9, re: /\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|ACCESS_KEY|PASSWORD|PRIVATE_KEY)\s*[:=]\s*["']?([A-Za-z0-9_./+=@%:-]{8,})["']?/g, group: 1 },
    // Cloud secrets that need context or key=value shape rather than a prefix.
    // vendorTag supplies the vendor label the value alone cannot (see secretVendor).
    { id: 'SECRET_KEY', score: 0.9, re: /\b(?:AccountKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/=]{40,})/g, group: 1, vendorTag: _sv('azure', 'Azure storage/connection key') },
    // AWS secret access keys are bare 40-char base64 — context-gated, and
    // anchored with lookarounds because \b is unreliable next to + and /.
    { id: 'SECRET_KEY', score: 0.85, re: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g, ctx: /\b(?:aws.{0,12}secret|secret[_ ]?access[_ ]?key)\b/i, vendorTag: _sv('aws', 'AWS secret access key') },
    { id: 'SECRET_KEY', score: 0.9, re: /"type"\s*:\s*"service_account"/g, vendorTag: _sv('gcp', 'GCP service-account key file') },
    // Org-planted tripwire values for fake records, demos, and leak drills.
    { id: 'CANARY_TOKEN', score: 0.99, re: /\b(?:RW|PS|REDACTWALL|PROMPTWALL|PROMPTSENTINEL)[-_]CANARY[-_][A-Z0-9][A-Z0-9_-]{11,63}\b/gi },
    { id: 'PASSWORD', score: 0.8, re: /\b(?:pass(?:word|wd)?|pwd|passphrase)\s*[:=]\s*\S{4,}/gi },
    { id: 'US_ADDRESS', score: 0.6, re: /\b\d{1,6}\s+(?:[A-Za-z0-9.'-]+\s){0,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter)\b\.?/gi },
  ];
  const NAME_CONTEXT = /\b(?:member|customer|client|account holder|name is|patient|[Mm]r|[Mm]rs|[Mm]s|[Dd]r)\.?[:,]?\s+([A-Z][a-z]+\s+[A-Z][a-z]+)/g;
  // Stateless probe over the same pattern — .test() on a /g regex is lastIndex-
  // dependent, so classifySemantic uses this copy instead.
  const NAME_CONTEXT_PROBE = new RegExp(NAME_CONTEXT.source);
  const SEMANTIC_DETECTOR_IDS = ['PERSON_NAME', 'SOURCE_CODE', 'LEGAL_CONTRACT', 'CREDENTIALS', 'CONFIDENTIAL_BUSINESS', 'HEALTH_RECORD', 'PROMPT_ATTACK', 'FINANCIAL_STATEMENT', 'TAX_FILING', 'HR_RECORD'];
  // Emitted dynamically (not from a regex in DETECTORS) but must still be a
  // known, policy-addressable detector id — e.g. usable in alwaysBlock.
  const VIRTUAL_DETECTOR_IDS = ['EXACT_MATCH'];
  const CUSTOM_DETECTOR_ID_RE = /^[A-Z][A-Z0-9_]{2,79}$/;
  const CUSTOM_DETECTOR_LIMIT = 100;
  const CUSTOM_PATTERN_MAX_CHARS = 240;
  const CUSTOM_CONTEXT_MAX_CHARS = 160;
  const CUSTOM_MAX_REPEAT = 80;
  const CUSTOM_DETECTOR_CACHE = typeof WeakMap !== 'undefined' ? new WeakMap() : null;

  function builtInDetectorIds() {
    const ids = new Set();
    for (const d of DETECTORS) ids.add(d.id);
    for (const id of SEMANTIC_DETECTOR_IDS) ids.add(id);
    for (const id of VIRTUAL_DETECTOR_IDS) ids.add(id);
    return ids;
  }

  function boundedNumberValue(value, fallback, min, max) {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.max(min, Math.min(max, n));
  }

  function normalizeCustomFlags(value) {
    const raw = String(value || '');
    if (!/^[i]*$/.test(raw)) return null;
    return raw.includes('i') ? 'gi' : 'g';
  }

  function regexLooksSafe(pattern, maxChars) {
    const p = String(pattern || '');
    if (!p || p.length > maxChars) return false;
    if (/\(\?<([!=])?/.test(p) || /\(\?<!|\(\?<=/.test(p)) return false;
    if (/\\[1-9]/.test(p)) return false;
    if (/\.\*|\.\+/.test(p)) return false;
    if ((p.match(/\|/g) || []).length > 24) return false;
    if ((p.match(/[+*]/g) || []).length > 18) return false;
    if (/\([^)]*(?:\+|\*|\{\d+(?:,\d*)?\})[^)]*\)(?:\+|\*|\{\d+(?:,\d*)?\})/.test(p)) return false;
    // Unbounded quantifier over an alternation group whose branches can overlap
    // (e.g. '([0-9]|\d)+') backtracks exponentially — reject it too.
    if (/\([^)]*\|[^)]*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(p)) return false;
    const reps = p.match(/\{(\d+)(?:,(\d*))?\}/g) || [];
    for (const rep of reps) {
      const m = rep.match(/\{(\d+)(?:,(\d*))?\}/);
      if (!m) continue;
      if (m[2] === '') return false;
      const upper = m[2] == null ? Number(m[1]) : Number(m[2]);
      if (!Number.isFinite(upper) || upper > CUSTOM_MAX_REPEAT) return false;
    }
    return true;
  }

  function normalizeCustomValidators(value) {
    const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const out = {};
    const intFields = [
      ['minDigits', 0, 0, 64],
      ['maxDigits', 128, 0, 128],
      ['minLength', 1, 1, 128],
      ['maxLength', 128, 1, 128],
    ];
    for (const [key, fallback, min, max] of intFields) {
      if (source[key] === undefined) continue;
      out[key] = Math.round(boundedNumberValue(source[key], fallback, min, max));
    }
    if (source.requireLetter !== undefined) out.requireLetter = source.requireLetter === true;
    if (source.requireDigit !== undefined) out.requireDigit = source.requireDigit === true;
    if (source.denyRepeating !== undefined) out.denyRepeating = source.denyRepeating !== false;
    if (source.plausibleId !== undefined) out.plausibleId = source.plausibleId === true;
    if (source.checksum !== undefined) {
      const checksum = String(source.checksum || '').trim().toLowerCase();
      if (checksum === 'luhn') out.checksum = checksum;
    }
    return out;
  }

  function validateCustomValue(value, validators) {
    const v = String(value || '').trim();
    const compact = v.replace(/\s+/g, '');
    const d = compactDigits(v);
    const rules = validators || {};
    if (!v || v.length > 128) return false;
    if (v.length < (rules.minLength || 1)) return false;
    if (v.length > (rules.maxLength || 128)) return false;
    if (d.length < (rules.minDigits || 0)) return false;
    if (d.length > (rules.maxDigits || 128)) return false;
    if (rules.requireLetter && !/[A-Za-z]/.test(v)) return false;
    if (rules.requireDigit && !/\d/.test(v)) return false;
    if (rules.denyRepeating !== false && /^([A-Z0-9])\1+$/i.test(compact.replace(/[-_]/g, ''))) return false;
    if (rules.plausibleId && !idValuePlausible(v, rules.minDigits || 4, rules.maxLength || 32)) return false;
    if (rules.checksum === 'luhn' && !luhnValid(v)) return false;
    return true;
  }

  function publicCustomDetector(det) {
    const out = {
      id: det.id,
      label: det.label,
      severity: det.severity,
      severityLabel: SEVERITY_LABEL[det.severity] || 'low',
      score: det.score,
      pattern: det.pattern,
      flags: det.flags.replace('g', ''),
      group: det.group,
      custom: true,
    };
    if (det.context) out.context = det.context;
    if (Object.keys(det.validators || {}).length) out.validators = det.validators;
    return out;
  }

  function normalizeCustomDetector(raw, builtinIds) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || raw.enabled === false) return null;
    const id = String(raw.id || '').trim().toUpperCase();
    if (!CUSTOM_DETECTOR_ID_RE.test(id)) return null;
    if ((builtinIds || builtInDetectorIds()).has(id)) return null;
    const pattern = String(raw.pattern || raw.regex || '').trim();
    if (!regexLooksSafe(pattern, CUSTOM_PATTERN_MAX_CHARS)) return null;
    const flags = normalizeCustomFlags(raw.flags);
    if (!flags) return null;
    let re;
    try { re = new RegExp(pattern, flags); } catch { return null; }
    // A pattern that can match the empty string would spin detectStructured's
    // exec loop forever (lastIndex never advances). Reject it up front.
    re.lastIndex = 0;
    if (re.test('')) return null;
    re.lastIndex = 0;
    let ctx = null;
    let context = '';
    if (raw.context !== undefined) {
      context = String(raw.context || '').trim();
      if (!regexLooksSafe(context, CUSTOM_CONTEXT_MAX_CHARS)) return null;
      try { ctx = new RegExp(context, flags); } catch { return null; }
    }
    const validators = normalizeCustomValidators(raw.validators);
    return {
      id,
      label: String(raw.label || id).trim().slice(0, 80) || id,
      score: boundedNumberValue(raw.score, 0.75, 0.1, 1),
      severity: Math.round(boundedNumberValue(raw.severity, 3, 1, 4)),
      pattern,
      flags,
      group: Math.round(boundedNumberValue(raw.group, 0, 0, 10)),
      context,
      validators,
      custom: true,
      re,
      ctx,
      validate: (m) => validateCustomValue(m, validators),
    };
  }

  function normalizeCustomDetectors(value) {
    const list = Array.isArray(value) ? value : (value && Array.isArray(value.detectors) ? value.detectors : []);
    if (CUSTOM_DETECTOR_CACHE && list && typeof list === 'object') {
      const cached = CUSTOM_DETECTOR_CACHE.get(list);
      if (cached) return cached;
    }
    const out = [];
    const seen = new Set();
    const builtinIds = builtInDetectorIds();
    for (const item of list) {
      const det = normalizeCustomDetector(item, builtinIds);
      if (!det || seen.has(det.id)) continue;
      seen.add(det.id);
      out.push(det);
      if (out.length >= CUSTOM_DETECTOR_LIMIT) break;
    }
    if (CUSTOM_DETECTOR_CACHE && list && typeof list === 'object') CUSTOM_DETECTOR_CACHE.set(list, out);
    return out;
  }

  // Detector metadata for the console (enable/disable lists).
  function listDetectors(opts) {
    const ids = [];
    const seen = new Set();
    const add = (id) => { if (!seen.has(id)) { seen.add(id); ids.push(id); } };
    for (const d of DETECTORS) add(d.id);
    SEMANTIC_DETECTOR_IDS.forEach(add);
    VIRTUAL_DETECTOR_IDS.forEach(add);
    const builtIn = ids.map((id) => ({ id, severity: SEVERITY[id] || 1, severityLabel: SEVERITY_LABEL[SEVERITY[id] || 1] }));
    const custom = normalizeCustomDetectors(opts && opts.customDetectors).map(publicCustomDetector);
    return builtIn.concat(custom);
  }

  function ctxOk(det, text, idx) {
    if (!det.ctx) return true;
    const start = Math.max(0, idx - 40), end = Math.min(text.length, idx + 40);
    det.ctx.lastIndex = 0;
    return det.ctx.test(text.slice(start, end));
  }

  // ---------- Exact Data Match (EDM) -----------------------------------------
  // Flag values that exactly match an org-provided watchlist (member IDs, account
  // numbers, employee names) WITHOUT the plaintext ever leaving the org: the
  // admin fingerprints each known value to a salted one-way hash, and detection
  // hashes candidate spans and checks set membership. This is the on-device,
  // privacy-preserving version of Nightfall/Strac EDM — the vault of real values
  // never ships to the sensor, only irreversible fingerprints do.
  const EDM_CACHE = typeof WeakMap !== 'undefined' ? new WeakMap() : null;
  function _fnv1a(str) { let h = 0x811c9dc5; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0; } return h; }
  function _djb2(str) { let h = 5381; for (let i = 0; i < str.length; i++) h = ((h * 33) ^ str.charCodeAt(i)) >>> 0; return h; }
  // 64-bit-ish fingerprint as two independent 32-bit hashes → negligible
  // collision rate for realistic watchlist sizes, still zero-dependency.
  function edmFingerprint(value, salt) {
    const norm = String(value || '').toLowerCase().replace(/\s+/g, ' ').trim();
    if (!norm) return '';
    const seeded = String(salt || '') + ' ' + norm;
    return _fnv1a(seeded).toString(16).padStart(8, '0') + _djb2(seeded).toString(16).padStart(8, '0');
  }
  function normalizeExactMatchConfig(value) {
    const cfg = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const list = Array.isArray(cfg.fingerprints) ? cfg.fingerprints : [];
    if (EDM_CACHE && typeof cfg === 'object') { const c = EDM_CACHE.get(cfg); if (c) return c; }
    const set = new Set();
    for (const fp of list) { const s = String(fp || '').trim().toLowerCase(); if (/^[0-9a-f]{16}$/.test(s)) set.add(s); }
    const out = {
      salt: String(cfg.salt || ''),
      set,
      minLen: Math.max(4, Math.min(64, Number(cfg.minLen) || 6)),
      maxWords: Math.max(1, Math.min(8, Number(cfg.maxWords) || 5)),
      score: Math.max(0.1, Math.min(1, Number(cfg.score) || 0.99)),
      severity: Math.round(Math.max(1, Math.min(4, Number(cfg.severity) || 4))),
      enabled: set.size > 0 && cfg.enabled !== false,
    };
    if (EDM_CACHE && typeof cfg === 'object') EDM_CACHE.set(cfg, out);
    return out;
  }
  function detectExactMatch(text, cfg) {
    const c = normalizeExactMatchConfig(cfg);
    if (!c.enabled) return [];
    const out = [];
    const seen = new Set();
    const tokenRe = /[A-Za-z0-9][A-Za-z0-9._%+@'-]*/g;
    const toks = []; let t;
    tokenRe.lastIndex = 0;
    // Scan the full text: every structured detector runs over the whole input,
    // so EDM must too. A silent token cap here would let a watchlisted value
    // hide past the cutoff in a large paste — a fail-open for exactly the
    // must-never-leak data EDM protects. The inner loop is O(tokens * maxWords)
    // with maxWords <= 8, i.e. linear and bounded.
    while ((t = tokenRe.exec(text)) !== null) { toks.push({ v: t[0], start: t.index, end: t.index + t[0].length }); }
    for (let i = 0; i < toks.length; i++) {
      for (let n = 1; n <= c.maxWords && i + n <= toks.length; n++) {
        const span = text.slice(toks[i].start, toks[i + n - 1].end);
        if (span.length < c.minLen) continue;
        const variants = [span];
        const digits = span.replace(/\D/g, '');
        // Compare against the SAME normalization edmFingerprint applies (whitespace
        // collapsed to single spaces, not stripped), so a watchlisted number written
        // with spaces ('1234 5678') still yields its digits-only fingerprint variant.
        const spanNorm = span.toLowerCase().replace(/\s+/g, ' ').trim();
        if (digits.length >= c.minLen && digits !== spanNorm) variants.push(digits);
        for (const variant of variants) {
          if (c.set.has(edmFingerprint(variant, c.salt))) {
            const key = toks[i].start + '|' + toks[i + n - 1].end;
            if (!seen.has(key)) { seen.add(key); out.push({ type: 'EXACT_MATCH', value: span, start: toks[i].start, end: toks[i + n - 1].end, score: c.score, severity: c.severity }); }
            break;
          }
        }
      }
    }
    return out;
  }

  function detectStructured(text, disabled, customDetectors) {
    const out = [];
    const seen = new Set();
    for (const det of DETECTORS.concat(normalizeCustomDetectors(customDetectors))) {
      if (disabled.has(det.id)) continue;
      det.re.lastIndex = 0; let m;
      while ((m = det.re.exec(text)) !== null) {
        // A zero-length match never advances lastIndex on its own, so bump it
        // by hand to avoid spinning forever on empty-matchable patterns.
        if (m[0] === '') { det.re.lastIndex++; continue; }
        const v = det.group ? m[det.group] : m[0];
        if (!v) continue;
        const start = det.group ? m.index + m[0].indexOf(v) : m.index;
        if (det.validate && !det.validate(v, text)) continue;
        if (!ctxOk(det, text, start)) continue;
        const key = det.id + '|' + v + '|' + start;
        if (seen.has(key)) continue; seen.add(key);
        const finding = { type: det.id, value: v, start, end: start + v.length, score: det.score, severity: det.severity || SEVERITY[det.id] || 1 };
        if (det.id === 'SECRET_KEY') {
          const vt = det.vendorTag || secretVendor(v);
          if (vt) { finding.vendor = vt.vendor; finding.vendorLabel = vt.label; }
        }
        out.push(finding);
      }
    }
    if (!disabled.has('PERSON_NAME')) {
      NAME_CONTEXT.lastIndex = 0; let n;
      while ((n = NAME_CONTEXT.exec(text)) !== null) {
        const v = n[1], start = n.index + n[0].indexOf(v);
        out.push({ type: 'PERSON_NAME', value: v, start, end: start + v.length, score: 0.55, severity: 1 });
      }
    }
    return out;
  }

  // ---------- compact on-device semantic model (the ONNX swap-in) ------------
  // A tiny hashing-trick logistic-regression classifier — an endpoint "small
  // model" (cf. Harmonic) but zero-dependency and a few KB. It AUGMENTS the
  // keyword heuristic (max-combine), so literal markers still fire and
  // paraphrases ("thinking about switching away from Acme, keep this internal")
  // get caught too. Trained offline by scripts/train-semantic.js; the weights
  // are regenerated between the markers below. Empty model => LR never fires
  // (pure heuristic, no regression).
  const PS_FEAT_DIMS = 1024;
  function _h(str) { let h = 5381; for (let i = 0; i < str.length; i++) h = ((h * 33) ^ str.charCodeAt(i)) >>> 0; return h % PS_FEAT_DIMS; }
  function _structFeats(t) {
    t = t || ''; const len = Math.max(t.length, 1); const lines = t.split('\n'); const nl = Math.max(lines.length, 1);
    return [
      (t.match(/[{}()\[\];:=<>+\-*/%]/g) || []).length / len,          // punctuation density
      /[-+*/%]=|=[^=]/.test(t) ? 1 : 0,                                 // assignment-ish operator
      /:\s*(\n|$)/.test(t) ? 1 : 0,                                     // colon at end of line (py/blocks)
      lines.filter((l) => /^\s{2,}\S/.test(l)).length / nl,            // indented lines ratio
      /[A-Za-z_]\w{0,63}[ \t]{0,4}\(/.test(t) ? 1 : 0,                  // function-call parens (bounded: no catastrophic backtracking on long single-token pastes)
      (t.match(/\d/g) || []).length / len,                             // digit density
      /=>/.test(t) ? 1 : 0,                                             // arrow function
      Math.min(1, (len / nl) / 80),                                    // avg line length (norm)
    ];
  }
  // Feature vector: L2-normalized hashed word uni/bigrams + structural tail.
  function _featurize(text) {
    const S = 8, f = new Array(PS_FEAT_DIMS + S).fill(0);
    const toks = (text || '').toLowerCase().match(/[a-z0-9_']+/g) || [];
    for (let i = 0; i < toks.length; i++) {
      f[_h(toks[i])] += 1;
      if (i + 1 < toks.length) f[_h(toks[i] + '~' + toks[i + 1])] += 1;
      // subword char n-grams (3,4) — share signal across paraphrases / morphology
      // / obfuscation, which bag-of-words misses. Down-weighted so whole words lead.
      const w = '^' + toks[i] + '$';
      for (let k = 0; k + 3 <= w.length; k++) f[_h('#' + w.slice(k, k + 3))] += 0.5;
      for (let k = 0; k + 4 <= w.length; k++) f[_h('#' + w.slice(k, k + 4))] += 0.5;
    }
    let norm = 0; for (let i = 0; i < PS_FEAT_DIMS; i++) norm += f[i] * f[i];
    norm = Math.sqrt(norm) || 1; for (let i = 0; i < PS_FEAT_DIMS; i++) f[i] /= norm;
    const sf = _structFeats(text); for (let j = 0; j < S; j++) f[PS_FEAT_DIMS + j] = sf[j];
    return f;
  }
  // __SEMANTIC_MODEL_START__ (regenerated by scripts/train-semantic.js — do not hand-edit)
  var SEMANTIC_MODEL = {"dims":1032,"models":{"CONFIDENTIAL_BUSINESS":{"bias":-1.6697,"w":{"0":-0.1258,"2":0.1161,"6":0.2071,"7":-0.2001,"9":-0.1864,"12":0.179,"13":0.1754,"14":-0.1756,"15":0.1089,"16":0.4088,"18":0.1464,"19":-0.0947,"20":0.2613,"23":0.2982,"25":-0.0891,"28":-0.0796,"29":0.1517,"30":0.2287,"31":0.1887,"33":0.1267,"34":0.4687,"35":0.1654,"38":-0.0766,"41":0.2263,"43":0.1945,"44":-0.1156,"45":0.2666,"46":-0.1103,"47":0.0951,"49":0.1742,"50":0.1522,"52":0.1409,"53":-0.1067,"55":-0.1002,"56":-0.0943,"57":0.0727,"58":-0.107,"60":0.1889,"61":-0.1176,"64":0.1853,"66":0.4934,"70":-0.3697,"71":-0.0656,"72":0.1215,"73":-0.0914,"74":0.284,"75":0.297,"76":0.2644,"77":0.333,"78":0.2212,"80":0.0877,"81":0.1387,"82":0.2481,"83":0.1755,"84":0.075,"86":-0.0547,"87":-0.1045,"88":0.1068,"89":0.1055,"90":0.1245,"91":-0.1431,"92":0.0894,"93":0.2199,"94":0.3124,"95":-0.095,"96":-0.1056,"97":0.1642,"98":-0.1218,"99":0.1152,"102":-0.2744,"103":0.0866,"105":0.1134,"106":-0.1161,"109":-0.1215,"110":-0.3523,"111":-0.0921,"112":-0.0739,"116":0.1191,"118":-0.0863,"119":0.4437,"122":-0.2061,"123":0.3651,"124":-0.1488,"125":0.0817,"127":0.1986,"129":0.3018,"130":0.2141,"131":-0.0839,"132":0.2051,"133":-0.065,"134":-0.1804,"138":0.6761,"139":-0.0508,"140":0.0704,"142":0.2581,"143":-0.0582,"144":-0.0605,"145":-0.0755,"146":0.0789,"147":-0.0675,"148":0.0723,"149":-0.1368,"151":-0.1477,"152":-0.1367,"153":-0.2655,"155":0.0551,"156":-0.1235,"158":-0.2029,"159":-0.1498,"160":-0.2912,"161":0.0636,"162":-0.0566,"163":0.5863,"164":-0.2543,"165":-0.0516,"166":-0.1551,"167":-0.2802,"168":-0.0574,"169":-0.2133,"170":0.0928,"171":0.1061,"172":-0.0938,"174":0.2492,"175":0.0678,"177":0.1054,"178":0.2078,"179":0.1331,"181":0.3113,"183":-0.127,"184":-0.2035,"185":-0.1144,"186":0.2949,"187":0.134,"189":0.1877,"190":0.1539,"191":-0.0546,"192":0.0531,"193":-0.0869,"194":0.0769,"195":0.0666,"196":-0.0806,"197":0.1639,"198":-0.088,"199":-0.1606,"200":0.1719,"201":-0.1202,"203":-0.1811,"204":-0.1098,"205":0.2053,"206":0.0938,"207":0.3238,"208":0.0674,"210":-0.0522,"211":0.0828,"212":-0.7532,"213":0.1285,"214":-0.067,"215":-0.192,"216":-0.2144,"217":0.1118,"219":0.2469,"220":0.1716,"221":-0.2676,"222":-0.1085,"223":0.0921,"224":-0.0939,"225":-0.1114,"229":-0.0501,"230":0.2254,"231":0.0533,"233":-0.0688,"234":-0.2431,"235":-0.2553,"237":-0.1707,"238":0.1943,"239":-0.0723,"240":-0.1844,"241":0.2635,"242":-0.0674,"243":-0.0682,"245":-0.0651,"246":-0.1201,"247":-0.1402,"248":-0.0509,"249":-0.1574,"250":0.0972,"253":-0.2416,"254":-0.1169,"256":0.0644,"257":0.097,"258":-0.0749,"259":-0.0721,"260":-0.091,"261":-0.1045,"263":-0.0923,"264":-0.0521,"265":-0.186,"266":-0.1069,"267":0.4046,"269":-0.2376,"270":0.0587,"271":-0.1992,"272":0.215,"273":-0.0902,"274":0.2265,"278":0.3663,"281":-0.0849,"282":-0.0816,"284":0.222,"285":-0.1464,"286":-0.0985,"287":-0.0733,"291":-0.0804,"293":0.1758,"294":0.0502,"295":0.6811,"298":-0.0772,"299":-0.2519,"300":0.051,"301":0.177,"302":-0.1013,"304":-0.2177,"305":-0.0523,"306":-0.0571,"307":-0.0742,"308":-0.0957,"309":-0.1092,"310":0.2168,"311":-0.256,"316":0.0839,"317":-0.0842,"318":0.1426,"320":-0.0651,"321":-0.0948,"323":-0.2109,"324":-0.1878,"326":0.1958,"331":0.1545,"332":-0.0616,"333":0.2252,"334":-0.2776,"335":-0.2938,"337":-0.1363,"338":0.0524,"340":-0.0669,"342":0.0522,"343":0.3599,"344":0.1028,"345":-0.0543,"346":0.0548,"349":-0.0691,"350":-0.1445,"351":0.1495,"353":-0.0946,"354":0.0543,"355":-0.0672,"356":-0.2835,"357":-0.0765,"358":0.3261,"360":-0.1053,"361":0.5297,"362":-0.1041,"363":-0.1799,"364":-0.07,"365":-0.1488,"367":-0.0545,"368":-0.2217,"369":0.1512,"371":-0.061,"372":-0.2059,"374":-0.0953,"375":0.1217,"376":0.3252,"377":-0.243,"378":0.1635,"379":-0.1702,"380":-0.1215,"381":-0.0683,"382":-0.0886,"383":0.1503,"386":0.3071,"391":-0.3078,"392":0.0777,"393":-0.1702,"394":-0.1934,"396":-0.1039,"397":-0.1648,"398":0.1426,"399":0.1722,"401":0.1446,"403":-0.1382,"405":-0.2408,"406":0.1846,"408":-0.1229,"410":-0.0733,"411":-0.0723,"412":-0.1872,"413":-0.0732,"414":-0.129,"416":0.1406,"418":-0.1929,"419":-0.3378,"420":-0.0543,"421":0.1313,"422":-0.07,"423":-0.1645,"424":0.0556,"426":-0.1045,"427":0.1458,"428":-0.243,"429":-0.0808,"430":0.0984,"431":-0.2084,"433":0.3175,"434":-0.0608,"435":-0.0737,"436":-0.2641,"437":-0.0724,"438":0.0777,"440":0.0723,"441":-0.3707,"442":0.0637,"446":0.1328,"447":-0.0576,"448":-0.2007,"449":-0.0871,"450":-0.1077,"451":-0.0596,"452":-0.2158,"453":0.1591,"454":-0.0823,"455":-0.2744,"457":-0.1207,"458":-0.0705,"459":0.1134,"460":-0.134,"461":-0.054,"463":-0.0721,"464":-0.1298,"466":-0.2179,"467":-0.0564,"468":0.1219,"469":-0.2758,"470":-0.099,"471":-0.1929,"472":-0.1591,"473":-0.1603,"476":-0.1557,"477":-0.2113,"478":0.1158,"479":0.2839,"480":0.2607,"481":-0.1589,"482":-0.1198,"483":0.0669,"484":0.1118,"487":-0.3118,"488":-0.188,"490":0.1181,"491":0.0972,"492":-0.2038,"493":0.3208,"494":-0.3306,"495":-0.1673,"496":-0.1479,"498":-0.1173,"499":0.1747,"500":-0.1019,"503":-0.1031,"504":0.2152,"505":-0.1097,"506":-0.0664,"507":-0.072,"509":-0.1149,"510":-0.2194,"514":0.2637,"515":0.1558,"516":0.1552,"517":0.099,"520":0.0777,"521":-0.1685,"523":-0.0629,"525":-0.0951,"526":-0.2578,"527":0.2279,"528":-0.2009,"529":0.1076,"530":0.1715,"531":0.1001,"532":0.0505,"533":0.2661,"534":-0.0602,"537":-0.1525,"538":0.1281,"539":0.0986,"540":-0.1253,"541":0.0571,"542":-0.0582,"544":-0.2149,"545":-0.0725,"546":-0.094,"548":-0.0818,"552":-0.1129,"553":-0.0626,"554":-0.0655,"555":-0.0913,"557":0.0748,"559":0.1298,"561":0.2254,"562":-0.0671,"563":-0.2769,"565":-0.0897,"566":0.0615,"567":0.2083,"569":-0.1427,"571":-0.1553,"572":-0.1698,"574":-0.107,"577":-0.1351,"579":-0.0994,"581":-0.148,"583":0.0749,"586":-0.1248,"587":-0.1166,"588":-0.2144,"592":-0.1306,"593":-0.0824,"596":-0.1929,"597":0.0721,"599":0.1921,"600":-0.0732,"601":-0.1292,"602":-0.0621,"603":-0.2709,"605":-0.097,"606":-0.1101,"607":-0.2225,"609":-0.0903,"612":0.0808,"614":-0.0784,"615":-0.0887,"616":-0.1077,"618":-0.0911,"619":-0.0966,"624":-0.1136,"625":0.15,"626":0.3365,"627":0.2746,"628":0.3789,"629":-0.101,"630":-0.155,"633":-0.1726,"634":0.0726,"635":-0.1708,"636":-0.132,"637":-0.0691,"641":-0.2007,"642":-0.1598,"643":0.136,"644":0.5704,"645":-0.1201,"646":0.1986,"647":-0.1371,"648":-0.1323,"650":-0.0921,"651":-0.0894,"652":-0.0658,"653":0.2045,"655":0.1601,"656":0.3077,"657":-0.404,"658":-0.1477,"659":0.3069,"660":-0.4694,"661":0.1609,"662":0.0793,"664":-0.0978,"665":0.0902,"666":-0.1083,"667":0.3428,"668":-0.1114,"669":0.1154,"670":0.2213,"671":-0.1722,"672":-0.1208,"673":0.2102,"674":-0.1494,"675":-0.1546,"677":0.0712,"678":-0.0913,"679":0.2446,"680":-0.0885,"681":-0.09,"682":-0.2167,"683":-0.0916,"684":-0.1098,"685":0.0758,"688":0.327,"692":0.0881,"693":0.2608,"695":0.0599,"697":0.0687,"698":-0.1219,"700":0.1319,"701":-0.1084,"706":-0.0967,"707":-0.0533,"708":0.167,"709":-0.2028,"710":-0.1168,"711":0.1168,"713":0.1084,"714":-0.0544,"715":0.1365,"718":0.1721,"719":0.0529,"720":-0.1106,"721":0.0604,"722":0.1934,"724":-0.1325,"725":0.4999,"726":0.0752,"727":0.0589,"729":-0.0538,"730":0.0895,"731":0.2173,"732":0.4465,"733":0.1549,"735":-0.1519,"736":-0.158,"739":-0.086,"741":0.1205,"744":-0.1115,"748":0.0774,"750":0.1071,"753":-0.0682,"754":-0.1885,"755":0.0642,"756":0.3918,"757":-0.0809,"758":-0.123,"759":0.0946,"760":-0.3337,"761":0.1395,"762":-0.1629,"763":-0.0553,"764":0.4759,"765":-0.0779,"766":0.2362,"767":-0.1522,"768":0.0951,"769":-0.1767,"772":-0.3313,"773":-0.3235,"774":-0.259,"775":-0.1367,"776":0.1701,"777":-0.2538,"778":0.0777,"779":0.0913,"781":0.0558,"782":-0.148,"783":-0.0897,"786":-0.1754,"787":-0.132,"788":-0.0684,"789":0.0531,"790":0.1229,"791":0.0709,"792":-0.199,"793":-0.3877,"794":0.2189,"796":-0.1054,"797":0.2238,"798":-0.1772,"800":-0.1452,"801":-0.1892,"802":0.1846,"806":-0.2428,"807":-0.1463,"808":0.5381,"809":-0.1457,"810":0.6315,"811":-0.0646,"812":0.1404,"813":0.6703,"814":0.0564,"815":-0.0715,"816":-0.0996,"818":0.1866,"819":0.0783,"822":-0.0693,"824":0.1118,"825":0.2671,"826":-0.1034,"827":0.2691,"828":-0.0812,"829":0.1207,"831":0.5868,"833":-0.0602,"835":-0.0537,"836":-0.488,"837":-0.0843,"838":-0.1916,"839":-0.1205,"840":-0.0595,"842":0.0616,"843":0.1729,"844":-0.1564,"845":0.1128,"846":0.1247,"847":-0.0603,"848":-0.0873,"849":-0.0818,"850":-0.1428,"851":-0.0762,"854":0.3338,"856":-0.0638,"857":0.0668,"858":-0.1182,"859":-0.3004,"860":0.0781,"861":-0.1286,"862":-0.1499,"863":-0.2636,"865":0.2002,"866":-0.1876,"867":-0.2295,"868":0.0525,"869":-0.2416,"870":-0.1567,"871":0.0679,"873":-0.0807,"874":0.0842,"876":-0.3182,"877":0.1332,"879":0.2517,"881":0.173,"883":0.0751,"885":0.2453,"886":-0.1471,"888":-0.0647,"889":0.1258,"891":0.0698,"892":-0.0629,"894":-0.098,"895":-0.0757,"897":-0.1586,"898":-0.1515,"899":-0.2746,"900":0.1802,"903":0.0789,"904":0.112,"905":-0.06,"906":0.1049,"907":0.1384,"908":-0.2704,"910":-0.0573,"912":-0.125,"913":-0.1462,"914":-0.1736,"915":0.1518,"917":0.0582,"919":0.2134,"922":-0.1901,"924":-0.0795,"925":-0.1191,"926":0.213,"927":-0.1456,"928":-0.1285,"929":-0.1733,"930":-0.0655,"932":-0.0799,"933":-0.0911,"934":0.1402,"935":-0.0787,"936":-0.197,"937":-0.2142,"938":0.089,"939":-0.1563,"940":-0.2234,"941":0.0511,"942":-0.1649,"944":0.3935,"945":-0.1212,"946":-0.1103,"947":-0.1313,"949":-0.0896,"950":0.1864,"951":0.2925,"953":0.0611,"956":-0.092,"958":-0.0724,"959":-0.0818,"960":-0.1929,"961":0.0699,"963":0.0831,"964":0.0987,"965":-0.0552,"966":-0.0656,"968":0.5411,"969":-0.0805,"971":-0.2593,"973":0.0543,"975":-0.0816,"976":-0.0922,"977":-0.122,"978":0.4181,"979":-0.2563,"980":-0.2142,"981":-0.285,"982":0.0918,"983":0.1505,"984":0.2232,"987":-0.3704,"988":0.1522,"989":0.155,"990":-0.0773,"991":0.2993,"993":-0.0866,"994":-0.1711,"996":0.1203,"997":0.3545,"998":-0.1503,"999":0.1326,"1002":0.0932,"1003":0.0521,"1007":0.0659,"1008":0.1009,"1009":0.0583,"1012":-0.0891,"1013":0.2848,"1014":-0.2082,"1015":-0.3354,"1016":-0.105,"1017":-0.2143,"1018":-0.1008,"1020":-0.1533,"1021":-0.1354,"1022":0.103,"1023":-0.1568,"1024":-0.3678,"1025":-1.5143,"1026":-0.5319,"1027":-0.3331,"1028":-1.3845,"1029":-0.3903,"1030":-0.142,"1031":0.3356},"threshold":0.5},"SOURCE_CODE":{"bias":-0.3362,"w":{"0":-0.1652,"4":0.1779,"5":0.1483,"6":-0.0845,"7":-0.0911,"9":-0.057,"13":-0.0663,"14":-0.2302,"18":-0.0647,"20":-0.15,"25":-0.069,"27":0.2558,"28":-0.0719,"30":-0.0624,"31":-0.0802,"33":-0.06,"34":-0.0847,"35":-0.0969,"37":0.071,"38":-0.1481,"40":-0.0568,"49":-0.0891,"50":-0.0695,"52":-0.0698,"60":-0.0559,"61":-0.1121,"62":0.0706,"72":0.0959,"74":-0.1246,"80":-0.0659,"82":-0.0599,"83":-0.1311,"84":-0.0749,"86":0.0555,"87":0.3055,"89":-0.1192,"90":-0.0941,"91":0.0817,"92":0.1674,"93":-0.0631,"94":-0.0757,"95":-0.1293,"98":0.1247,"99":0.0932,"102":-0.1655,"105":-0.0696,"106":-0.2269,"110":0.0671,"112":-0.0998,"123":-0.0622,"124":-0.0917,"126":-0.0637,"129":-0.1948,"130":-0.0808,"135":0.084,"137":0.1049,"138":-0.1305,"140":0.1026,"141":-0.0551,"142":-0.08,"147":-0.1104,"149":-0.0812,"151":0.18,"152":-0.0594,"154":0.0654,"155":0.0571,"157":-0.0584,"158":-0.0546,"160":-0.1665,"163":-0.3358,"164":-0.0587,"168":-0.0818,"169":-0.1565,"170":0.0761,"172":-0.105,"173":-0.0627,"179":-0.1378,"180":-0.1286,"183":-0.1986,"184":-0.0577,"185":-0.1045,"186":-0.1085,"196":-0.1512,"198":0.0631,"200":-0.1074,"201":-0.1069,"203":-0.1535,"204":-0.1067,"207":-0.0673,"209":-0.0548,"212":-0.1892,"213":-0.1044,"215":-0.0819,"216":-0.0714,"217":-0.0894,"219":0.3093,"221":-0.1077,"224":-0.0586,"225":0.2281,"226":-0.0868,"229":-0.0748,"230":-0.3249,"231":0.0938,"232":-0.1258,"233":-0.0535,"236":-0.0924,"237":-0.1497,"239":-0.1895,"242":-0.0608,"244":-0.0813,"245":0.1696,"246":-0.0899,"247":-0.1967,"249":-0.2761,"251":-0.1008,"253":0.0664,"254":0.0706,"257":-0.0754,"259":-0.0667,"262":-0.0762,"263":0.0601,"264":0.3184,"265":0.128,"267":-0.2365,"268":-0.0514,"271":-0.0654,"272":-0.0514,"274":-0.058,"278":-0.1189,"279":-0.0519,"283":-0.0902,"285":-0.0614,"293":-0.1398,"295":0.0695,"296":0.0548,"298":-0.0636,"299":-0.1023,"300":0.11,"308":-0.0568,"309":-0.1326,"311":-0.1176,"318":-0.0531,"322":0.078,"323":0.1128,"324":0.1023,"325":0.1165,"327":-0.0621,"332":0.0809,"334":-0.072,"335":0.097,"338":0.0603,"343":0.1127,"344":-0.0569,"347":0.0861,"348":-0.0526,"350":-0.0554,"353":-0.0833,"360":-0.12,"361":-0.0753,"362":-0.0972,"363":0.0965,"367":0.0833,"372":0.1019,"374":-0.0937,"376":-0.1063,"377":-0.1051,"379":-0.0968,"381":-0.0579,"382":0.2274,"383":-0.1027,"384":-0.0579,"386":-0.1249,"387":0.0593,"388":0.0812,"390":0.1155,"393":0.0957,"394":0.3207,"397":0.261,"398":0.0684,"400":0.0738,"404":0.0696,"405":0.1345,"407":0.0619,"411":0.0572,"412":-0.0553,"413":-0.0511,"418":0.6121,"419":-0.1269,"420":-0.069,"423":-0.0511,"424":-0.0651,"427":-0.112,"430":-0.0906,"431":-0.0634,"434":-0.0815,"436":0.1641,"438":-0.052,"439":-0.0944,"441":-0.0862,"442":-0.06,"446":-0.1053,"448":-0.0836,"449":-0.0923,"450":0.1,"452":-0.1954,"457":0.0514,"460":0.0737,"461":0.0969,"464":0.4094,"466":-0.1122,"467":0.1565,"469":-0.0801,"470":0.1036,"471":0.1026,"473":-0.0505,"476":-0.0644,"477":0.3927,"480":-0.1305,"481":-0.0895,"485":-0.0551,"488":-0.0591,"490":-0.1356,"491":-0.0604,"492":-0.0979,"493":-0.1029,"494":-0.0821,"495":0.1352,"496":-0.0638,"498":-0.1504,"499":-0.1348,"503":-0.0804,"505":-0.0518,"506":-0.0891,"510":-0.072,"516":-0.0537,"517":-0.0605,"519":0.0592,"521":-0.115,"524":0.0702,"528":-0.1242,"531":-0.0596,"532":-0.056,"538":-0.0807,"541":0.0834,"544":-0.0607,"555":-0.0543,"556":0.1564,"558":-0.0638,"559":-0.0568,"560":-0.13,"563":-0.0592,"565":0.182,"566":-0.0881,"569":0.109,"572":-0.0502,"575":-0.0814,"576":-0.0861,"578":-0.062,"579":-0.1463,"581":-0.0667,"584":-0.1044,"585":0.0687,"587":-0.0656,"591":0.0835,"601":0.0834,"607":-0.092,"609":-0.0876,"614":-0.0536,"619":-0.096,"622":0.0724,"628":-0.0995,"629":-0.0987,"630":-0.0682,"631":0.0505,"632":0.1657,"634":0.0853,"640":0.1202,"643":-0.1707,"644":-0.4548,"645":-0.1936,"646":-0.0609,"649":-0.1063,"650":-0.0744,"651":0.1744,"654":0.0919,"655":0.1514,"656":-0.1188,"657":-0.0842,"658":-0.169,"659":-0.1091,"660":-0.1072,"663":-0.0984,"665":-0.1245,"666":-0.128,"668":-0.05,"669":0.0855,"671":-0.1092,"678":-0.0694,"681":-0.165,"682":-0.0692,"685":-0.0751,"686":0.0805,"688":-0.0712,"689":0.145,"690":-0.0565,"691":-0.0735,"693":0.0641,"695":0.0873,"696":0.0658,"697":-0.1054,"698":0.1448,"706":0.0515,"707":-0.0536,"711":0.1189,"712":-0.0653,"713":0.0832,"715":0.1067,"721":-0.087,"723":-0.1772,"724":-0.0796,"725":-0.0625,"726":-0.0578,"730":-0.1009,"732":-0.5128,"734":0.1092,"735":0.1139,"736":-0.0501,"740":-0.0585,"742":0.1813,"744":-0.0523,"746":0.1734,"747":-0.0502,"750":-0.07,"754":-0.0586,"756":-0.1206,"757":-0.1316,"761":-0.1001,"762":-0.0571,"765":-0.1053,"766":-0.0647,"769":-0.1726,"772":0.0709,"774":-0.118,"775":-0.0731,"777":0.2158,"778":0.186,"781":-0.132,"782":-0.3401,"788":-0.1091,"789":-0.1712,"790":0.2862,"791":-0.0699,"792":-0.1471,"793":0.0592,"794":-0.1272,"796":-0.2103,"797":-0.0892,"802":-0.1833,"806":-0.1434,"807":0.1991,"808":0.2381,"809":0.1879,"813":-0.1755,"815":-0.0743,"816":0.0907,"818":0.0786,"819":-0.1945,"822":-0.0589,"826":-0.0573,"827":-0.3056,"828":0.0941,"829":-0.0838,"831":-0.29,"832":-0.0691,"836":-0.1799,"837":0.1365,"838":-0.2267,"840":-0.0937,"843":-0.1022,"844":-0.1096,"847":-0.0702,"848":0.1213,"849":-0.084,"851":-0.0842,"854":-0.07,"858":0.1244,"859":0.1587,"860":-0.0635,"862":-0.0866,"863":-0.0677,"865":-0.3223,"866":-0.1172,"869":-0.0827,"870":-0.0543,"871":0.0681,"875":0.0799,"876":-0.1683,"877":-0.2068,"881":0.1554,"882":-0.0689,"886":0.1013,"889":0.0874,"890":-0.0875,"893":0.0709,"894":0.0847,"896":0.0633,"897":0.1273,"898":-0.0634,"900":-0.059,"902":-0.0617,"908":-0.0666,"910":-0.0568,"911":-0.0619,"912":-0.0792,"913":-0.0647,"914":-0.0836,"915":-0.0587,"917":-0.0715,"919":-0.053,"921":-0.0746,"922":-0.0839,"923":-0.0552,"924":-0.0646,"925":-0.0932,"926":-0.1516,"928":-0.1862,"931":0.1794,"933":-0.0707,"935":0.315,"936":-0.1215,"937":-0.052,"939":-0.0794,"940":-0.0892,"942":-0.1031,"944":-0.1673,"945":0.3466,"946":0.0514,"947":-0.117,"955":-0.058,"958":-0.235,"965":-0.148,"968":-0.1018,"970":-0.0655,"971":-0.0775,"972":0.1157,"974":0.0908,"975":-0.0582,"976":0.1103,"977":-0.0695,"978":-0.0917,"979":-0.1298,"981":-0.091,"983":-0.1022,"984":-0.2149,"986":-0.0694,"987":-0.1147,"992":-0.0532,"993":-0.0513,"994":-0.1585,"997":-0.1021,"998":-0.1412,"1000":0.0671,"1002":-0.0623,"1004":-0.061,"1010":-0.0519,"1013":0.115,"1014":0.351,"1015":-0.1329,"1021":-0.0799,"1022":-0.127,"1024":0.5321,"1025":1.8051,"1026":0.7074,"1027":0.8992,"1028":2.945,"1030":0.4342,"1031":-3.2613},"threshold":0.5},"LEGAL_CONTRACT":{"bias":-2.304,"w":{"1":0.0818,"2":-0.2515,"3":-0.0969,"5":-0.3744,"7":0.1177,"8":0.1012,"12":0.1085,"16":-0.3305,"17":0.1496,"18":0.0628,"20":0.1751,"22":-0.1413,"24":-0.0876,"25":0.1632,"26":-0.0802,"27":-0.1817,"30":-0.1465,"31":0.1309,"32":-0.1703,"33":-0.1395,"34":-0.3149,"35":0.1657,"36":-0.2062,"37":-0.0701,"38":-0.1792,"39":-0.0885,"40":-0.1641,"42":-0.1064,"43":-0.0622,"44":0.2624,"45":-0.0745,"46":-0.1227,"47":0.1103,"49":0.618,"50":0.1502,"53":-0.0908,"54":-0.0676,"55":-0.0945,"56":-0.056,"57":-0.2036,"58":-0.1054,"60":0.4068,"61":0.6664,"62":-0.0948,"63":0.2787,"64":-0.131,"66":-0.2247,"70":-0.2737,"73":0.1583,"74":-0.2774,"75":0.1346,"78":-0.2281,"79":-0.1372,"81":-0.0576,"82":0.0785,"83":0.0966,"84":-0.2733,"85":-0.1083,"86":-0.164,"87":-0.1177,"88":-0.0716,"89":0.0781,"90":0.2313,"91":0.1029,"92":-0.0958,"93":-0.1262,"95":-0.2184,"97":0.1686,"98":0.1161,"99":-0.1488,"101":-0.0786,"102":0.1127,"103":-0.065,"104":-0.0533,"105":-0.0789,"106":-0.2619,"107":-0.1155,"109":0.064,"110":-0.3513,"111":0.2695,"112":0.0829,"113":0.0512,"115":0.1147,"116":0.144,"117":-0.1287,"118":0.1948,"119":-0.0532,"121":-0.0892,"123":-0.2138,"124":0.4613,"125":-0.0695,"126":0.13,"128":0.1295,"129":-0.5575,"130":-0.2998,"132":-0.1931,"133":-0.239,"135":-0.0802,"136":-0.0881,"137":0.2006,"138":-0.1505,"139":-0.0618,"142":-0.1038,"144":-0.0601,"145":0.0815,"146":0.126,"147":-0.2312,"148":-0.0659,"149":0.4261,"150":-0.1457,"151":-0.1109,"152":0.0955,"153":0.6469,"154":-0.1011,"156":0.1418,"157":0.206,"158":-0.1993,"159":-0.0677,"160":-0.0975,"161":0.0883,"162":0.1692,"163":0.4308,"165":0.1585,"167":0.3965,"169":0.7092,"170":-0.3211,"171":0.5157,"172":0.1182,"173":-0.2069,"174":-0.1405,"175":-0.0731,"176":-0.0502,"179":-0.3749,"180":0.25,"181":-0.0557,"182":-0.1757,"184":-0.1567,"185":0.3172,"186":-0.0761,"187":-0.0819,"188":0.0701,"189":-0.1145,"190":0.0673,"191":0.055,"192":0.1837,"193":0.2484,"194":-0.1209,"195":0.0571,"196":-0.1074,"197":-0.1166,"202":0.264,"203":0.5609,"204":0.438,"205":-0.2012,"207":0.2237,"209":-0.0592,"212":0.2776,"213":-0.1295,"214":-0.0659,"215":-0.1434,"216":0.2095,"217":-0.2833,"218":-0.1978,"219":-0.195,"220":-0.0704,"221":0.1136,"222":0.124,"223":0.0513,"224":0.4179,"226":-0.0752,"227":-0.1058,"229":0.2919,"230":-0.0905,"231":-0.1659,"232":0.0857,"233":-0.309,"234":0.3345,"235":0.0616,"236":0.1631,"237":0.2085,"238":0.0642,"239":-0.1186,"240":-0.1189,"241":-0.0825,"242":-0.1009,"243":0.2495,"244":0.1321,"245":-0.0871,"246":0.4375,"247":0.171,"249":0.9997,"250":-0.1287,"251":-0.2226,"252":-0.0968,"254":0.5441,"257":-0.1189,"259":0.3811,"262":0.2126,"263":-0.065,"264":0.0783,"265":-0.0912,"266":-0.1116,"267":0.3216,"268":0.159,"269":0.5288,"270":-0.1162,"271":0.355,"272":-0.1558,"273":-0.0656,"275":-0.0965,"276":0.095,"277":-0.0709,"278":-0.1806,"283":0.0809,"284":-0.0576,"285":0.0814,"286":-0.0966,"287":0.0841,"288":-0.146,"290":-0.0589,"291":-0.0827,"292":-0.0907,"293":-0.3529,"295":-0.3,"296":0.2141,"297":0.0639,"298":-0.0795,"299":0.7615,"301":-0.071,"302":-0.1375,"303":-0.0532,"304":0.2527,"305":0.1395,"307":0.0709,"309":-0.3695,"311":0.5017,"314":0.0598,"315":-0.1107,"316":-0.1101,"317":0.2299,"319":-0.0951,"320":-0.102,"321":-0.1441,"322":-0.2325,"323":-0.0781,"324":0.1266,"325":-0.1407,"328":-0.1341,"329":-0.094,"330":0.176,"331":-0.1428,"332":-0.0578,"333":0.1099,"334":0.2645,"335":0.497,"337":-0.0945,"338":-0.074,"340":-0.0681,"341":0.1518,"343":-0.19,"344":-0.0991,"345":0.2088,"346":-0.0627,"348":-0.176,"349":0.3386,"350":0.0955,"351":-0.137,"352":-0.1344,"354":-0.1298,"355":-0.0621,"356":-0.0578,"357":0.2274,"358":-0.0726,"359":0.0791,"360":-0.3089,"361":-0.1985,"362":0.1051,"363":-0.3686,"364":-0.1232,"367":0.0701,"368":-0.1162,"369":-0.1184,"371":-0.0556,"372":0.4624,"373":-0.0675,"374":0.1904,"376":-0.0742,"377":0.2947,"378":-0.1065,"380":0.1918,"382":-0.1519,"385":0.056,"387":-0.3872,"388":0.0593,"389":-0.1279,"391":-0.1711,"393":0.2516,"394":0.1046,"396":-0.1548,"397":0.1125,"398":-0.1983,"400":-0.1177,"403":0.0543,"404":-0.065,"405":-0.2612,"406":-0.0851,"411":-0.1288,"412":-0.2196,"413":0.1856,"414":0.1856,"416":0.0549,"418":-0.1511,"419":0.6008,"420":0.0819,"422":-0.0739,"425":-0.181,"426":0.12,"427":-0.2229,"428":0.1501,"429":0.2421,"430":-0.1875,"431":-0.2118,"433":-0.1248,"434":-0.2073,"435":-0.0629,"436":0.2554,"437":-0.0524,"438":0.2759,"439":0.1122,"442":0.1439,"443":0.284,"444":0.0574,"445":-0.1873,"446":-0.1581,"448":0.4586,"449":0.2131,"450":0.0775,"451":-0.1856,"453":-0.0655,"454":-0.0782,"455":0.4329,"457":0.0813,"458":0.0625,"459":0.0617,"461":-0.1023,"463":-0.1214,"466":-0.2934,"467":-0.0732,"468":-0.0732,"469":-0.2799,"470":-0.2476,"471":-0.111,"472":0.1888,"473":0.2928,"474":-0.0947,"476":-0.102,"477":-0.2193,"478":-0.1536,"479":-0.2031,"480":0.2498,"483":0.098,"484":-0.0561,"485":-0.0527,"487":-0.2246,"488":-0.18,"490":0.403,"491":-0.057,"492":-0.0708,"493":-0.2059,"494":-0.2837,"495":-0.0764,"496":-0.1988,"497":-0.0522,"498":-0.2644,"499":-0.1102,"500":-0.0837,"502":0.0551,"503":-0.2305,"504":-0.0923,"508":-0.2292,"509":0.2051,"511":0.0577,"512":-0.1467,"513":-0.1095,"514":0.0667,"515":-0.1649,"516":-0.092,"518":-0.0534,"519":-0.124,"520":-0.0547,"521":0.3604,"524":-0.1526,"525":0.0561,"526":0.2849,"527":-0.0562,"528":-0.32,"529":0.1186,"530":-0.1291,"531":-0.2717,"532":-0.1756,"534":-0.0572,"535":0.1197,"536":-0.1536,"537":-0.1165,"538":-0.2599,"540":-0.0826,"541":-0.3168,"542":-0.0502,"544":0.2307,"545":-0.057,"546":0.2621,"547":0.1491,"549":-0.123,"550":-0.1318,"551":-0.1226,"552":0.0833,"553":0.0993,"554":-0.1171,"555":0.1366,"556":-0.0625,"557":-0.2073,"559":-0.1774,"561":-0.1731,"562":-0.1426,"563":0.3632,"564":0.0827,"566":0.1588,"567":0.2665,"568":0.1424,"571":-0.138,"572":-0.1851,"574":0.1061,"577":-0.1187,"580":-0.052,"581":0.3716,"582":-0.0557,"584":0.0572,"585":0.163,"587":-0.1376,"590":0.0656,"591":0.0653,"597":-0.0713,"599":-0.1081,"600":0.0887,"601":0.3209,"602":-0.1246,"603":0.3149,"605":-0.0821,"606":0.1325,"607":-0.1943,"609":0.4182,"612":0.0969,"613":-0.0544,"614":0.1953,"615":0.1026,"618":-0.0802,"619":0.4633,"621":-0.0649,"623":0.085,"624":-0.2693,"625":-0.1218,"626":-0.1427,"627":-0.1389,"628":-0.1924,"629":0.6611,"630":0.2394,"631":0.0718,"633":-0.2026,"634":-0.1152,"635":0.0748,"636":0.3589,"637":0.1296,"639":0.0562,"643":-0.1538,"644":0.6115,"647":-0.3547,"648":0.182,"649":0.0897,"650":0.0794,"654":-0.058,"655":-0.1651,"656":-0.2205,"657":-0.1002,"658":-0.0681,"659":0.1706,"660":0.5542,"661":0.1476,"662":-0.0723,"666":-0.2522,"670":-0.2593,"671":-0.107,"672":-0.1106,"673":0.0552,"674":-0.066,"675":0.2157,"676":0.1737,"677":-0.1875,"678":0.0758,"679":-0.0721,"680":-0.0519,"681":0.0658,"682":0.0571,"684":-0.052,"685":0.2224,"687":0.1577,"688":0.1298,"690":-0.1212,"691":0.2943,"692":0.2713,"693":0.1361,"694":-0.1472,"695":-0.0817,"696":-0.1103,"697":-0.2185,"698":-0.0788,"699":0.1565,"701":0.0814,"703":-0.0624,"704":-0.0886,"705":0.1516,"706":0.4951,"707":-0.1041,"710":-0.1792,"711":-0.0935,"714":-0.0556,"715":-0.0535,"716":-0.0558,"718":-0.238,"719":-0.2229,"720":-0.2266,"722":-0.1284,"723":0.1092,"724":0.098,"725":-0.1739,"726":-0.1258,"731":-0.1707,"732":0.5158,"733":-0.1432,"734":0.9487,"735":-0.0523,"737":0.1966,"739":-0.0614,"741":-0.0539,"742":-0.2337,"743":0.0889,"744":0.2048,"749":0.1018,"750":-0.1823,"752":0.0791,"754":0.0949,"756":-0.2491,"758":0.0542,"759":0.0616,"760":0.865,"761":0.1848,"762":-0.1584,"763":-0.151,"765":-0.0852,"766":-0.1166,"767":-0.2279,"768":-0.1113,"770":0.1041,"771":-0.166,"772":0.1543,"773":0.4336,"774":0.2887,"775":0.1346,"776":-0.057,"777":0.3844,"778":-0.2096,"780":0.0881,"781":0.1311,"782":0.3842,"785":-0.0625,"786":0.4946,"787":0.2163,"788":0.1191,"790":-0.3145,"791":0.1072,"792":0.0519,"793":-0.2778,"794":0.1785,"796":0.1706,"797":-0.0581,"798":0.2489,"799":0.0807,"800":0.1843,"801":0.1353,"802":0.2246,"803":-0.1899,"804":-0.1298,"805":0.0869,"807":-0.1993,"808":-0.2833,"810":-0.2602,"811":0.2068,"813":-0.3433,"815":0.0972,"816":-0.101,"819":0.1523,"820":-0.0848,"821":-0.0697,"822":-0.0547,"823":-0.0907,"824":-0.144,"825":-0.1186,"827":0.2525,"828":0.063,"829":0.1979,"831":0.4664,"832":-0.1578,"833":0.1697,"835":-0.0716,"836":0.1349,"837":-0.0701,"838":-0.1437,"839":-0.1985,"840":0.2888,"841":0.0633,"843":-0.1726,"844":0.1899,"846":-0.0794,"850":-0.099,"851":0.0658,"852":-0.0944,"853":-0.0844,"854":-0.2134,"855":-0.063,"856":0.0516,"857":-0.0874,"858":0.1153,"859":0.4489,"860":0.1615,"862":-0.0585,"863":0.788,"864":0.109,"865":0.2723,"866":0.3264,"867":0.8743,"868":-0.0905,"869":-0.1616,"870":-0.2105,"871":-0.068,"872":-0.0562,"873":0.1771,"874":0.0552,"875":-0.1203,"876":1.4382,"877":0.2661,"878":-0.0932,"880":-0.0788,"881":-0.1308,"884":-0.1744,"885":-0.1639,"886":-0.2592,"887":0.1395,"888":0.2788,"890":-0.0715,"893":-0.0831,"894":-0.2523,"895":-0.0568,"896":0.1191,"897":0.1024,"899":-0.1431,"900":0.26,"901":-0.082,"902":-0.1939,"904":-0.112,"905":-0.1619,"906":0.1271,"907":-0.075,"908":0.0881,"909":0.0735,"910":-0.0876,"911":0.1111,"912":0.194,"913":0.0608,"914":0.0951,"915":-0.0963,"916":-0.1367,"917":0.4357,"918":0.1333,"920":0.0615,"921":0.1082,"922":-0.2339,"923":-0.1283,"925":0.406,"926":0.1944,"927":0.2582,"928":0.3045,"930":0.0577,"931":-0.1672,"933":0.0676,"935":0.2728,"936":0.2689,"937":0.1511,"938":0.0634,"939":-0.2272,"940":-0.1183,"943":0.2533,"944":0.1793,"945":-0.2076,"946":-0.1185,"947":0.3274,"948":-0.0877,"949":0.2201,"950":-0.1416,"951":-0.2097,"952":-0.1219,"954":0.134,"957":0.238,"958":-0.3038,"959":0.1488,"963":-0.1262,"964":-0.0788,"965":-0.0517,"966":-0.0751,"969":-0.0713,"971":0.2601,"973":-0.1238,"974":-0.0802,"975":-0.115,"976":0.2872,"977":0.3333,"978":0.1033,"979":0.3578,"983":-0.128,"984":0.2671,"985":-0.0637,"986":-0.1221,"988":0.1816,"990":-0.1345,"993":0.2016,"994":0.435,"995":0.3155,"996":-0.0891,"998":-0.2853,"999":-0.146,"1000":-0.052,"1002":-0.1126,"1003":-0.0721,"1006":0.0575,"1007":-0.0649,"1008":-0.1884,"1010":0.1042,"1011":-0.1173,"1012":-0.0768,"1013":-0.2447,"1014":-0.0553,"1015":-0.1012,"1016":-0.1561,"1017":0.1011,"1018":0.0708,"1020":-0.0584,"1021":0.3502,"1022":-0.1574,"1023":0.1033,"1024":-0.4957,"1025":-1.5473,"1026":0.2654,"1027":-0.4157,"1029":-0.349,"1030":-0.1749,"1031":0.2981},"threshold":0.5},"CREDENTIALS":{"bias":-1.0006,"w":{"0":0.2506,"2":0.3697,"3":-0.1865,"5":-0.3213,"6":0.086,"7":-0.0741,"8":-0.11,"9":-0.054,"10":-0.0946,"11":-0.0797,"12":-0.1161,"14":-0.262,"15":-0.1106,"16":0.0502,"18":-0.3091,"19":0.1083,"20":-0.2059,"21":-0.2493,"22":-0.1478,"23":-0.1673,"24":-0.0764,"25":0.0904,"26":0.1203,"27":0.0695,"28":0.278,"30":-0.2241,"32":0.0986,"34":-0.0943,"35":0.0511,"36":0.1376,"37":-0.0722,"38":0.1578,"39":-0.0814,"40":0.4295,"41":-0.0985,"42":0.2727,"43":-0.1191,"44":-0.1407,"47":-0.1116,"49":-0.3188,"50":-0.1397,"52":-0.2206,"53":0.3383,"54":0.1386,"55":0.1963,"57":-0.1725,"58":0.1418,"59":0.078,"60":-0.187,"61":-0.3107,"62":-0.0832,"63":-0.0837,"64":-0.1227,"67":0.222,"69":0.1068,"70":1.1079,"71":-0.0521,"72":-0.1233,"73":-0.1534,"74":0.1318,"75":-0.1366,"76":0.0855,"77":-0.1464,"78":0.0836,"79":0.1165,"80":-0.2103,"81":-0.0501,"82":-0.139,"83":-0.1972,"84":-0.1023,"86":-0.1982,"88":-0.1128,"89":-0.0916,"90":-0.1423,"91":-0.1273,"92":-0.0652,"93":-0.3369,"94":-0.1614,"95":0.2934,"97":-0.1651,"98":-0.1403,"99":0.1192,"101":-0.1029,"102":0.1147,"105":0.0719,"106":0.3387,"107":0.2944,"108":0.2473,"109":0.1651,"111":-0.0735,"112":-0.2944,"113":-0.1062,"114":-0.0589,"115":-0.1379,"116":-0.4219,"117":-0.1531,"118":-0.0609,"119":-0.2168,"120":-0.1746,"123":0.1371,"124":-0.1454,"125":-0.058,"128":-0.1097,"130":-0.2597,"132":-0.2932,"133":0.2695,"136":-0.1101,"137":-0.1998,"138":-0.4051,"139":-0.0524,"140":-0.1189,"141":0.2679,"142":-0.1086,"143":0.1755,"144":-0.0568,"145":0.0722,"146":-0.1159,"147":-0.4526,"148":-0.0729,"149":-0.0864,"150":-0.1393,"151":-0.0716,"152":0.0942,"153":-0.3213,"154":0.0882,"155":-0.2859,"156":-0.1594,"157":-0.1922,"158":0.7242,"159":0.2365,"161":-0.0919,"163":-0.5723,"164":0.0764,"167":-0.3181,"169":-0.3137,"170":-0.2498,"171":-0.2536,"172":0.0977,"173":0.0865,"174":-0.1213,"175":0.0729,"178":-0.1139,"180":0.0717,"181":-0.1503,"183":0.4099,"184":-0.133,"186":-0.0627,"187":-0.0707,"189":-0.3817,"190":-0.1346,"192":-0.0927,"193":-0.0605,"195":-0.2616,"196":0.3187,"198":0.1523,"199":-0.2398,"200":-0.2673,"201":0.201,"204":-0.2997,"205":-0.1881,"206":-0.2346,"207":0.063,"208":-0.0668,"209":0.1259,"210":-0.0972,"211":-0.0516,"212":-0.6891,"213":0.1459,"215":-0.163,"217":0.1184,"218":0.1096,"219":-0.2396,"221":-0.1388,"222":0.0521,"223":-0.1203,"224":-0.1885,"228":-0.1914,"229":-0.0914,"230":0.0573,"231":-0.0704,"232":-0.1463,"233":0.4284,"234":-0.3581,"235":-0.1813,"236":0.1959,"238":-0.218,"239":-0.153,"240":0.2487,"241":-0.129,"243":-0.0827,"245":-0.0947,"246":-0.0514,"247":-0.1179,"248":-0.1183,"249":-0.1763,"251":-0.1603,"252":-0.0542,"254":-0.2363,"255":0.1147,"256":-0.0565,"258":-0.0619,"260":-0.0713,"261":-0.1031,"262":-0.076,"263":0.1457,"264":-0.1759,"267":-0.2302,"268":0.1176,"271":-0.0785,"273":0.4337,"275":0.1134,"277":0.0669,"278":0.072,"281":-0.0671,"283":-0.2235,"284":-0.1297,"285":0.1964,"286":0.1835,"287":0.0788,"288":-0.1096,"290":-0.0507,"291":0.1628,"292":0.1908,"293":-0.1831,"294":0.1548,"295":-0.2734,"296":-0.1506,"298":-0.1407,"299":-0.3332,"300":-0.1213,"301":-0.0666,"304":0.2035,"306":0.2354,"307":-0.2068,"308":0.1207,"309":0.2562,"310":-0.1959,"315":0.0709,"316":0.0885,"317":-0.0742,"318":0.1612,"319":-0.1142,"320":-0.0724,"321":0.4316,"322":-0.1028,"325":0.1136,"326":-0.0742,"328":0.2595,"330":-0.0888,"331":0.0731,"332":-0.1084,"333":-0.1948,"334":-0.2447,"335":-0.2464,"337":-0.2163,"338":-0.1188,"339":-0.117,"340":0.0969,"341":-0.1352,"342":-0.0696,"343":-0.161,"344":-0.2224,"345":-0.0706,"348":0.1653,"349":-0.0914,"352":0.2377,"353":0.1437,"354":0.0538,"355":-0.0588,"356":0.0921,"357":-0.1417,"360":0.2823,"362":0.2385,"363":0.1638,"364":0.2157,"368":0.3868,"369":-0.1649,"371":0.1381,"372":-0.1087,"373":0.0813,"374":0.1641,"377":0.15,"378":-0.0709,"379":0.0576,"380":-0.1371,"381":0.1605,"382":0.1116,"383":0.3614,"385":-0.07,"386":-0.16,"387":0.1572,"389":-0.1091,"390":-0.2421,"391":0.3436,"394":-0.1853,"396":0.168,"397":-0.1468,"399":-0.1016,"400":0.1658,"401":-0.1308,"403":0.0526,"404":-0.1007,"405":0.5427,"407":-0.1044,"408":0.0836,"411":0.2215,"412":0.0817,"413":-0.0864,"414":0.0942,"415":0.2643,"418":-0.3254,"419":-0.0934,"420":0.0649,"421":-0.0763,"423":0.0907,"425":0.1738,"426":-0.0746,"427":0.3801,"429":-0.0678,"430":-0.1439,"431":0.3452,"433":-0.0988,"434":0.2814,"435":0.0642,"436":-0.3835,"438":-0.2152,"439":-0.1301,"440":-0.0693,"443":-0.1159,"445":-0.1232,"446":0.0659,"448":-0.1909,"449":-0.053,"450":-0.1849,"451":-0.1524,"452":-0.3824,"453":-0.0759,"454":0.1375,"455":-0.2139,"456":-0.0624,"457":-0.0993,"459":-0.1842,"460":-0.1589,"461":-0.1419,"462":-0.1598,"463":-0.0544,"464":-0.0702,"466":0.4234,"467":-0.0584,"468":0.0774,"469":0.1208,"470":-0.1289,"471":0.2957,"472":-0.1287,"473":-0.1527,"475":-0.1317,"477":-0.3885,"478":-0.0663,"479":-0.2252,"480":-0.3453,"481":-0.0602,"482":-0.051,"483":-0.2362,"484":-0.0955,"485":0.1662,"487":0.5541,"488":0.5683,"490":0.1028,"491":0.0814,"492":0.5703,"493":0.2247,"494":-0.2538,"496":-0.2464,"498":0.3031,"499":0.3136,"502":0.0759,"503":-0.2448,"504":-0.0877,"505":0.1288,"508":0.0876,"509":-0.1487,"510":0.1951,"512":0.145,"513":-0.0889,"514":-0.0987,"515":-0.1371,"516":0.0506,"518":0.0847,"521":0.3293,"524":0.2257,"525":-0.0798,"528":0.6233,"529":-0.1211,"530":0.2082,"531":-0.1641,"532":0.3679,"533":-0.1284,"535":-0.1182,"536":0.1362,"537":-0.1324,"538":-0.1695,"540":-0.1672,"541":-0.2878,"542":0.2303,"544":-0.1836,"545":0.235,"546":-0.0591,"548":0.1566,"549":0.1544,"550":0.2222,"551":0.1653,"553":-0.114,"556":-0.0583,"557":-0.111,"558":-0.138,"560":0.1301,"561":-0.1452,"562":-0.1038,"563":-0.1883,"565":-0.0781,"567":-0.1421,"568":-0.0925,"569":0.197,"570":0.0844,"571":-0.1117,"572":0.1756,"573":-0.1469,"574":0.1928,"575":0.0586,"576":0.1358,"577":0.1298,"578":-0.126,"579":0.1099,"580":0.1395,"581":-0.134,"582":0.0797,"584":-0.1909,"585":-0.1459,"586":0.0568,"587":0.2288,"588":0.3926,"592":0.1971,"595":0.1675,"596":-0.1562,"597":-0.0587,"599":-0.0805,"600":-0.079,"601":-0.2597,"602":0.1713,"603":-0.245,"605":0.0596,"606":-0.083,"607":0.439,"608":0.1445,"609":-0.1053,"612":-0.0652,"614":-0.2468,"615":-0.1097,"617":-0.0568,"618":0.129,"619":-0.1308,"620":0.2592,"621":-0.0577,"623":-0.0669,"624":-0.0564,"625":-0.1501,"626":-0.1185,"627":-0.1248,"628":-0.2871,"629":-0.2291,"632":-0.1091,"633":0.2314,"634":-0.134,"635":-0.1387,"636":-0.133,"637":-0.0551,"639":-0.1075,"640":-0.1044,"642":-0.0574,"643":0.1516,"644":-0.508,"645":0.3633,"646":-0.2038,"647":-0.1965,"648":0.1511,"655":-0.1525,"656":-0.1205,"657":-0.3462,"658":0.2352,"659":-0.2804,"660":-0.0753,"661":0.1953,"662":-0.1047,"663":-0.1009,"664":-0.1009,"666":0.2769,"667":-0.211,"669":-0.2203,"670":-0.3559,"671":0.1957,"672":0.164,"673":-0.1083,"674":-0.1404,"675":-0.2797,"676":-0.0652,"677":-0.159,"678":-0.1385,"679":-0.0571,"680":0.1797,"682":0.2113,"683":0.207,"685":-0.1123,"688":-0.3126,"689":-0.1532,"691":0.0652,"692":-0.1818,"693":-0.1584,"694":-0.1282,"695":-0.0614,"696":0.1804,"697":0.2783,"698":-0.1877,"699":-0.1813,"700":-0.0816,"701":0.0765,"702":-0.0551,"703":-0.1706,"704":0.1215,"707":-0.1384,"708":-0.1457,"709":0.1882,"710":0.1622,"712":-0.1983,"713":-0.1005,"714":0.086,"715":-0.1557,"716":-0.0522,"718":-0.305,"719":-0.403,"720":-0.2591,"721":0.0549,"723":-0.0771,"724":0.1411,"725":-0.1596,"726":0.1073,"728":-0.0509,"731":-0.1538,"732":0.4488,"734":-0.3696,"736":0.389,"737":-0.0827,"739":0.2306,"742":0.1288,"744":-0.0701,"745":0.0874,"747":0.1432,"749":0.1911,"750":0.4484,"752":-0.1184,"753":0.1624,"754":0.2605,"756":0.3139,"757":0.1445,"758":-0.0755,"759":-0.1254,"760":-0.4186,"763":0.5135,"764":-0.2736,"765":0.0968,"766":-0.0644,"767":0.3211,"768":-0.1587,"769":0.3364,"770":-0.0518,"771":-0.1737,"772":0.4273,"773":-0.3964,"774":0.1499,"775":-0.1084,"776":-0.0795,"777":-0.1731,"778":-0.0982,"780":-0.0575,"781":-0.1493,"783":-0.0761,"784":-0.0596,"785":-0.1281,"786":-0.1598,"787":-0.2272,"788":0.0827,"790":-0.1861,"791":0.0653,"792":0.3505,"793":-0.2229,"794":-0.0805,"795":-0.1491,"796":0.1443,"798":-0.172,"799":-0.0828,"800":-0.156,"801":-0.0983,"802":-0.494,"803":0.2178,"804":-0.1281,"806":0.3092,"807":-0.1603,"808":-0.451,"809":0.1476,"810":-0.2582,"811":0.0555,"814":-0.1461,"815":-0.0741,"816":-0.0707,"818":-0.1342,"819":-0.2735,"820":0.0606,"822":0.1249,"824":-0.1399,"826":0.116,"827":0.1196,"829":-0.1544,"831":0.2227,"833":-0.167,"834":0.1004,"835":-0.0763,"836":-0.3845,"838":0.3742,"839":0.4037,"840":-0.0746,"841":0.1028,"842":-0.1113,"843":0.2893,"844":0.0617,"846":-0.1643,"848":-0.1857,"849":0.2204,"850":-0.1522,"851":-0.0977,"852":-0.0809,"853":-0.0712,"854":-0.1028,"856":-0.091,"858":0.2208,"860":-0.2068,"861":-0.077,"862":0.4915,"863":-0.2276,"866":-0.15,"867":-0.2545,"869":0.1255,"870":-0.1682,"871":-0.0532,"873":-0.1145,"876":-0.3748,"877":-0.5258,"878":0.1743,"879":-0.1207,"880":-0.0652,"881":-0.1233,"882":-0.0899,"883":-0.0985,"884":0.1952,"886":-0.2582,"887":-0.0715,"888":-0.0505,"889":-0.1469,"893":-0.1533,"894":0.4951,"895":0.2558,"896":-0.0943,"897":-0.1425,"898":-0.0779,"899":-0.124,"900":-0.0651,"901":-0.0631,"902":0.1579,"904":-0.0832,"907":-0.0572,"908":0.4662,"909":-0.1143,"910":0.1914,"911":0.0864,"913":-0.1612,"914":0.1362,"915":-0.1822,"916":0.1525,"917":-0.2292,"918":-0.0877,"919":-0.1431,"920":-0.1312,"922":0.5716,"923":0.1579,"926":-0.3957,"927":-0.1172,"928":0.0914,"929":0.3213,"931":-0.1239,"932":-0.0788,"933":0.0951,"935":-0.2695,"936":0.0864,"937":0.1281,"938":-0.0676,"939":0.5638,"940":-0.1498,"942":0.3701,"944":-0.0609,"945":-0.1925,"946":-0.1851,"947":-0.1859,"948":0.0911,"949":-0.1064,"951":0.1844,"952":0.1656,"953":-0.0732,"955":-0.2165,"956":-0.1235,"957":-0.1405,"958":0.1976,"960":0.1963,"962":0.1783,"963":-0.1219,"964":-0.0738,"965":0.3869,"966":0.3182,"967":-0.0766,"968":-0.1218,"969":-0.0831,"970":0.243,"971":0.1497,"972":-0.1474,"973":0.1325,"974":-0.2721,"975":-0.1768,"976":-0.1328,"977":-0.0772,"978":-0.0862,"979":0.1201,"980":-0.1802,"981":-0.1472,"982":0.1489,"983":-0.1892,"984":0.1136,"985":-0.147,"986":-0.1381,"987":-0.2762,"988":-0.224,"989":-0.0544,"990":0.1482,"991":-0.1966,"992":0.079,"994":0.1418,"995":-0.1069,"996":-0.066,"997":-0.2147,"998":-0.1086,"1004":-0.1875,"1007":-0.0663,"1010":-0.0716,"1011":0.1464,"1012":0.126,"1013":-0.169,"1014":-0.0709,"1015":0.6482,"1018":0.0581,"1019":-0.1606,"1020":0.1269,"1022":0.2859,"1023":-0.2469,"1024":0.3737,"1025":1.2702,"1026":-0.8742,"1027":-0.7406,"1028":-2.2652,"1029":1.2725,"1030":-0.3331,"1031":-0.5193},"threshold":0.5},"PROMPT_ATTACK":{"bias":-1.6924,"w":{"0":0.0744,"1":-0.0685,"2":-0.1975,"3":0.3932,"4":-0.1035,"5":0.4976,"6":-0.2745,"7":0.124,"8":-0.2464,"9":0.3215,"10":-0.0976,"12":-0.1388,"13":-0.1443,"14":0.6396,"16":-0.1628,"17":-0.1379,"18":0.2201,"19":0.0583,"21":0.311,"22":0.2596,"23":-0.1735,"27":-0.2168,"28":-0.1345,"29":-0.1259,"31":-0.22,"32":-0.089,"33":0.0587,"34":-0.226,"35":-0.3095,"36":-0.058,"37":0.1273,"38":0.1296,"40":-0.1719,"41":-0.097,"42":-0.1192,"43":-0.1557,"45":-0.0805,"46":0.2043,"48":-0.1171,"49":-0.3736,"53":-0.1095,"54":-0.0575,"55":0.0561,"57":0.2301,"58":0.1222,"59":-0.0678,"60":-0.2328,"61":-0.1631,"63":-0.1069,"64":-0.1299,"66":-0.0578,"67":-0.1275,"68":-0.1629,"69":-0.0688,"70":-0.5016,"71":-0.0597,"72":-0.101,"73":0.0849,"74":-0.0788,"75":-0.1666,"76":-0.2163,"77":-0.0968,"79":0.0542,"80":0.3063,"81":-0.0583,"82":-0.1554,"84":0.2771,"85":0.0623,"86":0.288,"89":0.2015,"90":-0.1755,"92":-0.1396,"94":-0.1917,"96":0.1193,"97":-0.177,"98":-0.0938,"99":-0.1377,"101":0.2253,"102":-0.0661,"103":-0.0694,"105":-0.1634,"107":-0.1234,"108":-0.1645,"109":-0.1068,"110":0.6031,"111":-0.0862,"112":0.1714,"115":0.0741,"116":0.0502,"117":0.3626,"118":-0.0727,"119":-0.0732,"121":-0.0791,"123":-0.1139,"124":-0.0659,"125":0.0698,"126":-0.059,"127":-0.1122,"128":-0.1485,"129":0.3972,"130":0.3142,"134":0.2211,"135":-0.0718,"136":0.0586,"137":-0.1908,"138":-0.0955,"139":-0.0655,"141":-0.1095,"142":-0.1562,"143":-0.1061,"144":0.1308,"146":-0.117,"147":0.6088,"148":-0.1484,"150":0.1562,"151":0.1202,"152":-0.1844,"154":-0.1749,"156":0.1212,"158":-0.2625,"160":0.6903,"161":-0.0999,"163":-0.2798,"164":0.2152,"165":-0.4374,"166":0.2155,"167":0.0806,"168":0.1102,"169":0.1559,"170":0.1574,"171":-0.3217,"173":0.0537,"174":-0.0691,"175":-0.0759,"176":0.1105,"177":-0.0504,"178":-0.1502,"179":0.4674,"180":-0.289,"182":0.2743,"183":-0.1228,"184":0.4905,"187":-0.0786,"189":-0.3498,"190":-0.1378,"191":-0.0559,"192":-0.1069,"194":-0.1082,"196":-0.1514,"197":-0.0838,"198":-0.1768,"200":0.189,"202":-0.1918,"203":-0.2246,"204":-0.1331,"205":-0.1383,"206":0.0897,"207":-0.3808,"208":0.1111,"209":-0.1104,"211":-0.1413,"212":1.221,"214":0.07,"215":0.4931,"216":0.1564,"217":0.227,"218":0.0859,"219":-0.2189,"220":-0.096,"221":0.3408,"222":-0.0924,"224":-0.1265,"225":-0.0973,"226":0.1486,"229":-0.2919,"230":0.1022,"232":0.185,"233":-0.1915,"234":-0.0919,"235":0.2053,"236":-0.3201,"237":0.2026,"239":0.5008,"240":0.0974,"241":-0.0534,"242":0.1843,"245":-0.0746,"246":-0.1061,"247":0.245,"249":-0.3665,"251":0.3732,"252":0.2465,"254":-0.2746,"255":-0.1678,"256":-0.0629,"257":0.1816,"258":0.1281,"259":-0.1986,"260":0.158,"261":0.2456,"263":-0.2916,"264":-0.1262,"266":0.2443,"267":-0.1801,"268":-0.1607,"269":-0.175,"273":-0.2411,"274":-0.1234,"276":-0.1546,"277":-0.0678,"278":-0.1538,"279":-0.114,"281":0.1426,"283":-0.0747,"284":-0.1365,"285":-0.1912,"287":-0.0599,"290":-0.0547,"292":-0.1041,"293":0.3057,"294":-0.103,"295":-0.1368,"296":-0.1609,"298":0.3655,"300":-0.101,"301":-0.0684,"302":0.1585,"303":0.052,"304":-0.3029,"307":0.0644,"308":0.0954,"309":0.2597,"310":-0.0772,"311":-0.1247,"314":-0.0608,"317":-0.0831,"318":-0.185,"319":0.1291,"320":-0.0809,"321":-0.205,"322":0.1035,"324":-0.1957,"325":-0.1605,"326":-0.0822,"327":-0.1031,"329":0.1539,"330":-0.1086,"331":-0.1349,"333":-0.2065,"334":0.3359,"335":0.1171,"336":-0.0567,"337":0.0597,"338":-0.0766,"340":-0.16,"343":-0.1601,"344":0.1578,"345":-0.0833,"346":-0.0575,"347":-0.1049,"348":-0.0959,"349":-0.1105,"350":0.157,"351":-0.1141,"352":-0.1355,"354":-0.1565,"355":0.1489,"356":0.1663,"357":-0.1507,"358":-0.1681,"359":-0.1727,"360":0.2628,"361":-0.1486,"362":-0.0842,"363":0.2516,"364":-0.1862,"365":0.2272,"367":-0.1158,"368":-0.1185,"369":-0.1431,"372":-0.2514,"373":-0.0601,"374":-0.07,"377":-0.1168,"379":0.1818,"382":-0.0666,"383":-0.2745,"384":0.0976,"385":-0.0733,"386":-0.0704,"387":0.1249,"389":0.2915,"390":-0.0625,"391":0.0539,"392":-0.1123,"393":-0.1704,"394":-0.1765,"395":-0.0542,"396":0.0695,"397":-0.1417,"399":-0.1087,"400":-0.1734,"401":-0.0623,"403":0.1135,"405":-0.2976,"406":-0.0786,"407":-0.0635,"410":0.154,"411":-0.1309,"412":0.3719,"415":-0.251,"416":-0.0758,"418":-0.0666,"420":-0.0752,"421":-0.0934,"423":0.1017,"425":-0.0575,"426":0.1186,"427":-0.2455,"428":0.1485,"429":-0.0648,"430":0.4388,"431":0.1706,"433":-0.0513,"434":0.1795,"435":-0.0635,"436":0.2293,"437":-0.0571,"438":-0.1644,"439":0.1038,"440":-0.0908,"441":0.2052,"442":-0.1127,"443":-0.1291,"445":0.2576,"446":-0.1703,"448":-0.1291,"449":-0.0719,"452":-0.5445,"453":-0.0699,"455":-0.3205,"456":-0.1533,"457":0.0779,"458":-0.1105,"459":-0.1633,"461":0.1635,"462":0.1345,"463":0.0964,"464":-0.2747,"467":-0.1085,"468":-0.068,"469":0.1251,"470":0.3281,"471":-0.1699,"472":0.1028,"473":0.0791,"474":0.1019,"476":0.3233,"478":0.1109,"479":-0.2436,"481":0.2843,"483":-0.1878,"485":-0.101,"487":0.0649,"488":-0.0534,"490":-0.3222,"492":-0.2067,"493":-0.1917,"494":0.948,"495":0.1615,"496":0.6762,"497":0.1128,"498":0.2162,"500":0.1883,"501":0.0999,"502":-0.0653,"503":0.3522,"504":-0.0927,"506":0.1084,"507":0.0515,"509":0.1648,"510":0.1537,"512":-0.1386,"514":-0.1172,"516":-0.0843,"519":0.0883,"520":-0.1079,"521":-0.3773,"522":0.1055,"523":0.0502,"524":-0.1618,"525":0.1086,"527":-0.1237,"528":0.0651,"529":-0.1422,"530":-0.1245,"531":0.3726,"532":-0.2011,"533":-0.1288,"534":0.1645,"536":-0.0615,"537":0.2697,"538":0.2159,"540":0.2418,"541":0.061,"543":-0.093,"544":0.1915,"545":-0.0698,"546":-0.0878,"547":-0.1171,"548":-0.1427,"549":-0.0956,"550":-0.1523,"551":-0.058,"552":-0.0834,"553":-0.1078,"554":0.1334,"555":-0.0588,"556":-0.0637,"557":0.2655,"558":0.1764,"559":0.0947,"560":-0.1474,"561":0.0638,"562":0.411,"563":0.259,"564":-0.0567,"565":-0.0565,"566":-0.0587,"567":-0.1581,"568":-0.0876,"569":-0.1612,"571":0.3393,"572":0.2288,"573":0.0978,"574":-0.0818,"575":-0.1453,"577":-0.0978,"579":0.0799,"580":-0.1241,"584":0.3103,"585":-0.1243,"586":0.07,"587":0.0978,"588":-0.4202,"590":-0.0972,"591":-0.0834,"592":-0.1433,"594":0.1121,"595":-0.1096,"596":0.0777,"597":0.0738,"598":0.0523,"600":-0.0825,"601":-0.0512,"602":-0.1154,"603":0.1843,"605":0.1813,"606":-0.1113,"607":0.1291,"608":-0.1289,"609":-0.0686,"610":0.0955,"611":-0.0507,"612":-0.0959,"613":-0.0577,"614":0.1015,"615":0.0531,"616":-0.1087,"618":0.062,"619":-0.1533,"620":-0.1151,"623":-0.0774,"624":0.2089,"625":0.123,"626":-0.1352,"628":0.2614,"629":-0.2805,"630":0.0827,"632":-0.1201,"633":0.0903,"634":0.1331,"635":0.0777,"636":-0.1372,"637":-0.0657,"640":-0.1006,"641":0.2869,"643":-0.0627,"645":-0.1146,"647":0.6585,"648":-0.2878,"650":-0.0974,"652":0.0842,"653":-0.1789,"655":-0.1322,"656":0.0911,"657":1.0878,"658":0.1678,"659":-0.2348,"660":-0.0814,"661":-0.3814,"663":0.2274,"664":0.2999,"665":0.1254,"666":0.1547,"667":-0.1017,"668":0.2752,"669":-0.1793,"670":0.1444,"671":0.1436,"672":-0.0961,"673":-0.1308,"674":0.1139,"675":0.3057,"676":-0.0681,"677":0.3477,"678":0.2376,"679":-0.07,"681":0.2935,"682":0.081,"683":-0.0717,"684":0.1123,"685":-0.2521,"687":-0.1189,"688":-0.0685,"689":-0.1385,"690":0.1455,"691":-0.2332,"692":-0.1646,"693":-0.1885,"694":0.2429,"696":-0.064,"697":-0.109,"698":0.0867,"699":-0.0564,"700":-0.0716,"702":-0.1406,"703":-0.2878,"706":-0.2749,"707":0.34,"708":-0.0826,"711":-0.1645,"713":-0.099,"715":-0.1231,"716":-0.0521,"718":0.2067,"719":0.39,"720":0.5018,"722":-0.1023,"723":-0.0546,"727":-0.0645,"728":0.0801,"731":0.1058,"732":-0.6271,"733":-0.1597,"734":-0.4656,"735":0.0559,"736":-0.1704,"737":-0.0827,"739":-0.1309,"740":0.1646,"741":-0.0506,"742":-0.1203,"746":-0.1517,"749":-0.2034,"750":-0.2105,"751":-0.0928,"753":-0.058,"754":-0.1041,"755":-0.1025,"756":-0.2012,"758":0.0792,"759":-0.1385,"761":-0.1359,"762":0.4311,"763":-0.2741,"764":-0.1485,"765":0.1195,"766":-0.0964,"767":0.2726,"769":-0.0969,"771":-0.1345,"772":-0.2657,"773":0.1118,"774":-0.1386,"775":0.2287,"777":-0.1142,"779":-0.1702,"780":-0.0657,"781":0.1376,"782":0.4464,"783":0.1935,"784":-0.0682,"785":0.127,"786":-0.2334,"789":0.1766,"790":-0.0622,"791":-0.1908,"793":0.589,"795":0.0947,"796":-0.0786,"798":0.203,"799":-0.0981,"801":0.2098,"802":-0.1864,"803":0.0815,"804":0.1855,"805":-0.064,"806":0.1657,"807":0.0634,"808":-0.3038,"809":-0.1642,"810":-0.2372,"811":-0.0991,"813":-0.445,"814":-0.056,"815":0.1223,"818":-0.0712,"819":0.3935,"820":-0.0773,"821":-0.1359,"823":-0.0756,"824":-0.158,"825":-0.1056,"826":-0.1232,"827":-0.206,"829":-0.1028,"831":-0.6431,"832":0.2596,"833":-0.0655,"834":-0.1235,"835":0.0705,"836":0.9591,"838":0.3447,"840":-0.245,"841":-0.1242,"842":0.1592,"843":-0.161,"844":0.0864,"845":-0.0549,"846":0.171,"847":-0.2425,"849":-0.2069,"850":0.288,"851":0.1546,"852":0.1594,"853":0.1317,"854":0.1483,"855":0.0871,"857":-0.0902,"858":-0.3938,"859":-0.3324,"860":0.1357,"861":0.2155,"862":-0.2008,"863":-0.1744,"864":-0.0769,"865":-0.3342,"866":0.1722,"867":-0.2152,"869":0.3637,"870":0.5597,"871":-0.0539,"874":-0.0996,"876":-0.4579,"877":0.3853,"878":-0.0867,"879":-0.1337,"882":0.1052,"883":0.0604,"884":-0.115,"886":0.32,"887":-0.0698,"888":-0.1816,"889":-0.1622,"890":0.2532,"891":-0.0935,"892":0.1607,"893":-0.0857,"894":-0.1901,"895":-0.07,"898":0.2719,"899":0.2423,"900":-0.2397,"902":-0.1061,"903":-0.233,"904":0.0908,"905":0.2414,"906":-0.1117,"907":-0.0673,"908":-0.146,"909":0.1406,"911":-0.1131,"913":0.2201,"915":0.1326,"916":-0.0715,"917":-0.298,"918":-0.1129,"920":0.1304,"921":-0.2855,"922":-0.0661,"923":-0.1792,"924":0.2002,"925":-0.1655,"927":-0.1384,"929":-0.312,"930":-0.2382,"931":0.1572,"932":-0.3077,"934":-0.1057,"935":-0.2014,"936":-0.0799,"939":-0.3018,"940":0.6167,"942":-0.1001,"943":-0.1774,"944":-0.1645,"945":0.1871,"946":0.3125,"947":0.5678,"949":-0.0829,"950":0.0562,"951":-0.2317,"953":-0.0688,"955":0.0822,"956":0.1402,"957":-0.1566,"958":-0.535,"959":-0.1231,"960":-0.1538,"962":-0.2253,"963":0.1596,"964":-0.076,"965":-0.1707,"966":-0.1142,"967":-0.1186,"968":-0.2943,"969":0.1253,"970":-0.1714,"971":-0.0543,"973":-0.1836,"974":0.1337,"975":0.4357,"976":-0.1611,"977":0.0779,"978":-0.1739,"979":-0.1761,"980":0.2038,"981":0.3671,"982":-0.2125,"983":0.2972,"984":-0.2969,"985":-0.1679,"986":0.4382,"987":0.7714,"989":-0.1002,"990":0.157,"991":-0.0896,"993":-0.0757,"994":-0.14,"995":-0.203,"996":0.0999,"997":-0.0802,"998":0.593,"999":-0.1375,"1002":0.1084,"1003":-0.0699,"1004":-0.1791,"1007":0.0869,"1008":0.0821,"1014":-0.1104,"1016":0.3744,"1017":0.1628,"1018":-0.0871,"1019":-0.1692,"1020":0.1459,"1021":-0.1085,"1022":-0.2454,"1024":-0.4368,"1025":-1.406,"1026":-0.4733,"1027":-0.3346,"1028":-1.3187,"1029":-0.4008,"1030":-0.1317,"1031":0.2142},"threshold":0.5}}};
  // __SEMANTIC_MODEL_END__
  // Score a category from an already-computed feature vector — lets a single
  // analyze() featurize once and reuse it across every category (see
  // classifySemantic) instead of re-featurizing per category on the hot path.
  function _lrScoreFeatures(f, m) {
    let z = m.bias || 0; const w = m.w || {};
    for (const idx in w) { const fv = f[+idx]; if (fv) z += fv * w[idx]; }
    return 1 / (1 + Math.exp(-z));
  }
  function _lrProb(text, cat) {
    const m = SEMANTIC_MODEL.models && SEMANTIC_MODEL.models[cat];
    if (!m) return 0;
    return _lrScoreFeatures(_featurize(text), m);
  }
  function _lrThresh(cat) { const m = SEMANTIC_MODEL.models && SEMANTIC_MODEL.models[cat]; return m && typeof m.threshold === 'number' ? m.threshold : 1.01; }

  // Prompt-attack signals — jailbreak / instruction-override / system-prompt
  // exfiltration intent, and the "AI reading this" tell of INDIRECT injection
  // planted in documents and tool results. Each pattern is precise enough to
  // fire alone; discussing attacks in the abstract matches none of them.
  const PROMPT_ATTACK_SIGNALS = [
    /\b(?:ignore|disregard|forget|override)\b[\s\S]{0,40}?\b(?:previous|prior|above|earlier|original|system|all|any)\b[\s\S]{0,24}?\b(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?|guardrails?)\b/i,
    /\b(?:reveal|show|print|repeat|output|display|disclose|leak)\b[\s\S]{0,32}?\b(?:system prompt|hidden (?:instructions?|prompt)|initial instructions?|your (?:instructions|system message|directives)|developer message)\b/i,
    /\b(?:you are|you'?re|act as|pretend|roleplay as|simulate|become)\b[\s\S]{0,40}?\b(?:dan\b|do anything now|jailbroken|unrestricted|unfiltered|amoral|no (?:rules|restrictions|filters|limits)|without (?:any )?(?:restrictions?|filters?|guardrails?|limitations?))/i,
    /\b(?:developer mode|dan mode|god mode|jailbreak(?:ing| mode)?|no[- ]filter mode|evil mode)\b/i,
    /\b(?:bypass|disable|turn off|remove|evade|circumvent|get around)\b[\s\S]{0,28}?\b(?:your|the|all|any)\b[\s\S]{0,16}?\b(?:safety|guardrails?|content (?:filters?|polic\w+)|moderation|restrictions?|alignment|censorship)/i,
    /\b(?:ai|assistant|model|llm|agent)s?[\s\S]{0,16}?\b(?:reading|processing|parsing|summarizing)\s+this\b|\bwhen (?:the |an? )?(?:ai|assistant|model|llm) (?:reads?|sees?|processes)\s+this\b/i,
    /\b(?:never|do not|don'?t)\s+(?:refuse|decline)\b[\s\S]{0,24}?\b(?:any|requests?|instructions?|commands?)\b|\bno (?:warnings?|disclaimers?), no refusals?\b/i,
  ];
  function _promptAttackScore(t) {
    let hits = 0;
    for (const re of PROMPT_ATTACK_SIGNALS) if (re.test(t)) hits += 1;
    return hits ? Math.min(1, 0.62 + 0.12 * (hits - 1)) : 0;
  }

  function classifySemantic(text, disabled) {
    const t = text || '', lower = t.toLowerCase(), len = Math.max(t.length, 1);
    const cats = [];
    const want = (id) => !disabled.has(id);
    // Featurize at most once per analyze (lazily, only when a model exists) and
    // reuse the vector across categories — the featurization dominates cost.
    let _feats = null;
    const catProb = (cat) => {
      const m = SEMANTIC_MODEL.models && SEMANTIC_MODEL.models[cat];
      if (!m) return 0;
      if (_feats === null) _feats = _featurize(t);
      return _lrScoreFeatures(_feats, m);
    };

    if (want('SOURCE_CODE')) {
      let code = 0;
      [/\bfunction\b/, /=>/, /\bdef\s+\w+\s*\(/, /\bclass\s+\w+/, /\bimport\s+[\w{]/, /\b(?:const|let|var)\s+\w+\s*=/,
       /\bpublic\s+(?:static\s+)?\w+/, /#include\b/, /\bSELECT\b.+\bFROM\b/i, /\b(?:INSERT|UPDATE|DELETE)\b.+\b(?:INTO|SET|FROM)\b/i,
       /\breturn\b\s+\w/, /\bif\s*\(.+\)\s*[{:]/, /```[a-z0-9_-]*\n[\s\S]{12,}```/i, /\b(?:async\s+function|await\s+\w+\(|from\s+[\w.]+\s+import|module\.exports|export\s+default)\b/].forEach((re) => { if (re.test(t)) code += 0.18; });
      const braces = (t.match(/[{}();]/g) || []).length;
      if (braces / len > 0.03) code += 0.25;
      if (/\n\s{2,}\S/.test(t) && braces > 3) code += 0.15;
      const p = catProb('SOURCE_CODE');
      if (code >= 0.45 || p >= _lrThresh('SOURCE_CODE')) cats.push({ category: 'SOURCE_CODE', score: Math.min(1, Math.max(code, p)) });
    }
    if (want('LEGAL_CONTRACT')) {
      let legal = 0;
      ['agreement', 'hereby', 'hereinafter', 'indemnif', 'liabilit', 'shall not', 'terms and conditions',
       'confidentiality', 'non-disclosure', 'party of the', 'in witness whereof', 'governing law', 'warrant',
       'breach', 'covenant', 'arbitration', 'force majeure', 'entire agreement', 'assignment without consent',
       'termination for cause', 'limitation of liability', 'receiving party', 'disclosing party'].forEach((w) => { if (lower.includes(w)) legal += 0.16; });
      const p = catProb('LEGAL_CONTRACT');
      if (legal >= 0.32 || p >= _lrThresh('LEGAL_CONTRACT')) cats.push({ category: 'LEGAL_CONTRACT', score: Math.min(1, Math.max(legal, p)) });
    }
    if (want('CREDENTIALS')) {
      let cred = 0;
      // Conclusive standalone signals fire on their own — a bearer token, a
      // user:pass@host URI, a PEM header, or an UPPER_SECRET=value assignment is
      // a live secret regardless of surrounding prose.
      [/\bbearer\s+[A-Za-z0-9._-]{8,}/i, /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s:@/]+@/i, /-----BEGIN/,
       /\b[A-Z0-9_]*(?:SECRET|TOKEN|API_?KEY|ACCESS_KEY|PASSWORD|PRIVATE_KEY)\s*[:=]\s*\S/,
       /\bclient[_ -]?secret\s*[:=]\s*\S/i, /\baws_(?:secret_access_key|access_key_id)\s*[:=]/i,
       /\b(?:password|passwd|pwd)\s+is\s+\S{6,}/i].forEach((re) => { if (re.test(t)) cred = Math.max(cred, 0.6); });
      // Weaker cues need corroboration (two together) so talking ABOUT
      // credentials ("rotate API keys") doesn't score.
      [/\bconnection\s*string\b/i, /\bpassword\s*[:=]/i, /\bapi[_ -]?key\s*[:=]/i, /\bsecret\s*[:=]/i, /\btoken\s*[:=]/i].forEach((re) => { if (re.test(t)) cred += 0.2; });
      const p = catProb('CREDENTIALS');
      if (cred >= 0.4 || p >= _lrThresh('CREDENTIALS')) cats.push({ category: 'CREDENTIALS', score: Math.min(1, Math.max(cred, p)) });
    }
    if (want('CONFIDENTIAL_BUSINESS')) {
      // Three independent paths, precision-first (benign prompts hit none of them):
      //  1) an explicit confidentiality marker is conclusive on its own;
      //  2) an intent-to-keep-secret cue PLUS a sensitive business topic;
      //  3) the trained model, for cue-less confidential meaning it generalizes to.
      const explicitConf = /\b((strictly|company|highly|business) )?confidential\b|internal only|internal[- ]use only|do not (share|distribute|forward|circulate)|not for distribution|proprietary|trade secret|privileged and confidential/i.test(t);
      const secrecyCue = /\b(do not (share|forward|distribute|circulate|mention)|don'?t (share|forward|tell|mention|circulate)|keep (this|it) (internal|confidential|quiet|between us|to yourself|under wraps)|to yourself|strictly (internal|confidential)|internal only|not (yet )?(public|announced|been announced)|off the record|under wraps|hush(\s*hush)?|stays? (internal|in this (thread|room|email)|between us)|cannot leave this|no one else (has|should)|embargo|before (anything|it'?s)( is)? (filed|announced|public)|discreet)/i.test(t);
      const bizSensitive = /\b(layoffs?|lay(ing)? off|headcount|restructur|wind(ing)? down|merger|acquisition|acquir|transaction|trim(?:ming)?[^.]{0,30}(?:org|team|staff|workforce|headcount|division|department|unit)|consent order|exam(iner| findings)|regulatory findings?|bsa|aml|restat|net[- ]?worth|portfolio|retention|earnings|revenue (projection|target)|miss(ing)? (our )?(numbers|targets?)|pricing (strategy|change)|margins|board (deck|pack|hears|approval)|customer list|member list|unreleased roadmap|material nonpublic|mnpi|vendor negotiation|non[- ]?renewal|security incident|breach plan|switch(ing)? (vendors?|processors?|away)|replac(e|ing) (our|the) (core|processor|vendor)|leaving (our|the) (vendor|processor)|considering (leaving|switching)|losing the .{0,24}account|cap table|pre[- ]revenue|churn|pipeline forecast|salary (band|range)|compensation band|pulling out of)\b/i.test(t);
      const p = catProb('CONFIDENTIAL_BUSINESS');
      const kwFires = explicitConf || (secrecyCue && bizSensitive);
      if (kwFires || p >= _lrThresh('CONFIDENTIAL_BUSINESS')) cats.push({ category: 'CONFIDENTIAL_BUSINESS', score: Math.min(1, Math.max(kwFires ? 0.72 : 0, p)) });
    }
    if (want('PROMPT_ATTACK')) {
      const kw = _promptAttackScore(t);
      const p = catProb('PROMPT_ATTACK');
      if (kw > 0 || p >= _lrThresh('PROMPT_ATTACK')) cats.push({ category: 'PROMPT_ATTACK', score: Math.min(1, Math.max(kw, p)) });
    }
    if (want('HEALTH_RECORD')) {
      const patientCue = /\b(patient|member|subscriber|insured|chart|medical record|mrn)\b/i.test(t);
      const healthTopic = /\b(diagnos(is|ed)|treatment|procedure|lab result|prescription|medication|claim|icd-?10|cpt|hipaa|phi|discharge summary|clinical note|provider|npi)\b/i.test(t);
      const identifierCue = /\b(mrn|medical record|health insurance|subscriber id|policy number|claim number|npi)\b/i.test(t);
      const deidentifiedCue = /\b(?:without|no|not)\s+(?:any\s+)?patient\s+(?:details|context|data|identifiers?|info|information)\b/i.test(t);
      const generalAsk = /\b(explain|what are|best practices|high level|in general|no specifics)\b/i.test(t);
      if (identifierCue || (patientCue && healthTopic && !deidentifiedCue && !generalAsk)) cats.push({ category: 'HEALTH_RECORD', score: 0.72 });
    }
    // Document-class categories (cf. Nightfall's LLM file classifiers), on-device
    // and keyword-first: two independent cue families ANDed plus negation cues
    // (the HEALTH_RECORD pattern), max-combined with the LR model so a future
    // trained model plugs in with zero engine change.
    if (want('FINANCIAL_STATEMENT')) {
      const docCue = /\b(balance sheet|income statement|statement of (?:income|operations|cash flows|financial condition)|profit (?:and|&) loss|p&l|trial balance|general ledger|10-[kq]\b|call report|form 5300)/i.test(t);
      const lineItemCue = /\b(total (?:assets|liabilities|equity)|net (?:income|interest income|worth)|retained earnings|accounts (?:receivable|payable)|allowance for (?:loan|credit) losses|provision for loan losses|charge-?offs?|operating expenses?|delinquen)/i.test(t);
      const generalAsk = /\b(explain|what (?:is|are)|how (?:to|do i) read|in general|template|example|for a class|financial literacy)\b/i.test(t);
      const dollarCue = /\$[\d,]+/.test(t);
      const p = catProb('FINANCIAL_STATEMENT');
      const kwFires = docCue && lineItemCue && (!generalAsk || dollarCue);
      if (kwFires || p >= _lrThresh('FINANCIAL_STATEMENT')) cats.push({ category: 'FINANCIAL_STATEMENT', score: Math.min(1, Math.max(kwFires ? 0.72 : 0, p)) });
    }
    if (want('TAX_FILING')) {
      const formCue = /\b(?:form\s+)?(w-2|w-4|w-9|1099(?:-[a-z]+)?|1040|941\b|940\b|1120s?|1065|schedule\s+[a-e]\b|k-1\b|990\b)/i.test(t);
      const fieldCue = /\b(wages|withholding|withheld|taxable income|adjusted gross income|agi\b|filing status|box \d|tax year 20\d{2}|employer identification|refund|amount owed|federal income tax)/i.test(t);
      const generalAsk = /\b(explain|what (?:is|are)|how (?:to|do i) read|in general|template|example|just the concepts)\b/i.test(t);
      const p = catProb('TAX_FILING');
      const kwFires = formCue && fieldCue && !generalAsk;
      if (kwFires || p >= _lrThresh('TAX_FILING')) cats.push({ category: 'TAX_FILING', score: Math.min(1, Math.max(kwFires ? 0.72 : 0, p)) });
    }
    if (want('HR_RECORD')) {
      const hrDocCue = /\b(performance (?:review|improvement plan)|pip\b|disciplinary (?:action|write-?up)|written warning|termination (?:letter|notice)|offer letter|salary (?:history|increase|adjustment)|compensation (?:change|review)|hr (?:file|record|case|complaint)|employee (?:id|record|file)|personnel file|fmla\b|accommodation request|background check|exit interview)/i.test(t);
      const employeeCue = /\b(employee|staff member|direct report|teller|loan officer|branch manager|underwriter|coworker|new hire)\b/i.test(t) || NAME_CONTEXT_PROBE.test(t);
      const templateAsk = /\b(job (?:posting|description)|template|handbook|policy|in general|best practices|hypothetical|example|sample)\b/i.test(t);
      const p = catProb('HR_RECORD');
      const kwFires = hrDocCue && employeeCue && !templateAsk;
      if (kwFires || p >= _lrThresh('HR_RECORD')) cats.push({ category: 'HR_RECORD', score: Math.min(1, Math.max(kwFires ? 0.72 : 0, p)) });
    }
    return cats;
  }

  // One line of the "why this score" rationale: what was found, how sure the
  // engine is, how many points it contributed, and which obligations apply.
  function breakdownEntry(kind, type, severity, score) {
    return {
      kind, type, severity,
      severityLabel: SEVERITY_LABEL[severity] || 'none',
      confidence: CONFIDENCE_LABEL[confidenceTier(score)],
      points: Math.round(severity * score * (kind === 'finding' ? 8 : 7)),
      regulations: regulationsFor(type),
    };
  }

  // Unicode digit fold: map non-ASCII decimal digits (fullwidth, Arabic-Indic,
  // Devanagari, Thai, ...) to ASCII so a structured detector cannot be bypassed
  // by writing an SSN/card/IBAN in another digit script. Strictly one BMP code
  // point -> one ASCII char, so finding offsets stay valid against the ORIGINAL
  // text that tokenize()/redact() slice. Pure-ASCII input (the common case)
  // short-circuits with no allocation.
  const NON_ASCII_DIGIT = /[\u0660-\u0669\u06F0-\u06F9\u07C0-\u07C9\u0966-\u096F\u09E6-\u09EF\u0A66-\u0A6F\u0AE6-\u0AEF\u0B66-\u0B6F\u0BE6-\u0BEF\u0C66-\u0C6F\u0CE6-\u0CEF\u0D66-\u0D6F\u0E50-\u0E59\u0ED0-\u0ED9\u0F20-\u0F29\u1040-\u1049\u17E0-\u17E9\u1810-\u1819\uFF10-\uFF19]/;
  const NON_ASCII_DIGIT_G = new RegExp(NON_ASCII_DIGIT.source, 'g');
  const DIGIT_BLOCK_STARTS = [0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x17E0, 0x1810, 0xFF10];
  function foldDigits(text) {
    if (!NON_ASCII_DIGIT.test(text)) return text;
    return text.replace(NON_ASCII_DIGIT_G, (ch) => {
      const cp = ch.charCodeAt(0);
      for (const b of DIGIT_BLOCK_STARTS) { if (cp >= b && cp <= b + 9) return String(cp - b); }
      return ch;
    });
  }

  function analyze(text, opts) {
    opts = opts || {};
    const disabled = new Set([].concat(opts.ignore || [], opts.disabledDetectors || []));
    if (!text || typeof text !== 'string') {
      return { findings: [], categories: [], maxSeverity: 0, maxSeverityLabel: 'none', riskScore: 0, entityCounts: {}, scoreBreakdown: [], regulations: [] };
    }
    text = foldDigits(text);
    let findings = detectStructured(text, disabled, opts.customDetectors);
    if (opts.exactMatch && !disabled.has('EXACT_MATCH')) findings = findings.concat(detectExactMatch(text, opts.exactMatch));
    findings.sort((a, b) => (b.severity - a.severity) || (b.score - a.score));
    // Greedy overlap resolution: accept findings in priority order, skipping any
    // that overlap an already-accepted span. Accepted spans are kept sorted by
    // start so each overlap test only checks the two positional neighbours
    // (O(log k)) instead of scanning every accepted span (was O(k^2), which
    // blocked the event loop on large pastes on this per-keystroke hot path).
    const accepted = [];
    const byStart = [];
    for (const f of findings) {
      let lo = 0, hi = byStart.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (byStart[mid].start < f.start) lo = mid + 1; else hi = mid; }
      const left = byStart[lo - 1];
      const right = byStart[lo];
      const overlaps = (left && left.start < f.end && f.start < left.end)
        || (right && right.start < f.end && f.start < right.end);
      if (!overlaps) { accepted.push(f); byStart.splice(lo, 0, f); }
    }
    accepted.sort((a, b) => a.start - b.start);
    const categories = classifySemantic(text, disabled);
    const entityCounts = {};
    const scoreBreakdown = [];
    let maxSeverity = 0;
    for (const f of accepted) {
      const tier = confidenceTier(f.score);
      f.confidence = tier; f.confidenceLabel = CONFIDENCE_LABEL[tier]; f.regulations = regulationsFor(f.type);
      scoreBreakdown.push(breakdownEntry('finding', f.type, f.severity, f.score));
      entityCounts[f.type] = (entityCounts[f.type] || 0) + 1; if (f.severity > maxSeverity) maxSeverity = f.severity;
    }
    for (const c of categories) {
      const sv = SEVERITY[c.category] || 2;
      if (sv > maxSeverity) maxSeverity = sv;
      entityCounts[c.category] = 1; c.confidence = confidenceTier(c.score); c.confidenceLabel = CONFIDENCE_LABEL[c.confidence];
      scoreBreakdown.push(breakdownEntry('category', c.category, sv, c.score));
    }
    let raw = 0;
    for (const f of accepted) raw += f.severity * f.score * 8;
    for (const c of categories) raw += (SEVERITY[c.category] || 2) * c.score * 7;
    const riskScore = Math.min(100, Math.round(raw));
    const regulations = [...new Set(scoreBreakdown.flatMap((e) => e.regulations))];
    return { findings: accepted, categories, maxSeverity, maxSeverityLabel: SEVERITY_LABEL[maxSeverity] || 'none', riskScore, entityCounts, scoreBreakdown, regulations };
  }

  function redact(text, findings) {
    if (!findings || !findings.length) return text;
    const sorted = [...findings].sort((a, b) => b.start - a.start);
    let out = text;
    for (const f of sorted) out = out.slice(0, f.start) + '[' + f.type + ']' + out.slice(f.end);
    return out;
  }
  function maskValue(type, value) {
    if (type === 'CANARY_TOKEN') return '[CANARY_TOKEN]';
    const d = (value || '').replace(/\D/g, '');
    if ((type === 'US_ITIN' || type === 'US_NPI' || type === 'MEMBER_ID' || type === 'LOAN_NUMBER'
      || type === 'MEDICAL_RECORD_NUMBER' || type === 'HEALTH_INSURANCE_ID') && d.length >= 4) return '**** ' + d.slice(-4);
    if ((type === 'CREDIT_CARD' || type === 'US_SSN' || type === 'BANK_ACCOUNT' || type === 'IBAN') && d.length >= 4) return '•••• ' + d.slice(-4);
    if (type === 'EMAIL_ADDRESS') { const p = value.split('@'); return (p[0] ? p[0][0] : '') + '***@' + (p[1] || ''); }
    if (!value || value.length <= 4) return '****';
    return value.slice(0, 2) + '***' + value.slice(-2);
  }

  // ---------- reversible tokenization (pseudonymization) ---------------------
  // Replace each finding with a stable, typed placeholder so a prompt can reach
  // the model with NO real PII, then be re-hydrated locally from the map. Same
  // value -> same token within a call, so the model can still reason about "the
  // same person/account". This is the on-device primitive behind 'redact' mode
  // (parity with Strac/Nightfall pseudonymization, but the map never has to
  // leave the device).
  function tokenize(text, findings) {
    const accepted = (findings || []).slice().sort((a, b) => a.start - b.start);
    const byValue = new Map();   // value -> token (stability across repeats)
    const counters = {};         // type  -> next index
    const map = {};              // token -> value (reverse map / vault)
    for (const f of accepted) {
      if (byValue.has(f.value)) continue;
      const n = (counters[f.type] = (counters[f.type] || 0) + 1);
      const token = '[[' + f.type + '_' + n + ']]';
      byValue.set(f.value, token);
      map[token] = f.value;
    }
    let out = text;
    for (const f of accepted.slice().sort((a, b) => b.start - a.start)) {
      out = out.slice(0, f.start) + byValue.get(f.value) + out.slice(f.end);
    }
    return { text: out, map, tokens: Object.keys(map).length };
  }

  // Reverse tokenize(): swap every token back to its original value. Replaces
  // longer tokens first so e.g. [[X_11]] can't be clobbered by [[X_1]].
  function detokenize(text, map) {
    if (!text || !map) return text;
    let out = String(text);
    for (const token of Object.keys(map).sort((a, b) => b.length - a.length)) {
      out = out.split(token).join(map[token]);
    }
    return out;
  }

  // analyze + tokenize in one call.
  function tokenizePrompt(text, opts) {
    const analysis = analyze(text, opts);
    const t = tokenize(text, analysis.findings);
    return { tokenizedText: t.text, map: t.map, tokenCount: t.tokens, analysis };
  }

  function publicCustomDetectorConfig(value) {
    return normalizeCustomDetectors(value).map(publicCustomDetector);
  }

  const api = { analyze, redact, maskValue, tokenize, detokenize, tokenizePrompt, classifySemantic, _featurize, _lrProb, listDetectors, normalizeCustomDetectors, publicCustomDetectorConfig, edmFingerprint, normalizeExactMatchConfig, secretVendor, luhnValid, ssnPlausible, abaValid, ibanValid, vinValid, bankAccountPlausible, itinPlausible, npiValid, datePlausible, ipv6Valid, cardNetwork, ninoValid, nhsValid, sinValid, tfnValid, aadhaarValid, regulationsFor, SEVERITY, SEVERITY_LABEL, CONFIDENCE_LABEL, REGULATIONS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.PSDetect = api;
})(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : null));
