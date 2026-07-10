'use strict';

const detector = require('./detector');
const validation = require('./validation');

function categoryNames(analysis) {
  return [...new Set(((analysis && analysis.categories) || [])
    .map((category) => category.category)
    .filter(Boolean))];
}

function sanitizeSensitiveText(value, max) {
  const text = String(value == null ? '' : value);
  const analysis = detector.analyze(text);
  const categories = categoryNames(analysis);
  const safe = categories.length
    ? `[REDACTED: ${categories.join(', ')}]`
    : detector.redact(text, analysis.findings || []);
  return validation.sanitizeStoredNote(safe, max);
}

module.exports = { sanitizeSensitiveText, categoryNames };
