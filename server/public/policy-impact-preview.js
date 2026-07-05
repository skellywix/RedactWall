'use strict';
(function () {
  function safe(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (char) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char];
    });
  }

  function pill(tone, label) {
    return '<span class="chip status-chip ' + safe(tone) + '">' + safe(label) + '</span>';
  }

  function metric(label, value, detail) {
    return '<div><span>' + safe(label) + '</span><b>' + safe(value) + '</b><small>' + safe(detail || '') + '</small></div>';
  }

  function list(title, rows) {
    var body = (rows || []).filter(function (item) {
      return item.changed || item.newlyBlocked || item.newlyAllowed;
    }).slice(0, 4).map(function (item) {
      return '<div class="policy-impact-row"><span>' + safe(item.label) + '</span><b>' + safe(item.changed) + ' changed</b><small>' + safe(item.newlyBlocked) + ' new block / ' + safe(item.newlyAllowed) + ' new allow</small></div>';
    }).join('');
    return '<section><strong>' + safe(title) + '</strong>' + (body || '<p>No material change in this slice.</p>') + '</section>';
  }

  function render(result) {
    var target = document.querySelector('#policyImpactPreview');
    if (!target || !result || !result.summary) return;
    var s = result.summary;
    var tone = s.newlyBlocked ? 'bad' : s.changed ? 'warn' : 'good';
    var blocked = s.proposed && s.proposed.blocked || 0;
    target.innerHTML = '<div class="sensor-head"><div><h3>Policy Impact Preview</h3><p>Recent metadata only. Prompt bodies and masked values are excluded.</p></div>'
      + pill(tone, s.changed ? s.changed + ' changed' : 'No change') + '</div>'
      + '<div class="policy-impact-metrics">'
      + metric('Sample', s.sampleSize || 0, 'recent events')
      + metric('Changed', s.changed || 0, (s.moreRestrictive || 0) + ' stricter')
      + metric('New blocks', s.newlyBlocked || 0, blocked + ' proposed blocked')
      + metric('New allows', s.newlyAllowed || 0, (s.lessRestrictive || 0) + ' looser')
      + '</div><div class="policy-impact-deltas">'
      + list('Destinations', result.topDeltas && result.topDeltas.destinations)
      + list('Detectors and categories', result.topDeltas && result.topDeltas.categories)
      + list('Sources', result.topDeltas && result.topDeltas.sources)
      + '</div>';
  }

  window.RedactWallPolicyImpact = { render: render };
}());
