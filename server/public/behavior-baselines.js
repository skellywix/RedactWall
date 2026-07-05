(function(){
'use strict';
function n(v){const x=Number(v);return Number.isFinite(x)?x:0;}
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function stateLabel(s){return s==='critical'?'Critical':s==='warning'?'Watch':'Normal';}
function tone(s){return s==='critical'?'critical':s==='warning'?'attention':'ready';}
function row(item){
  const t=tone(item.state);
  return `<button class="behavior-baseline-row ${esc(t)}" type="button" data-tab-jump="${esc(item.targetTab||'activity')}">
    <span>${esc(stateLabel(item.state))}</span>
    <strong>${esc(item.title||'Behavior baseline')}</strong>
    <small>${esc(item.label||'metadata')} / ${esc(item.detail||'No unusual change')}</small>
    <b>${esc(n(item.score))}</b>
  </button>`;
}
function render(posture,deps){
  const q=deps.$,target=q('#behaviorBaselineRows'),summary=q('#behaviorBaselineSummary');
  if(!target||!summary)return;
  const b=posture&&posture.behaviorBaselines&&typeof posture.behaviorBaselines==='object'?posture.behaviorBaselines:null;
  const s=b&&b.summary||{};
  const rows=Array.isArray(b&&b.dimensions)?b.dimensions:[];
  summary.textContent=b?`${n(s.anomalies)} anomalies / ${n(s.critical)} critical / ${n(s.warning)} watch`:'Waiting for data';
  target.innerHTML=rows.length?rows.slice(0,6).map(row).join(''):'<div class="signal-empty"><b>No behavior anomalies</b><p>Recent metadata matches the learned baseline.</p></div>';
}
window.RedactWallBehaviorBaselines={render};
}());
