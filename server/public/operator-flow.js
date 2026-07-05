(function(){
'use strict';
const prefersReduce=()=>window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function n(value){const number=Number(value);return Number.isFinite(number)?number:0;}
function flowTone(value){return value>0?'critical':'ready';}
function actionTone(critical,warning){return critical?'critical':warning?'attention':'ready';}
function safeSummary(text,fallback){return text||fallback;}
function step(id,title,primary,meta,action,tone,target){
  return {id,title,primary:safeSummary(primary,'0'),meta:safeSummary(meta,'No open evidence'),action,tone:tone||'idle',target};
}
function operatorSteps(posture){
  const threat=posture&&posture.threatGuardrails&&posture.threatGuardrails.summary||{};
  const actions=Array.isArray(posture&&posture.actionQueue)?posture.actionQueue:[];
  const inventory=posture&&posture.aiInventory&&posture.aiInventory.summary||{};
  const behavior=posture&&posture.behaviorBaselines&&posture.behaviorBaselines.summary||{};
  const mcp=posture&&posture.agenticMcp&&posture.agenticMcp.summary||{};
  const graph=posture&&posture.controlGraph&&posture.controlGraph.summary||{};
  const mission=posture&&posture.hardening&&posture.hardening.mission||{};
  const ledger=mission.proofLedger||posture&&posture.hardening&&posture.hardening.proofLedger||{};
  const critical=actions.filter((item)=>item&&item.severity==='critical').length;
  const warning=actions.filter((item)=>item&&item.severity==='warning').length;
  const routed=actions.filter((item)=>item&&['assigned','snoozed','resolved'].includes(item.workflowStatus)).length;
  const highAssets=n(inventory.highRiskAssets)+n(inventory.unapprovedLocalTools);
  const threatOpen=n(threat.critical)+n(threat.blocked);
  const proofOpen=n(ledger.attention)+n(ledger.missing);
  return [
    step('threats','Threat triage',`${n(threat.events)} events`,`${n(threat.activeRules)} rules / ${n(threatOpen)} urgent`,'Review threats',threatOpen?'critical':n(threat.events)?'attention':'ready','#threatGuardrailsRows'),
    step('baselines','Behavior baselines',`${n(behavior.anomalies)} anomalies`,`${n(behavior.critical)} critical / ${n(behavior.warning)} watch`,'Review baselines',n(behavior.critical)?'critical':n(behavior.warning)?'attention':'ready','#behaviorBaselineRows'),
    step('actions','Hardening actions',`${actions.length} actions`,`${critical} critical / ${warning} warning / ${routed} routed`,'Route actions',actionTone(critical,warning),'#hardeningActionQueue'),
    step('assets','AI surface review',`${highAssets} high risk`,`${n(inventory.activeDestinations)} destinations / ${n(mcp.activeAgents)} agents`,'Review assets',flowTone(highAssets),'#aiInventoryRows'),
    step('graph','Control graph',`${n(graph.highRiskAssets)} watched`,`${n(graph.nodes)} nodes / ${n(graph.controlledLinks)} controlled links`,'Map control',flowTone(n(graph.highRiskAssets)+n(graph.shadowAssets)),'#controlGraphMap'),
    step('soc','SOC handoff',`${n(ledger.verified)} proof`,`${proofOpen} open / ${safeSummary(graph.privacy,'metadata only')}`,'Prepare SOC',proofOpen?'attention':'ready','#siemPackagePreview'),
  ];
}
function render(posture,deps){
  const q=deps.$,safe=deps.escapeHtml,summary=q('#operatorFlowSummary'),target=q('#operatorFlowRows');
  if(!summary||!target)return;
  if(!posture){summary.textContent='Waiting for data';target.innerHTML='<div class="signal-empty"><b>Waiting</b><p>Posture refresh pending.</p></div>';return;}
  const rows=operatorSteps(posture),urgent=rows.filter((row)=>row.tone==='critical').length,attention=rows.filter((row)=>row.tone==='attention').length,ready=rows.filter((row)=>row.tone==='ready').length;
  summary.textContent=`${urgent} urgent / ${attention} attention / ${ready} ready`;
  target.innerHTML=rows.map((row)=>`<button class="operator-flow-card ${safe(row.tone)}" type="button" data-flow-target="${safe(row.target)}">
    <span>${safe(row.title)}</span>
    <strong>${safe(row.primary)}</strong>
    <small>${safe(row.meta)}</small>
    <b>${safe(row.action)}</b>
  </button>`).join('');
}
document.addEventListener('click',(event)=>{
  const button=event.target.closest('[data-flow-target]');
  if(!button)return;
  const target=document.querySelector(button.getAttribute('data-flow-target')||'');
  if(target)target.scrollIntoView({block:'start',behavior:prefersReduce()?'auto':'smooth'});
});
window.RedactWallOperatorFlow={render};
}());
