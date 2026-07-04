(function(){
'use strict';
function empty(title,body,safe){return `<div class="signal-empty"><b>${safe(title)}</b><p>${safe(body)}</p></div>`;}
function stateLabel(state){
  return ({ready:'Ready',attention:'Attention',critical:'Critical',missing:'Missing',online:'Online',warning:'Warning',error:'Critical',idle:'Idle'})[state]||state||'Unknown';
}
function status(item){
  const value=String(item&&item.status||'').toLowerCase(),state=String(item&&item.state||'').toLowerCase();
  if(['online','warning','error','idle'].includes(value))return value;
  if(['critical','missing'].includes(state))return'error';
  if(state==='attention')return'warning';
  return'online';
}
function kpi(label,value,meta,safe){return `<div class="agentic-mcp-kpi"><span>${safe(label)}</span><b>${safe(value||0)}</b><em>${safe(meta||'')}</em></div>`;}
function ruleRow(item,safe){
  return `<button class="agentic-mcp-row threat-guardrail-row ${safe(status(item))}" type="button" data-tab-jump="${safe(item.targetTab||'activity')}" title="${safe(item.detail||'')}"><span>${safe(item.framework||'AI risk')}</span><strong>${safe(item.label||'Guardrail')}</strong><small>${safe(item.detail||'No sanitized detail.')}</small><b>${safe(item.events||0)}</b></button>`;
}
function controlRow(item,safe){
  return `<button class="agentic-mcp-policy-row threat-guardrail-control" type="button" data-tab-jump="${safe(item.targetTab||'policy')}"><span>${safe(item.label||'Control')}</span><b>${safe(stateLabel(item.state))}</b><small>${safe(item.detail||'No detail.')}</small></button>`;
}
function recentRow(item,safe){
  const threats=Array.isArray(item.threats)&&item.threats.length?item.threats.join(', '):'AI threat';
  return `<button class="agentic-mcp-row threat-guardrail-row ${safe(status(item))}" type="button" data-tab-jump="activity" title="${safe(item.detail||'')}"><span>${safe(item.decision||item.severity||'event')}</span><strong>${safe(item.title||'Threat event')}</strong><small>${safe(threats)} / ${safe(item.destination||'unknown')} / ${safe(item.detail||'raw content excluded')}</small><b>${safe(item.severity||'info')}</b></button>`;
}
function render(currentPosture,deps){
  const q=deps.$,safe=deps.escapeHtml,summary=q('#threatGuardrailsSummary'),target=q('#threatGuardrailsRows');
  if(!summary||!target)return;
  const data=currentPosture&&currentPosture.threatGuardrails&&typeof currentPosture.threatGuardrails==='object'?currentPosture.threatGuardrails:null;
  if(!data){summary.textContent='Waiting for data';target.innerHTML=empty('No AI threat data','Threat guardrails appear after posture refresh.',safe);return;}
  const s=data.summary||{},rules=Array.isArray(data.rules)?data.rules:[],controls=Array.isArray(data.controls)?data.controls:[],recent=Array.isArray(data.recent)?data.recent:[];
  summary.textContent=`${s.events||0} events / ${s.activeRules||0} active rules / ${s.privacy||'prompt bodies excluded'}`;
  const kpis=[
    kpi('Events',s.events,`${s.detections||0} detections`,safe),
    kpi('Critical',s.critical,`${s.blocked||0} blocked`,safe),
    kpi('Injection',s.promptInjection,'OWASP LLM01',safe),
    kpi('Unsafe output',s.unsafeOutput,'response scan',safe),
  ].join('');
  const ruleRows=rules.length?rules.slice(0,6).map((x)=>ruleRow(x,safe)).join(''):empty('No active rules','No AI threat guardrail evidence yet.',safe);
  const controlRows=controls.length?controls.map((x)=>controlRow(x,safe)).join(''):empty('No controls','Policy guardrail controls are not available.',safe);
  const recentRows=recent.length?recent.map((x)=>recentRow(x,safe)).join(''):empty('No recent threats','Recent AI threat events will appear here.',safe);
  target.innerHTML=`<div class="agentic-mcp-kpis">${kpis}</div><div class="agentic-mcp-columns"><section class="agentic-mcp-panel"><div class="agentic-mcp-panel-head"><strong>Guardrails</strong><span>${safe(rules.filter((x)=>x.events).length)}</span></div><div class="agentic-mcp-list">${ruleRows}</div></section><section class="agentic-mcp-panel"><div class="agentic-mcp-panel-head"><strong>Controls</strong><span>${safe(controls.length)}</span></div><div class="agentic-mcp-policy">${controlRows}</div></section><section class="agentic-mcp-panel"><div class="agentic-mcp-panel-head"><strong>Recent</strong><span>${safe(recent.length)}</span></div><div class="agentic-mcp-list">${recentRows}</div></section></div>`;
}
window.PromptWallThreatGuardrails={render};
}());
