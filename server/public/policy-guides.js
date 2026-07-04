(function(){
'use strict';
const MCP_RE=/^[A-Za-z0-9.*:_/-]{1,160}$/;
const q=(s,el=document)=>el.querySelector(s);
function list(value){return[...new Set(String(value||'').split(/[\n,]+/).map((x)=>x.trim()).filter(Boolean))];}
function cleanId(value,fallback){const id=String(value||'').toLowerCase().replace(/[^a-z0-9_-]+/g,'_').replace(/^_+|_+$/g,'').slice(0,64);return id||fallback;}
function field(id){const el=q(`#${id}`);return el?el.value:'';}
function numberField(id,min,max){const raw=field(id);if(raw==='')return null;const value=Number(raw);return Number.isFinite(value)?Math.max(min,Math.min(max,Math.round(value))):null;}
function status(message){const el=q('#polSaved');if(el)el.textContent=message;}
function visible(ready){const root=q('#policyGuidedControls');if(root)root.classList.toggle('hidden',!ready);}
function updateVisibility(){visible(!!(q('#savePolicy')&&q('#pol_mcp_allowed_tools')&&q('#pol_approval_routing_rules')));}
function textareaList(selector){const el=q(selector);return el?list(el.value):[];}
function writeTextareaList(selector,items){const el=q(selector);if(el)el.value=[...new Set(items)].join('\n');}
function parseJsonArray(selector,label){const el=q(selector);if(!el)return null;const raw=String(el.value||'').trim();if(!raw)return[];try{const parsed=JSON.parse(raw);if(!Array.isArray(parsed))throw new Error('array');return parsed;}catch(_){alert(`${label} must be valid JSON array syntax.`);return null;}}
function writeJsonArray(selector,items){const el=q(selector);if(el)el.value=JSON.stringify(items,null,2);}
function routeMatchers(){
  const out={};
  [['groups','route_builder_groups'],['destinations','route_builder_destinations'],['categories','route_builder_categories'],['detectors','route_builder_detectors']].forEach(([key,id])=>{const values=list(field(id));if(values.length)out[key]=values;});
  return out;
}
function suggestedRouteId(){
  const pieces=[field('route_builder_group'),field('route_builder_groups'),field('route_builder_destinations'),field('route_builder_categories'),field('route_builder_detectors')].map((x)=>list(x)[0]||x).filter(Boolean);
  return cleanId(`route_${pieces.join('_')}`,'approval_route');
}
function applyMcpRule(){
  const pattern=field('mcp_builder_pattern').trim();
  const decision=field('mcp_builder_decision')||'approval';
  if(!MCP_RE.test(pattern)){status('Invalid MCP tool pattern');return;}
  const selectors={allowed:'#pol_mcp_allowed_tools',blocked:'#pol_mcp_blocked_tools',approval:'#pol_mcp_approval_required_tools'};
  Object.values(selectors).forEach((selector)=>writeTextareaList(selector,textareaList(selector).filter((item)=>item!==pattern)));
  writeTextareaList(selectors[decision],textareaList(selectors[decision]).concat(pattern));
  status(`Applied MCP rule ${pattern}`);
}
function addApprovalRoute(){
  const matchers=routeMatchers();
  const severity=numberField('route_builder_severity',0,4);
  const risk=numberField('route_builder_risk',0,100);
  if(!Object.keys(matchers).length&&severity==null&&risk==null){status('Approval route needs a matcher');return;}
  const group=cleanId(field('route_builder_group'),'');
  if(!group){status('Approval route needs an assigned group');return;}
  const sla=numberField('route_builder_sla',15,7*24*60)||60;
  const rule={id:cleanId(field('route_builder_id'),suggestedRouteId()),...matchers,assignedGroup:group,assignedRole:field('route_builder_role')||'approver',slaMinutes:sla};
  if(severity!=null)rule.minSeverity=severity;
  if(risk!=null)rule.minRiskScore=risk;
  const reason=cleanId(field('route_builder_reason'),'');
  if(reason)rule.reason=reason;
  const existing=parseJsonArray('#pol_approval_routing_rules','Approval routing rules');
  if(existing==null)return;
  writeJsonArray('#pol_approval_routing_rules',existing.filter((item)=>item&&item.id!==rule.id).concat(rule));
  status(`Added route ${rule.id}`);
}
document.addEventListener('change',(event)=>{
  if(event.target&&event.target.id==='mcp_builder_preset'&&event.target.value){const input=q('#mcp_builder_pattern');if(input)input.value=event.target.value;}
  updateVisibility();
});
document.addEventListener('click',(event)=>{
  const button=event.target&&event.target.closest('button');
  if(!button)return;
  if(button.id==='addMcpToolRule'){applyMcpRule();return;}
  if(button.id==='addApprovalRoute')addApprovalRoute();
});
new MutationObserver(updateVisibility).observe(document.documentElement,{childList:true,subtree:true});
document.addEventListener('DOMContentLoaded',updateVisibility);
}());
