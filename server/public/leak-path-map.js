(function(){
'use strict';
const LENSES=[{id:'before',label:'Before PromptWall'},{id:'with',label:'With PromptWall'}];
const LOCK='<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 10V8a5 5 0 0 1 10 0v2m-11 0h12v10H6V10Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>';
const SCENARIOS=[
  {id:'member-data',label:'Member data',payload:'Member SSN and account numbers (masked findings only)',
    actor:'Member services rep',via:'Browser paste into governed chat',sourceKey:'browser_extension',
    dest:'ChatGPT (governed)',destKind:'Governed app',verdict:'Blocked',tone:'blocked',
    leak:'Member SSN leaves the device inside a chat prompt',
    saved:'Hard stop before egress; the prompt never reached the model',
    statKey:'blocked',statLabel:'blocked',cta:{label:'Open approval queue',tab:'queue'}},
  {id:'loan-file',label:'Loan file',payload:'Loan application with income and SSN fields (masked findings only)',
    actor:'Lending analyst',via:'Desktop file upload',sourceKey:'endpoint_agent',
    dest:'Claude (governed)',destKind:'Governed app',verdict:'Approval required',tone:'approval',
    leak:'A full loan file is uploaded to an AI tool with no review',
    saved:'Held in the approval queue until a security admin releases it',
    statKey:'pending',statLabel:'awaiting review',cta:{label:'Open approval queue',tab:'queue'}},
  {id:'source-code',label:'Source code',payload:'Proprietary code with an embedded credential (masked finding only)',
    actor:'Engineer',via:'Desktop AI app paste',sourceKey:'endpoint_agent',
    dest:'Unapproved desktop AI',destKind:'Shadow AI',verdict:'Redacted',tone:'redacted',
    leak:'Source code and a live credential reach an ungoverned tool',
    saved:'Credential masked on-device before anything left the endpoint',
    statKey:'redacted',statLabel:'redacted',cta:{label:'Review shadow AI',tab:'coverage'}},
  {id:'contract',label:'Contract',payload:'Customer contract terms and counterparty PII (masked findings only)',
    actor:'Legal team',via:'Document upload to AI assistant',sourceKey:'browser_extension',
    dest:'Gemini (governed)',destKind:'Governed app',verdict:'Logged',tone:'logged',
    leak:'Confidential contract context is exposed to a third-party model',
    saved:'User coached; sanitized receipt captured for examiners',
    statKey:'coached',statLabel:'coached',cta:{label:'Export evidence pack',tab:'audit'}},
  {id:'mcp-pull',label:'MCP document pull',payload:'Drive/SharePoint document context pulled by an agent (sanitized metadata only)',
    actor:'AI agent (MCP)',via:'Connector tool call',sourceKey:'mcp_guard',
    dest:'Drive connector to LLM',destKind:'MCP connector',verdict:'Redacted',tone:'redacted',
    leak:'An agent pulls whole customer documents into model context',
    saved:'Connector payload transformed before model access',
    statKey:'mcpControlled',statLabel:'controlled',cta:{label:'Review MCP policy',tab:'policy'}},
];
const state={scenario:'member-data',lens:'with',node:'control'};
let last=null,bound=false;
const num=(v)=>{const x=Number(v);return Number.isFinite(x)&&x>0?Math.round(x):0;};
function reduceMotion(){try{return Boolean(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches);}catch{return false;}}
function stats(p){
  const s=(p&&p.summary)||{};const inv=(p&&p.aiInventory&&p.aiInventory.summary)||{};const mcp=(p&&p.agenticMcp&&p.agenticMcp.summary)||{};
  return{blocked:num(s.blocked),redacted:num(s.redacted),pending:num(s.pending),coached:num(s.coached),
    events:num(s.events),sensitive:num(s.sensitiveEvents),shadowApps:num(inv.shadow),shadowEvents:num(s.shadowEvents),
    mcpControlled:num(mcp.controlled),mcpEvents:num(mcp.events)};
}
function surfaceBy(p,source){return ((p&&p.surfaces)||[]).find((item)=>item&&item.source===source&&item.id!=='surface-shadow-ai')||null;}
function auditSurface(p){return ((p&&p.surfaces)||[]).find((item)=>item&&item.id==='surface-audit-evidence')||null;}
function latestSignal(p,sourceKey){return ((p&&p.events)||[]).find((item)=>item&&item.source===sourceKey)||null;}
function destDetail(s,st){
  if(s.destKind==='Shadow AI')return `${st.shadowApps} shadow apps / ${st.shadowEvents} sightings`;
  if(s.destKind==='MCP connector')return `${st.mcpEvents} connector events observed`;
  return `${st.events} sanitized events in window`;
}
function controlNode(s,p,withLens,safe){
  const surface=surfaceBy(p,s.sourceKey);
  const health=surface?`${surface.name} / ${num(surface.health)}% health`:'Awaiting sensor evidence';
  if(!withLens)return `<span>PromptWall</span><strong>No control point</strong><small>Uninspected path — nothing stands between the data and the model</small>`;
  return `<span>PromptWall ${LOCK}</span><em class="leak-verdict ${safe(s.tone)}">${safe(s.verdict)}</em><small>${safe(health)}</small>`;
}
function rowHtml(s,p,st,safe){
  const withLens=state.lens==='with';
  const selected=state.scenario===s.id;
  const cut=withLens&&s.tone==='blocked';
  const linkTone=withLens?(cut?'is-cut':'is-safe'):'is-leak';
  const link=(cls)=>`<span class="leak-link ${cls}" aria-hidden="true"><i class="leak-pulse"></i></span>`;
  const outcome=withLens
    ?`<span>Prevented + proven</span><strong>${safe(s.saved)}</strong><small>${safe(s.verdict)} / sanitized receipt captured</small>`
    :`<span>Exposure</span><strong>${safe(s.leak)}</strong><small>No block, no redaction, no audit trail</small>`;
  const node=(kind,body,cls)=>`<button class="leak-node ${cls||''}" type="button" data-leak-pick="${safe(s.id)}" data-leak-node="${kind}" aria-pressed="${selected&&state.node===kind}">${body}</button>`;
  return `<div class="leak-path-row ${withLens?safe(s.tone):'leaking'}${selected?' is-selected':''}" data-leak-scenario="${safe(s.id)}">
    ${node('source',`<span>Source</span><strong>${safe(s.actor)}</strong><small>${safe(s.via)}</small>`)}
    ${link(linkTone)}
    ${node('control',controlNode(s,p,withLens,safe),withLens?'is-armed':'is-absent')}
    ${link(cut?'is-cut is-ends':linkTone)}
    ${node('destination',`<span>${safe(s.destKind)}</span><strong>${safe(s.dest)}</strong><small>${safe(destDetail(s,st))}</small>`,s.destKind==='Shadow AI'?'is-shadow':'')}
    ${link(cut?'is-cut is-ends':linkTone)}
    ${node('outcome',outcome,withLens?'is-proof':'is-loss')}
  </div>`;
}
function nodeContext(s,withLens){
  if(state.node==='source')return `${s.actor} — ${s.via}.`;
  if(state.node==='destination')return `Destination: ${s.dest} (${s.destKind}).`;
  if(state.node==='outcome')return withLens?'Outcome with PromptWall in the path.':'Outcome with no control in the path.';
  return withLens?'PromptWall control point on this path.':'The missing control point on this path.';
}
function inspectorHtml(s,p,st,safe){
  const withLens=state.lens==='with';
  const audit=auditSurface(p);
  const signal=latestSignal(p,s.sourceKey);
  const count=num(st[s.statKey]);
  const happened=withLens
    ?`${s.actor} tried "${s.via}" toward ${s.dest}. PromptWall verdict: ${s.verdict}. ${count} ${s.statLabel} in the current window.`
    :`${s.actor}: "${s.via}" toward ${s.dest} with no inspection in the path. ${count} events like this were caught once PromptWall was in place.`;
  const stopped=withLens
    ?`${s.verdict} at the ${surfaceBy(p,s.sourceKey)?surfaceBy(p,s.sourceKey).name:'PromptWall'} control point. ${s.saved}.`
    :'Nothing. This is the exposure view — no control point exists on this path.';
  const proof=withLens
    ?(audit&&audit.status==='online'?`Tamper-evident audit chain: ${audit.description} No prompt bodies stored.`:'Audit chain needs review — evidence integrity is degraded.')
    :'None. Without a gateway there is no record this ever happened.';
  const ctas=[`<button class="ghost mini" type="button" data-tab-jump="${safe(s.cta.tab)}">${safe(s.cta.label)}</button>`];
  if(s.cta.tab!=='audit')ctas.push('<button class="ghost mini" type="button" data-tab-jump="audit">Export evidence pack</button>');
  return `<div class="leak-inspector-head">
      <div><h4>${safe(s.label)} path — ${safe(withLens?'with PromptWall':'before PromptWall')}</h4><p>${safe(nodeContext(s,withLens))}</p></div>
      <div class="leak-inspector-ctas">${ctas.join('')}</div>
    </div>
    <div class="leak-inspector-grid">
      <div class="leak-inspector-field"><span>What happened</span><b>${safe(happened)}</b></div>
      <div class="leak-inspector-field"><span>What would have leaked</span><b>${safe(s.payload)}</b></div>
      <div class="leak-inspector-field"><span>What stopped it</span><b>${safe(stopped)}</b></div>
      <div class="leak-inspector-field"><span>What proof exists</span><b>${safe(proof)}</b></div>
    </div>
    <div class="leak-inspector-evidence">${signal?`Latest sanitized signal: ${safe(signal.title)} (${safe(signal.severity)} / ${safe(signal.relatedMetric||'sanitized metadata')})`:'No sanitized signals for this path in the current window.'}</div>`;
}
function rerender(){if(last)render(last.posture,last.deps);}
function bind(){
  if(bound)return;bound=true;
  document.addEventListener('click',(e)=>{
    const lens=e.target.closest('[data-leak-lens]');
    if(lens){state.lens=lens.dataset.leakLens==='before'?'before':'with';rerender();return;}
    const node=e.target.closest('[data-leak-node]');
    if(node){state.scenario=node.dataset.leakPick||state.scenario;state.node=node.dataset.leakNode||'control';rerender();return;}
    const pick=e.target.closest('[data-leak-pick]');
    if(pick){state.scenario=pick.dataset.leakPick;state.node='control';rerender();}
  });
}
function render(currentPosture,deps){
  const q=deps.$,safe=deps.escapeHtml;
  const summary=q('#leakMapSummary'),lensEl=q('#leakMapLens'),chips=q('#leakMapScenarios'),stage=q('#leakMapStage'),inspector=q('#leakMapInspector');
  if(!summary||!lensEl||!chips||!stage||!inspector)return;
  last={posture:currentPosture,deps};bind();
  const st=stats(currentPosture);
  const scenario=SCENARIOS.find((item)=>item.id===state.scenario)||SCENARIOS[0];
  summary.textContent=currentPosture
    ?(st.events?`${st.sensitive} sensitive events / ${st.blocked+st.redacted} stopped or transformed / ${st.pending} awaiting approval / prompt bodies excluded`:'No sanitized activity yet — showing every potential leak path / prompt bodies excluded')
    :'Waiting for posture data — showing every potential leak path';
  lensEl.innerHTML=LENSES.map((lens)=>`<button class="leak-lens-button${state.lens===lens.id?' is-active':''}" type="button" data-leak-lens="${lens.id}" aria-pressed="${state.lens===lens.id}">${lens.label}</button>`).join('');
  chips.innerHTML=SCENARIOS.map((item)=>`<button class="leak-scenario-chip${state.scenario===item.id?' is-active':''}" type="button" data-leak-pick="${safe(item.id)}" aria-pressed="${state.scenario===item.id}">${safe(item.label)}<b>${num(st[item.statKey])}</b></button>`).join('');
  stage.className=`leak-map-stage lens-${state.lens}${reduceMotion()?' is-static':''}`;
  stage.innerHTML=`<div class="leak-map-legend" aria-hidden="true"><span>Where it starts</span><i></i><span>PromptWall control</span><i></i><span>AI destination</span><i></i><span>Consequence &amp; proof</span></div>`
    +SCENARIOS.map((item)=>rowHtml(item,currentPosture,st,safe)).join('');
  inspector.innerHTML=inspectorHtml(scenario,currentPosture,st,safe);
}
window.PromptWallLeakPathMap={render};
}());
