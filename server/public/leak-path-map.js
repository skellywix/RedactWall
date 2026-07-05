(function(){
'use strict';
const FILTERS=[{id:'all',label:'All flows'},{id:'risk',label:'At-risk'},{id:'shadow',label:'Shadow AI'}];
const W=1000,SEG_X=234,CH_L=436,CH_R=564,DEST_X=766,NODE_W=224,NODE_H=52,CH_W=128,CH_H=46,PAD_TOP=52,PAD_BOT=18,ROW_H=78;
const state={filter:'all',category:'',selected:null};
let last=null,bound=false;
const num=(v)=>{const x=Number(v);return Number.isFinite(x)&&x>0?Math.round(x):0;};
function reduceMotion(){try{return Boolean(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches);}catch{return false;}}
function trim(value,max){const text=String(value||'');return text.length>max?`${text.slice(0,max-1)}…`:text;}
function graph(posture){return posture&&posture.leakMap&&typeof posture.leakMap==='object'?posture.leakMap:null;}
function edgeVisible(edge,dests){
  if(state.filter==='risk'&&!(num(edge.uncontrolled)||num(edge.shadow)||num(edge.pending)))return false;
  if(state.filter==='shadow'&&!(num(edge.shadow)||(dests.get(edge.to)||{}).state==='shadow'))return false;
  if(state.category&&!(edge.categories||[]).some((item)=>item.label===state.category))return false;
  return true;
}
function edgeTone(edge,dests){
  if(num(edge.shadow)||(dests.get(edge.to)||{}).state==='shadow')return 'is-shadow';
  if(num(edge.uncontrolled))return 'is-leak';
  if(num(edge.pending))return 'is-held';
  return 'is-clean';
}
function edgeWidth(edge){return (1.6+Math.min(4.4,Math.log2(num(edge.events)+1))).toFixed(1);}
function yFor(index,count,height){const usable=height-PAD_TOP-PAD_BOT;return PAD_TOP+usable*((index+0.5)/Math.max(1,count));}
function destKicker(dest){
  const stateName=String(dest.state||'observed');
  if(stateName==='sanctioned')return 'GOVERNED';
  if(stateName==='shadow')return 'SHADOW AI';
  if(stateName==='unsanctioned')return 'UNSANCTIONED';
  return stateName.toUpperCase();
}
function nodeSub(item){
  const parts=[];
  if(num(item.uncontrolled))parts.push(`${num(item.uncontrolled)} uncontrolled`);
  if(num(item.shadow))parts.push(`${num(item.shadow)} shadow`);
  if(num(item.pending))parts.push(`${num(item.pending)} held`);
  if(!parts.length&&num(item.redacted))parts.push(`${num(item.redacted)} redacted`);
  if(!parts.length&&num(item.blocked))parts.push(`${num(item.blocked)} stopped`);
  if(!parts.length)parts.push(`${num(item.events)} events`);
  return parts.slice(0,2).join(' / ');
}
function boxNode(item,kind,x,y,kicker,safe,dim){
  const cls=`leak-node ${safe(item.status||'idle')}${dim?' is-dim':''}${state.selected&&state.selected.id===`${kind}:${item.id}`?' is-active':''}`;
  return `<g class="${cls}" data-leak-node="${safe(kind)}:${safe(item.id)}" role="button" tabindex="0" aria-label="${safe(`${item.label}: ${nodeSub(item)}`)}">
    <rect x="${x}" y="${y-NODE_H/2}" width="${NODE_W}" height="${NODE_H}" rx="9"></rect>
    <text class="leak-node-kicker" x="${x+12}" y="${y-9}">${safe(kicker)}</text>
    <text class="leak-node-title" x="${x+12}" y="${y+7}">${safe(trim(item.label,30))}</text>
    <text class="leak-node-sub" x="${x+12}" y="${y+21}">${safe(nodeSub(item))}</text>
  </g>`;
}
function channelNode(item,y,safe){
  const x=(CH_L+CH_R)/2-CH_W/2;
  const cls=`leak-node leak-channel ${safe(item.status||'idle')}${state.selected&&state.selected.id===`channel:${item.id}`?' is-active':''}`;
  return `<g class="${cls}" data-leak-node="channel:${safe(item.id)}" role="button" tabindex="0" aria-label="${safe(`${item.label} control point: ${nodeSub(item)}`)}">
    <rect x="${x}" y="${y-CH_H/2}" width="${CH_W}" height="${CH_H}" rx="9"></rect>
    <text class="leak-node-title" x="${x+CH_W/2}" y="${y-3}" text-anchor="middle">${safe(trim(item.label,14))}</text>
    <text class="leak-node-sub" x="${x+CH_W/2}" y="${y+13}" text-anchor="middle">${safe(nodeSub(item))}</text>
  </g>`;
}
function flowPath(x1,y1,x2,y2){const mid=(x1+x2)/2;return `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`;}
function edgePaths(edge,pos,dests,safe,still){
  const from=pos.segments.get(edge.from),via=pos.channels.get(edge.via)||pos.channels.get('api')||[...pos.channels.values()][0],to=pos.destinations.get(edge.to);
  if(from===undefined||via===undefined||to===undefined)return '';
  const tone=edgeTone(edge,dests);
  const width=edgeWidth(edge);
  const flow=still?'':' leak-flow';
  const inbound=flowPath(SEG_X,from,CH_L,via);
  const escapes=num(edge.uncontrolled)||num(edge.shadow)||num(edge.events)>num(edge.blocked)+num(edge.coached);
  const outbound=escapes?flowPath(CH_R,via,DEST_X,to):'';
  const stop=escapes?'':`<circle class="leak-stop" cx="${CH_R+10}" cy="${via}" r="5"></circle>`;
  return `<g class="leak-edge ${tone}" data-leak-edge="${safe(edge.id)}">
    <path class="leak-line${flow}" d="${inbound}" stroke-width="${width}"></path>
    ${outbound?`<path class="leak-line${flow}" d="${outbound}" stroke-width="${width}"></path>`:stop}
    <path class="leak-hit" d="${inbound}"></path>
    ${outbound?`<path class="leak-hit" d="${outbound}"></path>`:''}
    <title>${safe(`${edge.from.split(':').pop()} -> ${edge.to}: ${nodeSub(edge)}`)}</title>
  </g>`;
}
function stageSvg(map,safe,still){
  const rows=Math.max(map.segments.length,map.channels.length,map.destinations.length,3);
  const height=PAD_TOP+PAD_BOT+rows*ROW_H;
  const dests=new Map(map.destinations.map((item)=>[item.id,item]));
  const pos={
    segments:new Map(map.segments.map((item,i)=>[item.id,yFor(i,map.segments.length,height)])),
    channels:new Map(map.channels.map((item,i)=>[item.id,yFor(i,map.channels.length,height)])),
    destinations:new Map(map.destinations.map((item,i)=>[item.id,yFor(i,map.destinations.length,height)])),
  };
  const visible=map.edges.filter((edge)=>edgeVisible(edge,dests));
  const touched=new Set();
  visible.forEach((edge)=>{touched.add(`segment:${edge.from}`);touched.add(`channel:${edge.via}`);touched.add(`destination:${edge.to}`);});
  const dim=(kind,id)=>visible.length>0&&!touched.has(`${kind}:${id}`);
  return `<svg viewBox="0 0 ${W} ${height}" role="img" aria-label="Map of sensitive data paths from departments through RedactWall to AI destinations">
    <text class="leak-col-label" x="10" y="24">DEPARTMENTS &amp; TEAMS</text>
    <text class="leak-col-label" x="${(CH_L+CH_R)/2}" y="24" text-anchor="middle">REDACTWALL</text>
    <text class="leak-col-label" x="${W-10}" y="24" text-anchor="end">AI DESTINATIONS</text>
    <rect class="leak-wall" x="${(CH_L+CH_R)/2-23}" y="${PAD_TOP-18}" width="46" height="${height-PAD_TOP-PAD_BOT+30}" rx="14"></rect>
    ${visible.map((edge)=>edgePaths(edge,pos,dests,safe,still)).join('')}
    ${map.segments.map((item)=>boxNode(item,'segment',10,pos.segments.get(item.id),`${item.typeLabel||'Segment'}${num(item.users)?` · ${num(item.users)} user${num(item.users)===1?'':'s'}`:''}`,safe,dim('segment',item.id))).join('')}
    ${map.channels.map((item)=>channelNode(item,pos.channels.get(item.id),safe)).join('')}
    ${map.destinations.map((item)=>boxNode(item,'destination',DEST_X,pos.destinations.get(item.id),destKicker(item),safe,dim('destination',item.id))).join('')}
  </svg>`;
}
function findSelected(map){
  if(state.selected){
    if(state.selected.kind==='edge'){const edge=map.edges.find((item)=>item.id===state.selected.id);if(edge)return{kind:'edge',edge};}
    else{
      const[kind,...rest]=state.selected.id.split(':');const id=rest.join(':');
      const list=kind==='segment'?map.segments:kind==='channel'?map.channels:map.destinations;
      const node=list.find((item)=>item.id===id);if(node)return{kind,node};
    }
  }
  return map.edges.length?{kind:'edge',edge:map.edges[0]}:null;
}
function inspectorFlows(item){
  const categories=(item.categories||[]).map((cat)=>`${cat.label} ×${num(cat.events)}`).join(', ');
  return categories?`${categories} — masked findings only, never raw values.`:`${num(item.sensitive)} sensitive of ${num(item.events)} events — masked findings only, never raw values.`;
}
function inspectorOutcome(item){
  const parts=[];
  if(num(item.blocked))parts.push(`${num(item.blocked)} stopped at the wall`);
  if(num(item.redacted))parts.push(`${num(item.redacted)} redacted before the model`);
  if(num(item.pending))parts.push(`${num(item.pending)} held for approval`);
  if(num(item.coached))parts.push(`${num(item.coached)} coached`);
  if(num(item.uncontrolled))parts.push(`${num(item.uncontrolled)} reached the destination uncontrolled`);
  if(num(item.shadow))parts.push(`${num(item.shadow)} shadow AI sightings`);
  return parts.length?`${parts.join('; ')}.`:'No sensitive findings on this path yet.';
}
function inspectorCtas(map,sel,safe){
  const ctas=[];
  const item=sel.kind==='edge'?sel.edge:sel.node;
  if(num(item.pending))ctas.push('<button class="ghost mini" type="button" data-tab-jump="queue">Open approval queue</button>');
  if((sel.kind==='edge'&&(map.destinations.find((d)=>d.id===sel.edge.to)||{}).state==='shadow')||num(item.shadow))ctas.push('<button class="ghost mini" type="button" data-tab-jump="coverage">Review shadow AI</button>');
  if((sel.kind==='edge'?sel.edge.via:item.id)==='mcp_guard')ctas.push('<button class="ghost mini" type="button" data-tab-jump="policy">Review MCP policy</button>');
  ctas.push('<button class="ghost mini" type="button" data-tab-jump="audit">Export evidence pack</button>');
  return ctas.join('');
}
function inspectorHtml(map,posture,safe){
  const sel=findSelected(map);
  if(!sel)return '<div class="signal-empty"><b>No flows yet</b><p>The map draws itself as sensors report sanitized activity.</p></div>';
  const item=sel.kind==='edge'?sel.edge:sel.node;
  const audit=((posture&&posture.surfaces)||[]).find((surface)=>surface&&surface.id==='surface-audit-evidence');
  const title=sel.kind==='edge'
    ?`${sel.edge.from.split(':').pop().replace(/-/g,' ')} → ${sel.edge.to}`
    :`${item.label} (${sel.kind==='segment'?item.typeLabel||'segment':sel.kind==='channel'?'control point':destKicker(item).toLowerCase()})`;
  const route=sel.kind==='edge'
    ?`Via the ${sel.edge.viaLabel||'API'} control point / ${num(item.users)||''}${num(item.users)?' users / ':''}last seen ${item.lastSeen?new Date(item.lastSeen).toLocaleString():'—'}`
    :`${num(item.events)} events in the ${sel.kind} / last seen ${item.lastSeen?new Date(item.lastSeen).toLocaleString():'—'}`;
  const proof=audit&&audit.status==='online'
    ?`Tamper-evident audit chain verified: ${audit.description||'linked entries verified.'} Sanitized receipts only.`
    :'Audit chain needs review before this path can be evidenced.';
  return `<div class="leak-inspector-head">
      <div><h4>${safe(trim(title,72))}</h4><p>${safe(route)}</p></div>
      <div class="leak-inspector-ctas">${inspectorCtas(map,sel,safe)}</div>
    </div>
    <div class="leak-inspector-grid">
      <div class="leak-inspector-field"><span>What is flowing</span><b>${safe(inspectorFlows(item))}</b></div>
      <div class="leak-inspector-field"><span>Control outcome</span><b>${safe(inspectorOutcome(item))}</b></div>
      <div class="leak-inspector-field${num(item.uncontrolled)||num(item.shadow)?' is-alert':''}"><span>Exposure</span><b>${safe(num(item.uncontrolled)?`${num(item.uncontrolled)} sensitive events left with no control applied.`:num(item.shadow)?`${num(item.shadow)} sightings of ungoverned AI on this path.`:'No uncontrolled egress recorded on this path.')}</b></div>
      <div class="leak-inspector-field"><span>Proof</span><b>${safe(proof)}</b></div>
    </div>`;
}
function plural(count,word){return `${count} ${word}${count===1?'':'s'}`;}
function summaryText(map){
  if(!map)return 'Waiting for posture data';
  const s=map.summary||{};
  if(!num(s.events))return `No sanitized activity yet — the map draws as sensors report flows / ${s.privacy||'prompt bodies excluded'}`;
  return `${plural(num(s.segments),'department')} / ${plural(num(s.destinations),'AI destination')} / ${num(s.uncontrolled)} uncontrolled / ${num(s.shadow)} shadow / ${num(s.controlRate)}% controlled / ${s.privacy||'prompt bodies excluded'}`;
}
function rerender(){if(last)render(last.posture,last.deps);}
function pick(target){
  const node=target.closest('[data-leak-node]');
  if(node){state.selected={kind:'node',id:node.dataset.leakNode};rerender();return true;}
  const edge=target.closest('[data-leak-edge]');
  if(edge){state.selected={kind:'edge',id:edge.dataset.leakEdge};rerender();return true;}
  return false;
}
function bind(){
  if(bound)return;bound=true;
  document.addEventListener('click',(e)=>{
    const filter=e.target.closest('[data-leak-filter]');
    if(filter){state.filter=filter.dataset.leakFilter;rerender();return;}
    const category=e.target.closest('[data-leak-category]');
    if(category){state.category=state.category===category.dataset.leakCategory?'':category.dataset.leakCategory;rerender();return;}
    pick(e.target);
  });
  document.addEventListener('keydown',(e)=>{
    if((e.key==='Enter'||e.key===' ')&&e.target.closest&&e.target.closest('[data-leak-node]')){e.preventDefault();pick(e.target);}
  });
}
function render(currentPosture,deps){
  const q=deps.$,safe=deps.escapeHtml;
  const summary=q('#leakMapSummary'),filters=q('#leakMapLens'),chips=q('#leakMapScenarios'),stage=q('#leakMapStage'),inspector=q('#leakMapInspector');
  if(!summary||!filters||!chips||!stage||!inspector)return;
  last={posture:currentPosture,deps};bind();
  const map=graph(currentPosture);
  summary.textContent=summaryText(map);
  filters.innerHTML=FILTERS.map((item)=>`<button class="leak-lens-button${state.filter===item.id?' is-active':''}" type="button" data-leak-filter="${item.id}" aria-pressed="${state.filter===item.id}">${item.label}</button>`).join('');
  const categories=(map&&map.categories)||[];
  chips.innerHTML=categories.length
    ?categories.map((item)=>`<button class="leak-scenario-chip${state.category===item.label?' is-active':''}" type="button" data-leak-category="${safe(item.label)}" aria-pressed="${state.category===item.label}">${safe(trim(item.label,26))}<b>${num(item.events)}</b></button>`).join('')
    :'<span class="leak-chip-empty">Data types appear as sanitized findings arrive.</span>';
  const still=reduceMotion();
  stage.className=`leak-map-stage${still?' is-static':''}`;
  stage.innerHTML=map&&(map.segments.length||map.destinations.length)
    ?stageSvg(map,safe,still)
    :'<div class="signal-empty"><b>No paths mapped yet</b><p>Connect sensors and the exposure map draws every department-to-AI flow from sanitized events.</p></div>';
  inspector.innerHTML=map?inspectorHtml(map,currentPosture,safe):'';
}
window.RedactWallLeakPathMap={render};
}());
