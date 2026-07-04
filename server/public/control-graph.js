(function(){
'use strict';
function status(value){const v=String(value||'idle');return ['online','warning','error','idle'].includes(v)?v:'idle';}
function empty(title,body,safe){return `<div class="signal-empty"><b>${safe(title)}</b><p>${safe(body)}</p></div>`;}
function render(currentPosture,deps){
  const q=deps.$,safe=deps.escapeHtml,graph=currentPosture&&currentPosture.controlGraph&&typeof currentPosture.controlGraph==='object'?currentPosture.controlGraph:null;
  const summary=q('#controlGraphSummary'),target=q('#controlGraphMap');
  if(!summary||!target)return;
  const s=graph&&graph.summary&&typeof graph.summary==='object'?graph.summary:{};
  const lanes=graph&&Array.isArray(graph.lanes)?graph.lanes:[];
  const nodes=graph&&Array.isArray(graph.nodes)?graph.nodes:[];
  const edges=graph&&Array.isArray(graph.edges)?graph.edges:[];
  const nodesByLane=new Map();
  nodes.forEach((node)=>{const lane=node&&node.lane?node.lane:'assets';if(!nodesByLane.has(lane))nodesByLane.set(lane,[]);nodesByLane.get(lane).push(node);});
  summary.textContent=graph?`${s.nodes||0} nodes / ${s.edges||0} links / ${s.highRiskAssets||0} high risk / ${s.privacy||'prompt bodies excluded'}`:'Waiting for data';
  if(!graph||(!nodes.length&&!edges.length)){target.innerHTML=empty('No graph','Awaiting events.',safe);return;}
  const laneHtml=lanes.map((lane)=>{
    const laneNodes=nodesByLane.get(lane.id)||[];
    return `<section class="control-graph-lane">
      <div class="control-graph-lane-head">
        <div><strong>${safe(lane.label||'Lane')}</strong><small>${safe(lane.detail||'')}</small></div>
        <b>${safe(lane.count||laneNodes.length||0)}</b>
      </div>
      <div class="control-graph-node-list">${laneNodes.length?laneNodes.map((node)=>`<button class="control-graph-node ${safe(status(node.status))}" type="button" data-tab-jump="${safe(node.targetTab||'monitor')}" title="${safe(node.detail||'')}">
        <span>${safe(node.kind||node.lane||'node')}</span><strong>${safe(node.label||'Unknown')}</strong><small>${safe(node.detail||'Awaiting proof')}</small>
      </button>`).join(''):empty('Empty','No sanitized evidence.',safe)}</div>
    </section>`;
  }).join('');
  const labelFor=(id)=>{const node=nodes.find((item)=>item.id===id);return node?node.label:id;};
  const edgeHtml=`<section class="control-graph-edges">
    <div class="control-graph-edges-head"><strong>Highest-risk links</strong><span>${safe(s.controlledLinks||0)} controlled / ${safe(s.mcpLinks||0)} MCP</span></div>
    ${edges.length?edges.slice(0,10).map((edge)=>`<div class="control-graph-edge ${safe(status(edge.status))}">
      <span>${safe(edge.status||'idle')}</span>
      <div><strong>${safe(labelFor(edge.from))} -> ${safe(labelFor(edge.to))}</strong><small>${safe(edge.label||'flow')} / ${safe(edge.detail||'sanitized metadata only')}</small></div>
      <b>${safe(edge.events||0)}</b>
    </div>`).join(''):empty('No links','Awaiting links.',safe)}
  </section>`;
  target.innerHTML=`<div class="control-graph-lanes">${laneHtml}</div>${edgeHtml}`;
}
window.PromptWallControlGraph={render};
}());
