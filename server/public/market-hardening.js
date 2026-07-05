'use strict';

(function(){
  const $=(s)=>document.querySelector(s);
  const esc=(v)=>String(v??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const tone=(s)=>s==='leader'||s==='pilot_ready'?'ready':s==='gap'?'blocked':'attention';
  const label=(s)=>({leader:'Leader',pilot_ready:'Pilot ready',close_gap:'Close gap',gap:'Gap'})[s]||'Review';
  let loading=false;

  function segmentParam(){
    const select=$('#postureSegmentSelect');
    const value=select&&select.value&&select.value!=='all'?select.value:'';
    return value?`&segment=${encodeURIComponent(value)}`:'';
  }

  function miniList(title,items,empty){
    const rows=Array.isArray(items)&&items.length?items:[empty];
    return `<div class="market-hardening-list"><b>${esc(title)}</b>${rows.map((item)=>`<span>${esc(item)}</span>`).join('')}</div>`;
  }

  function render(focus){
    const summary=$('#marketHardeningSummary');
    const target=$('#marketHardeningRows');
    if(!summary||!target)return;
    const s=focus&&focus.summary||null;
    const lanes=focus&&Array.isArray(focus.lanes)?focus.lanes:[];
    if(!s){
      summary.textContent='Waiting for competitive focus';
      target.innerHTML='<div class="signal-empty"><b>No focus data</b><p>Refresh posture to build the market hardening flow.</p></div>';
      return;
    }
    summary.textContent=`${s.ready||0}/${s.total||0} pilot-ready / ${s.score||0}/100 / ${s.privacy||'metadata only'}`;
    target.innerHTML=`<div class="market-hardening-brief">
      <div><strong>${esc(s.objective||'Beat the top-three competitive bar')}</strong><span>${esc(s.nextLane||'Next lane')} / ${esc(s.nextAction||'Keep moving')}</span></div>
      <b>${esc(s.score||0)}<small>/100</small></b>
    </div>
    <div class="market-hardening-board">
      ${lanes.map((lane)=>`<article class="market-hardening-card ${tone(lane.state)}">
        <div class="market-hardening-head">
          <div><span>${esc((lane.competitors||[]).join(' + ')||'Market bar')}</span><strong>${esc(lane.label)}</strong></div>
          <b>${esc(lane.score||0)}<small>/100</small></b>
        </div>
        <p>${esc(lane.marketBar||'')}</p>
        <div class="market-hardening-state"><span>${esc(label(lane.state))}</span><span>${esc(lane.status||'review')}</span></div>
        <div class="market-hardening-columns">
          ${miniList('Proof',lane.evidence,'Awaiting proof')}
          ${miniList('Gap',lane.gaps,'No open gap')}
        </div>
        <div class="market-hardening-actions">
          <button class="ghost mini" type="button" data-tab-jump="${esc(lane.targetTab||'monitor')}">${esc(lane.action||'Open')}</button>
          ${lane.anchor?`<button class="ghost mini" type="button" data-market-anchor="${esc(lane.anchor)}">Jump to proof</button>`:''}
        </div>
      </article>`).join('')}
    </div>`;
  }

  async function load(){
    const target=$('#marketHardeningRows');
    if(!target||loading)return;
    loading=true;
    try{
      const res=await fetch('/api/posture?limit=5000'+segmentParam(),{credentials:'same-origin'});
      if(!res.ok)throw new Error('posture unavailable');
      const body=await res.json();
      render(body&&body.competitiveFocus);
    }catch{
      render(null);
    }finally{
      loading=false;
    }
  }

  document.addEventListener('click',(event)=>{
    const anchor=event.target.closest('[data-market-anchor]');
    if(anchor){
      const target=document.getElementById(anchor.dataset.marketAnchor||'');
      if(target)target.scrollIntoView({block:'start',behavior:'smooth'});
      return;
    }
    if(event.target.closest('#monitorRefresh')||event.target.closest('[data-posture-segment]'))setTimeout(load,450);
  });
  document.addEventListener('change',(event)=>{if(event.target&&event.target.id==='postureSegmentSelect')setTimeout(load,450);});
  window.RedactWallMarketHardening={load,render};
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);
  else load();
}());
