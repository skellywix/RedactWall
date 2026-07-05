'use strict';

(function(){
  const $=(s)=>document.querySelector(s);
  const esc=(v)=>String(v??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const tone=(state)=>state==='ready'?'secure':state==='blocked'?'critical':'warn';
  let loading=false;

  function segmentParam(){
    const select=$('#postureSegmentSelect');
    const value=select&&select.value&&select.value!=='all'?select.value:'';
    return value?`&segment=${encodeURIComponent(value)}`:'';
  }

  function bar(label,score,detail,value,state){
    const width=Math.max(5,Math.min(100,Number(score)||0));
    return `<div class="control-row">
      <div><strong>${esc(label)}</strong><span>${esc(value)} / ${esc(score||0)}/100</span></div>
      <div class="control-bar" role="img" aria-label="${esc(`${label} ${score||0} out of 100`)}"><i class="tone-${tone(state)}" style="--w:${width}%"></i></div>
      <span>${esc(detail)}</span>
    </div>`;
  }

  function render(report){
    const summary=$('#decisionQualitySummary');
    const target=$('#decisionQualityRows');
    if(!summary||!target)return;
    const quality=report&&report.decisionQuality;
    if(!quality||!quality.summary){
      summary.textContent='Waiting for data';
      target.innerHTML='<div class="signal-empty"><b>No decision quality data</b><p>Recent approval, coaching, and override outcomes appear here.</p></div>';
      return;
    }
    const s=quality.summary;
    const cards=Array.isArray(quality.cards)?quality.cards:[];
    const hotspots=Array.isArray(quality.hotspots)?quality.hotspots:[];
    summary.textContent=`${s.controlRate||0}% controlled / ${s.pendingReviews||0} pending / ${s.overrideWatch||0} overrides`;
    const cardRows=cards.map((card)=>bar(card.label,card.score,card.detail,card.value,card.state)).join('');
    const hotspotRows=hotspots.slice(0,4).map((item)=>`<div class="control-row">
      <div><strong>${esc(item.label)}</strong><span>${esc(item.kind)} / ${esc(item.events)} events</span></div>
      <div class="control-bar" role="img" aria-label="${esc(`${item.label} ${item.events} events`)}"><i style="--w:${Math.max(5,Math.min(100,Number(item.sensitive)||0))}%"></i></div>
      <span>${esc(item.detail||'metadata-only hotspot')}</span>
    </div>`).join('');
    target.innerHTML=`${cardRows}${hotspotRows?`<div class="control-row"><div><strong>Decision Hotspots</strong><span>metadata only</span></div></div>${hotspotRows}`:''}`;
  }

  async function load(){
    const target=$('#decisionQualityRows');
    if(!target||loading)return;
    loading=true;
    try{
      const res=await fetch('/api/posture?limit=5000'+segmentParam(),{credentials:'same-origin'});
      if(!res.ok)throw new Error('posture unavailable');
      render(await res.json());
    }catch{
      render(null);
    }finally{
      loading=false;
    }
  }

  function boot(){
    load();
    document.addEventListener('click',(e)=>{
      if(e.target.closest('#monitorRefresh')||e.target.closest('[data-posture-segment]'))setTimeout(load,450);
    });
    document.addEventListener('change',(e)=>{
      if(e.target&&e.target.id==='postureSegmentSelect')setTimeout(load,450);
    });
  }

  window.RedactWallDecisionQuality={load,render};
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);
  else boot();
})();
