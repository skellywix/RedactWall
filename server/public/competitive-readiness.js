'use strict';

(function(){
  const $=(s)=>document.querySelector(s);
  const esc=(v)=>String(v??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const stateText=(s)=>({leader:'Leader',pilot_ready:'Pilot ready',close_gap:'Close gap',gap:'Gap'})[s]||'Review';
  const tone=(s)=>s==='leader'||s==='pilot_ready'?'ready':s==='gap'?'blocked':'attention';
  const itemList=(label,items,empty)=>`<div class="hardening-list"><b>${esc(label)}</b><ul>${(items&&items.length?items:[empty]).map((x)=>`<li>${esc(x)}</li>`).join('')}</ul></div>`;
  let loading=false;

  function segmentParam(){
    const select=$('#postureSegmentSelect');
    const value=select&&select.value&&select.value!=='all'?select.value:'';
    return value?`&segment=${encodeURIComponent(value)}`:'';
  }

  function render(report){
    const summary=$('#competitiveReadinessSummary');
    const target=$('#competitiveReadinessRows');
    if(!summary||!target)return;
    if(!report||!report.summary){
      summary.textContent='Waiting for data';
      target.innerHTML='<div class="signal-empty"><b>No readiness data</b><p>Refresh posture.</p></div>';
      return;
    }
    const s=report.summary||{};
    const rows=Array.isArray(report.matrix)?report.matrix:[];
    summary.textContent=`${s.ready||0}/${s.total||0} ready / ${s.score||0}/100 / ${s.privacy||'metadata only'}`;
    target.innerHTML=rows.length?`<div class="hardening-board competitive-readiness-board">
      ${rows.map((row)=>`<article class="hardening-card ${tone(row.state)}">
        <div class="hardening-head">
          <div class="hardening-title"><strong>${esc(row.label)}</strong></div>
          <div class="hardening-score">${esc(row.score||0)}<span>/100</span></div>
        </div>
        <p class="hardening-desc">${esc(row.marketBar||row.detail||'')}</p>
        <div class="hardening-meta"><span>${esc(stateText(row.state))}</span><span>${esc(row.source||'posture')}</span></div>
        <div class="hardening-lists">
          ${itemList('Proof',row.evidence,'Awaiting proof')}
          ${itemList('Missing',row.gaps,'No open gaps')}
        </div>
        <button class="ghost mini" type="button" data-tab-jump="${esc(row.targetTab||'monitor')}">${esc(row.action||'Open')}</button>
      </article>`).join('')}
    </div>`:'<div class="signal-empty"><b>No matrix</b><p>Posture did not publish competitive rows.</p></div>';
  }

  async function load(){
    const target=$('#competitiveReadinessRows');
    if(!target||loading)return;
    loading=true;
    try{
      const res=await fetch('/api/posture?limit=5000'+segmentParam(),{credentials:'same-origin'});
      if(!res.ok)throw new Error('posture unavailable');
      const body=await res.json();
      render(body&&body.competitiveReadiness);
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

  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);
  else boot();
})();
