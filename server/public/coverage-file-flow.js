'use strict';

(function(){
  const $=(s)=>document.querySelector(s);
  const esc=(v)=>String(v??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const tone=(state)=>state==='covered'?'secure':state==='attention'||state==='missing'?'warn':'live';
  const label=(state)=>state==='covered'?'Covered':state==='attention'?'Attention':state==='missing'?'Missing':'Review';
  let loading=false;

  function meta(profile){
    const parts=[];
    if(profile.user)parts.push(profile.user);
    if(profile.orgId)parts.push(profile.orgId);
    if(Array.isArray(profile.platforms)&&profile.platforms.length)parts.push(profile.platforms.join(', '));
    if(profile.lastSeen)parts.push(`Last seen ${profile.lastSeen}`);
    parts.push('Local path: not reported');
    return parts.join(' | ');
  }

  function render(report){
    const target=$('#endpointFileFlowRows');
    if(!target)return;
    const rows=Array.isArray(report&&report.endpointFileFlowProfiles)?report.endpointFileFlowProfiles:[];
    target.innerHTML=rows.length?rows.map((profile)=>`<div class="tool-row">
      <div>
        <strong>${esc(profile.id||'unnamed_profile')}</strong>
        <span>${esc(meta(profile))}</span>
      </div>
      <div class="tool-state">
        <span class="status-chip tone-${tone(profile.state)}" tabindex="0" role="button" data-tooltip="${esc(profile.detail||label(profile.state))}" data-status-detail="${esc(`${profile.detail||label(profile.state)}\nLocal path: not reported`)}"><span class="status-light tone-${tone(profile.state)}" aria-hidden="true"></span>${esc(label(profile.state))}</span>
        <span>${esc(profile.detail||'configured profile')}</span>
      </div>
    </div>`).join(''):'<div class="signal-empty"><b>No file-flow profiles</b><p>Endpoint watchers appear here without local paths.</p></div>';
  }

  async function load(){
    const target=$('#endpointFileFlowRows');
    if(!target||loading)return;
    loading=true;
    try{
      const res=await fetch('/api/coverage',{credentials:'same-origin'});
      if(!res.ok)throw new Error('coverage unavailable');
      render(await res.json());
    }catch{
      render(null);
    }finally{
      loading=false;
    }
  }

  function boot(){
    load();
    addEventListener('pw:c',(e)=>render(e.detail));
  }

  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);
  else boot();
})();
