'use strict';

(function(){
  const $=(s)=>document.querySelector(s);
  const esc=(v)=>String(v??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let csrf='';
  let loading=false;

  async function csrfToken(){
    if(csrf)return csrf;
    const res=await fetch('/api/csrf',{credentials:'same-origin'});
    if(!res.ok)throw new Error('csrf unavailable');
    const body=await res.json();
    csrf=body.csrfToken||'';
    return csrf;
  }

  function bar(label,value,total,detail,state){
    const width=total?Math.max(5,Math.min(100,Math.round((Number(value)||0)/total*100))):5;
    const tone=state==='attention'?'tone-warn':state==='ready'?'tone-secure':'';
    return `<div class="control-row">
      <div><strong>${esc(label)}</strong><span>${esc(value)}/${esc(total)}</span></div>
      <div class="control-bar" role="img" aria-label="${esc(`${label} ${value} of ${total}`)}"><i class="${tone}" style="--w:${width}%"></i></div>
      <span>${esc(detail)}</span>
    </div>`;
  }

  function candidateRow(item){
    return `<div class="control-row">
      <div><strong>${esc(item.detectorId)}</strong><span>${esc(item.destination)} / ${esc(item.status)}</span></div>
      <div class="control-bar" role="img" aria-label="${esc(`${item.detectorId} risk ${item.riskScore||0}`)}"><i style="--w:${Math.max(5,Math.min(100,Number(item.riskScore)||0))}%"></i></div>
      <span>${esc((item.detectorIds||[]).join(', ')||'detector')}</span>
      <div class="action-workflow-controls">
        <button class="ghost mini" type="button" data-detector-feedback="valid" data-query-id="${esc(item.queryId)}" data-detector-id="${esc(item.detectorId)}">Valid</button>
        <button class="ghost mini" type="button" data-detector-feedback="false_positive" data-query-id="${esc(item.queryId)}" data-detector-id="${esc(item.detectorId)}">Noisy</button>
      </div>
    </div>`;
  }

  function render(report){
    const summary=$('#detectorFeedbackSummary');
    const target=$('#detectorFeedbackRows');
    if(!summary||!target)return;
    const s=report&&report.summary;
    if(!s){
      summary.textContent='Waiting for data';
      target.innerHTML='<div class="signal-empty"><b>No detector feedback</b><p>Validated and noisy detections appear here without prompt bodies.</p></div>';
      return;
    }
    const quality=report.quality&&report.quality.summary?report.quality:null;
    const qs=quality?quality.summary:{};
    summary.textContent=quality?`${qs.score||0}/100 eval / ${s.noisy||0} noisy / ${s.valid||0} valid / ${s.reviewCandidates||0} candidates`:`${s.noisy||0} noisy / ${s.valid||0} valid / ${s.reviewCandidates||0} candidates`;
    const detectors=Array.isArray(report.detectors)?report.detectors:[];
    const candidates=Array.isArray(report.reviewQueue)?report.reviewQueue:[];
    const qualityRows=quality?[
      bar('Held-out Eval',qs.score||0,100,qs.floorsMet?'floors met':`${qs.failures||0} floor gap${(qs.failures||0)===1?'':'s'}`,qs.floorsMet?'ready':'attention'),
      bar('Semantic Recall',qs.semanticRecall||0,100,`${qs.semanticPrecision||0}% precision`,(qs.semanticRecall||0)>=70?'ready':'attention'),
      bar('Structured Recall',qs.structuredRecall||0,100,`${qs.structuredF1||0}% F1`,(qs.structuredRecall||0)>=95?'ready':'attention'),
      bar('False Positives',(qs.benignFalsePositives||0)+(qs.baitFalsePositives||0),1,'benign plus structured bait',(qs.benignFalsePositives||0)+(qs.baitFalsePositives||0)===0?'ready':'attention'),
    ].join(''):'';
    const detectorRows=detectors.slice(0,4).map((row)=>bar(row.detectorId,row.falsePositive+row.tooSensitive,row.total,row.detail,row.state)).join('');
    const candidateRows=candidates.slice(0,4).map(candidateRow).join('');
    target.innerHTML=`${qualityRows}${detectorRows||'<div class="signal-empty"><b>No scored detectors</b><p>Submit feedback from candidates below.</p></div>'}
      ${candidateRows?'<div class="control-row"><div><strong>Review Candidates</strong><span>metadata only</span></div></div>'+candidateRows:''}`;
  }

  async function load(){
    const target=$('#detectorFeedbackRows');
    if(!target||loading)return;
    loading=true;
    try{
      const res=await fetch('/api/detector-feedback/report?queryLimit=1000&feedbackLimit=1000',{credentials:'same-origin'});
      if(!res.ok)throw new Error('feedback unavailable');
      render(await res.json());
    }catch{
      render(null);
    }finally{
      loading=false;
    }
  }

  async function submit(button){
    const verdict=button.dataset.detectorFeedback;
    const queryId=button.dataset.queryId;
    const detectorId=button.dataset.detectorId;
    button.disabled=true;
    try{
      const token=await csrfToken();
      const res=await fetch(`/api/queries/${encodeURIComponent(queryId)}/detector-feedback`,{
        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json','x-csrf-token':token},
        body:JSON.stringify({detectorId,verdict,reason:verdict==='valid'?'operator_validated':'operator_marked_noisy'}),
      });
      if(!res.ok)throw new Error('feedback failed');
      await load();
    }catch{
      button.textContent='Retry';
    }finally{
      button.disabled=false;
    }
  }

  function boot(){
    load();
    document.addEventListener('click',(e)=>{
      const feedback=e.target.closest('[data-detector-feedback]');
      if(feedback)return submit(feedback);
      if(e.target.closest('#monitorRefresh'))setTimeout(load,450);
    });
  }

  window.RedactWallDetectorFeedback={load,render};
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);
  else boot();
})();
