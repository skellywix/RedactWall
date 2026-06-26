const $ = (s,el=document)=>el.querySelector(s);
const $$ = (s,el=document)=>[...el.querySelectorAll(s)];
const fmt = (iso)=> new Date(iso).toLocaleString();
const sevClass = (l)=> l||'low';
let selected=null;
let csrfToken='';

async function api(path, opts={}){
  const next = {...opts};
  const method = String(next.method || 'GET').toUpperCase();
  const headers = new Headers(next.headers || {});
  if (csrfToken && ['POST','PUT','PATCH','DELETE'].includes(method)) headers.set('x-csrf-token', csrfToken);
  next.headers = headers;
  const r=await fetch(path,next);
  if(r.status===401){location.href='/login.html';return null;}
  if(r.status===403){alert('Security token expired. Refresh the dashboard and try again.');}
  return r;
}

async function loadCsrf(){
  const r = await api('/api/csrf');
  if (!r) return;
  const body = await r.json();
  csrfToken = body.csrfToken || '';
}

async function init(){
  const me = await (await api('/api/me')).json();
  await loadCsrf();
  $('#who').textContent = me.user+' - Security Admin';
  if(me.defaultPassword){ const b=$('#banner'); b.style.display='block';
    b.textContent='[!] Default admin password in use. Set ADMIN_PASSWORD before deploying to production.'; }
  await refreshAll();
  connectStream();
}

async function refreshAll(){ await Promise.all([loadStats(),loadQueue(),loadActivity()]); }

async function loadStats(){
  const s = await (await api('/api/stats')).json();
  $('#stats').innerHTML = [
    ['pending',s.pending,'Awaiting approval'],
    ['alert',s.todayBlocked,'Blocked today'],
    ['',s.approved,'Approved'],
    ['',s.denied,'Denied'],
    ['',s.total,'Total prompts gated'],
  ].map(([c,n,l])=>`<div class="stat ${c}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');
  const b=$('#qBadge'); if(s.pending>0){b.classList.remove('hidden');b.textContent=s.pending;}else b.classList.add('hidden');
  $('#topEntities').innerHTML = (s.topEntities.length? s.topEntities : []).map(([k,v])=>{
    const max = s.topEntities[0][1]||1;
    return `<div class="barrow"><div class="name">${k}</div><div class="bar"><i style="width:${Math.round(v/max*100)}%"></i></div><div class="v">${v}</div></div>`;
  }).join('') || '<div class="empty" style="padding:24px">No detections yet</div>';
}

function findingChips(findings,categories){
  const fc=(findings||[]).map(f=>`<span class="chip"><b>${f.type}</b> ${f.masked||''}</span>`).join('');
  const cc=(categories||[]).map(c=>`<span class="chip" style="border-color:#5b4a1f;color:#fcd34d"><b>${c}</b></span>`).join('');
  return fc+cc;
}
const srcLabel={browser_extension:'Browser',endpoint_agent:'Endpoint',mcp_guard:'MCP',api:'API',proxy:'Proxy'};

async function loadQueue(){
  const rows = await (await api('/api/queries?status=pending')).json();
  const el = $('#queueList');
  if(!rows.length){ el.innerHTML = `<div class="empty"><div class="big">OK</div>Queue clear - no prompts awaiting approval</div>`; return; }
  el.innerHTML = rows.map(renderQueueItem).join('');
}

function renderQueueItem(q){
  return `<div class="q ${selected===q.id?'selected':''}" data-id="${q.id}">
    <div class="top">
      <span class="sev ${sevClass(q.maxSeverityLabel)}">${q.maxSeverityLabel}</span>
      <span class="risk">risk <b>${q.riskScore}</b>/100</span>
    </div>
    <div class="meta">
      <span>User ${q.user}</span><span>to ${q.destination}</span><span>${q.channel||''}</span><span>${fmt(q.createdAt)}</span>
    </div>
    <div class="prompt" id="p_${q.id}">${escapeHtml(q.redactedPrompt)}</div>
    <div class="chips">${findingChips(q.findings,q.categories)}</div>
    <div style="margin-top:8px;font-size:12px;color:var(--mut)">Reasons: ${(q.reasons||[]).join('; ')}</div>
    <textarea class="note" id="note_${q.id}" placeholder="Decision note (optional, recorded in audit log)"></textarea>
    <div class="actions">
      <button class="btn approve" data-act="approve" data-id="${q.id}">Approve &amp; release</button>
      <button class="btn deny" data-act="deny" data-id="${q.id}">Deny</button>
      <button class="btn reveal" data-act="reveal" data-id="${q.id}">Reveal raw</button>
    </div>
  </div>`;
}

function escapeHtml(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

document.addEventListener('click', async (e)=>{
  const act = e.target.dataset.act;
  if(!act) return;
  const id = e.target.dataset.id;
  if(act==='reveal'){
    const r = await (await api(`/api/queries/${id}/reveal`,{method:'POST'})).json();
    const p = $('#p_'+id); if(p){ p.textContent = r.rawPrompt; p.style.borderColor='#5b2a2a'; }
    e.target.textContent='Raw shown (logged)'; e.target.disabled=true;
    return;
  }
  if(act==='approve'||act==='deny'){
    const note = ($('#note_'+id)||{}).value || '';
    e.target.disabled=true;
    await api(`/api/queries/${id}/${act}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note})});
    await refreshAll();
  }
});

async function loadActivity(){
  const rows = await (await api('/api/queries?limit=200')).json();
  $('#activityRows').innerHTML = rows.map(q=>`<tr>
    <td>${fmt(q.createdAt)}</td><td>${(srcLabel[q.source]||q.source||'API')}</td><td>${q.user}</td><td class="mono">${q.destination}</td>
    <td><span class="sev ${sevClass(q.maxSeverityLabel)}">${q.maxSeverityLabel}</span></td>
    <td>${q.riskScore}</td>
    <td>${Object.keys(q.entityCounts||{}).join(', ')||'-'}</td>
    <td><span class="pill ${q.status==='shadow_ai'?'ADMIN_LOGIN':(q.status==='approved'||q.status==='allowed'||q.status==='justified'||q.status==='warned_sent'||q.status==='redacted'?'APPROVED':(q.status==='denied'||q.status==='blocked_by_user'||q.status==='injection_blocked'||q.status==='response_flagged'?'DENIED':'BLOCKED'))}">${q.status}</span></td>
  </tr>`).join('') || '<tr><td colspan="8" class="empty">No activity</td></tr>';
}

async function loadAudit(){
  const d = await (await api('/api/audit')).json();
  const ig = d.integrity;
  $('#integrity').innerHTML = ig.ok
    ? `<span class="ok">* Chain verified</span> - ${ig.count} entries, cryptographically linked (SHA-256).`
    : `<span class="bad">* Integrity check FAILED</span> at ${ig.brokenAt}`;
  $('#auditRows').innerHTML = d.entries.map(a=>`<tr>
    <td class="mono">${fmt(a.ts)}</td><td><span class="pill ${a.action}">${a.action}</span></td>
    <td>${a.actor||'-'}</td><td class="mono">${a.queryId||'-'}</td><td>${a.detail||''}</td>
  </tr>`).join('');
}

async function exportEvidence(){
  const btn = $('#exportEvidence');
  const status = $('#exportStatus');
  btn.disabled = true;
  status.textContent = 'Preparing...';
  try {
    const r = await api('/api/export/evidence?queryLimit=1000&auditLimit=1000');
    if (!r || !r.ok) throw new Error('export failed');
    const pack = await r.json();
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    a.href = url;
    a.download = `promptsentinel-evidence-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    status.textContent = 'Downloaded';
    setTimeout(() => { status.textContent = ''; }, 2200);
  } catch (err) {
    status.textContent = 'Export failed';
  } finally {
    btn.disabled = false;
  }
}

async function loadPolicy(){
  const p = await (await api('/api/policy')).json();
  const tpls = await (await api('/api/policy/templates')).json();
  const modes=[['warn','Warn','Nudge the user, let them proceed'],['justify','Require justification','User must give a business reason'],['redact','Redact &amp; send','Tokenize PII, send safely, restore the reply'],['block','Block','Hold for Security Admin approval']];
  const tplBar = `<div style="margin-bottom:16px"><div style="color:var(--mut);font-size:12px;margin-bottom:6px">One-click regulation templates</div>
    <div class="chips">${tpls.map(t=>`<button class="chip ps-tpl" data-tpl="${t.id}" title="${t.description.replace(/"/g,'&quot;')}" style="cursor:pointer">${t.label}</button>`).join('')}</div></div>`;
  $('#policyBox').innerHTML = tplBar + `
    <div style="color:var(--mut);font-size:12.5px;margin-bottom:10px">When a sensor detects sensitive content, do this:</div>
    <div style="display:flex;gap:8px;margin-bottom:20px">
      ${modes.map(([v,t,d])=>`<label style="flex:1;border:1px solid ${p.enforcementMode===v?'#3b82f6':'var(--line)'};background:${p.enforcementMode===v?'#10243f':'var(--panel2)'};border-radius:10px;padding:10px;cursor:pointer;display:block">
        <div style="display:flex;align-items:center;gap:7px"><input type="radio" name="mode" value="${v}" ${p.enforcementMode===v?'checked':''} style="accent-color:#3b82f6"/><b style="font-size:13px">${t}</b></div>
        <div style="color:var(--mut);font-size:11.5px;margin-top:4px;margin-left:22px">${d}</div></label>`).join('')}
    </div>
    <div style="color:var(--mut);font-size:12.5px;margin-bottom:10px">Trigger thresholds:</div>
    <div style="display:grid;grid-template-columns:1fr 110px;gap:10px;align-items:center">
      <label>Block at minimum severity</label>
      <select id="pol_sev">
        ${[[1,'low'],[2,'medium'],[3,'high'],[4,'critical']].map(([v,l])=>`<option value="${v}" ${p.blockMinSeverity===v?'selected':''}>${l}</option>`).join('')}
      </select>
      <label>Block at risk score &gt;=</label>
      <input id="pol_risk" type="number" min="0" max="100" value="${p.blockRiskScore}" style="padding:8px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--txt)"/>
    </div>
    <div style="margin-top:16px"><div style="color:var(--mut);font-size:12px;margin-bottom:6px">Hard-stop entities (always block)</div>
      <div class="chips">${p.alwaysBlock.map(x=>`<span class="chip"><b>${x}</b></span>`).join('')}</div></div>
    <div style="margin-top:16px"><div style="color:var(--mut);font-size:12px;margin-bottom:6px">Governed AI destinations</div>
      <div class="chips">${p.governedDestinations.map(x=>`<span class="chip">${x}</span>`).join('')}</div></div>
    <button class="btn approve" id="savePolicy" style="margin-top:20px">Save policy</button>
    <span id="polSaved" style="margin-left:12px;color:#86efac;font-size:12.5px"></span>`;
  $('#savePolicy').onclick = async ()=>{
    const mode=(document.querySelector('input[name=mode]:checked')||{}).value||p.enforcementMode;
    const body = { enforcementMode:mode, blockMinSeverity:Number($('#pol_sev').value), blockRiskScore:Number($('#pol_risk').value) };
    await api('/api/policy',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    $('#polSaved').textContent='Saved'; setTimeout(()=>$('#polSaved').textContent='',2000);
  };
  $$('.ps-tpl').forEach(b=>b.onclick=async()=>{
    await api('/api/policy/apply-template',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:b.dataset.tpl})});
    loadPolicy();
  });
}

// Tabs
$$('.tab').forEach(t=>t.onclick=()=>{
  $$('.tab').forEach(x=>x.classList.remove('active')); t.classList.add('active');
  $$('section[id^=tab-]').forEach(s=>s.classList.add('hidden'));
  $('#tab-'+t.dataset.tab).classList.remove('hidden');
  if(t.dataset.tab==='audit') loadAudit();
  if(t.dataset.tab==='policy') loadPolicy();
  if(t.dataset.tab==='activity') loadActivity();
});

$('#logout').onclick = async ()=>{ await api('/api/logout',{method:'POST'}); location.href='/login.html'; };
$('#exportEvidence').onclick = exportEvidence;

// Live stream
function connectStream(){
  const es = new EventSource('/api/stream');
  es.addEventListener('query', ()=>{ loadStats(); loadQueue(); flash(); });
  es.addEventListener('decision', ()=>{ loadStats(); loadQueue(); loadActivity(); });
  es.addEventListener('stats', ()=> loadStats());
  es.onerror = ()=>{ $('#liveTxt').textContent='Reconnecting...'; };
  es.onopen = ()=>{ $('#liveTxt').textContent='Live'; };
}
function flash(){ const d=document.querySelector('.dot'); d.style.background='#f59e0b'; setTimeout(()=>d.style.background='#22c55e',500); }

init();

