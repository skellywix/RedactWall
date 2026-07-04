(function(){
'use strict';
const endpoint='/api/security/package';
function render(state,deps){
  const q=deps.$,safe=deps.escapeHtml,target=q('#securityPackagePreview'),summary=q('#securityPackageSummary'),button=q('#downloadSecurityPackage');
  if(!target||!summary)return;
  const admin=deps.canAdminWrite();
  if(button){
    button.disabled=state.securityPackageLoading||!admin||!!state.securityPackageError;
    button.setAttribute('aria-busy',state.securityPackageLoading?'true':'false');
    button.innerHTML=state.securityPackageLoading?'<span class="button-spinner" aria-hidden="true"></span>Preparing':`${deps.icons.download}Download Trust Package`;
  }
  const empty=(title,body)=>{summary.textContent=title;target.innerHTML=`<div class="signal-empty"><b>${safe(title)}</b><p>${safe(body)}</p></div>`;};
  if(!admin)return empty('Security Admin required','Vendor-risk trust packages are available to Security Admins only.');
  if(state.securityPackageLoading)return empty('Preparing package','Collecting sanitized controls, SBOM inventory, and validation commands.');
  if(state.securityPackageError)return empty(`Package error - ${deps.humanize(state.securityPackageError)}`.slice(0,80),'Refresh Audit or retry the download.');
  const pkg=state.currentSecurityPackage||{},coverage=pkg.summary&&pkg.summary.controlCoverage,sbom=pkg.sbom&&pkg.sbom.summary,controls=Array.isArray(pkg.controls)?pkg.controls:[],privacy=pkg.privacyContract||{};
  if(!coverage||!sbom)return empty('Waiting for package','Open Audit to generate procurement-ready trust evidence.');
  summary.textContent=`${coverage.verified}/${coverage.total} controls verified / ${sbom.components||0} dependencies inventoried`;
  const privacyRows=[['Raw prompts',privacy.rawPromptBodies],['Token vaults',privacy.tokenVaultValues],['Raw audit details',privacy.rawAuditDetails],['Local paths',privacy.localFilePaths]];
  const rank={missing:0,attention:1,verified:2};
  const topControls=controls.slice().sort((a,b)=>(rank[a.status]||0)-(rank[b.status]||0)||String(a.label||'').localeCompare(String(b.label||''))).slice(0,5);
  target.innerHTML=`<aside class="trust-package-sidebar"><div class="siem-kpi-grid"><div class="siem-kpi"><span>Verified</span><b>${safe(coverage.verified||0)}</b></div><div class="siem-kpi"><span>Attention</span><b>${safe(coverage.attention||0)}</b></div><div class="siem-kpi"><span>Missing</span><b>${safe(coverage.missing||0)}</b></div><div class="siem-kpi"><span>SBOM</span><b>${safe(sbom.components||0)}</b></div></div><div class="siem-privacy-list">${privacyRows.map(([label,value])=>`<span>${safe(label)} <b>${value===false?'omitted':'review'}</b></span>`).join('')}</div></aside><div class="trust-control-list">${topControls.map((item)=>`<article class="trust-control-row ${safe(item.status)}"><div class="trust-control-head"><strong>${safe(item.label)}</strong>${deps.statusChip(item.status==='verified'?'good':item.status==='attention'?'warn':'bad',deps.humanize(item.status),item.detail||'')}</div><p>${safe(item.detail||'')}</p><div class="siem-profile-meta"><span>${safe(item.owner||'security')}</span>${(item.evidence||[]).slice(0,2).map((evidence)=>`<span>${safe(evidence)}</span>`).join('')}</div></article>`).join('')}</div>`;
}
async function load(state,deps){
  if(!deps.$('#securityPackagePreview'))return null;
  if(!deps.canAdminWrite()){deps.setState({currentSecurityPackage:null,securityPackageError:'security_admin_required',securityPackageLoading:false});deps.renderSecurityPackage();return null;}
  deps.setState({securityPackageLoading:true,securityPackageError:''});deps.renderSecurityPackage();
  try{
    const response=await deps.api(endpoint),body=await deps.responseJsonObject(response,null);
    if(!response||!response.ok||!body){deps.setState({currentSecurityPackage:null,securityPackageError:'load_failed'});return null;}
    deps.setState({currentSecurityPackage:body});return body;
  }catch{deps.setState({currentSecurityPackage:null,securityPackageError:'load_failed'});return null;}
  finally{deps.setState({securityPackageLoading:false});deps.renderSecurityPackage();}
}
async function download(state,deps){
  if(!deps.canAdminWrite()){window.alert('Request not allowed for this session. Use a Security Admin account.');return;}
  const button=deps.$('#downloadSecurityPackage');
  if(button){button.disabled=true;button.setAttribute('aria-busy','true');button.innerHTML='<span class="button-spinner" aria-hidden="true"></span>Downloading';}
  try{
    const response=await deps.api(`${endpoint}?format=zip`);
    if(!response||!response.ok){window.alert(await deps.apiErrorSummary(response,'Security trust package download failed'));return;}
    const url=URL.createObjectURL(await response.blob()),link=Object.assign(document.createElement('a'),{href:url,download:'promptwall-security-trust-package.zip'});
    document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);deps.markUpdated('TRUST PACKAGE READY');
  }catch{window.alert('Security trust package download failed.');}
  finally{if(button){button.removeAttribute('aria-busy');button.innerHTML=`${deps.icons.download}Download Trust Package`;}deps.renderSecurityPackage();}
}
window.PromptWallSecurityPackage={render,load,download};
}());
