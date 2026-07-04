(function(){
'use strict';
const endpoint='/api/integrations/siem/package?profile=';
function render(state,deps){
  const q=deps.$,safe=deps.escapeHtml,target=q('#siemPackagePreview'),summary=q('#siemPackageSummary');
  if(!target||!summary)return;
  const select=q('#siemPackageProfile'),button=q('#downloadSiemPackage'),admin=deps.canAdminWrite();
  if(select&&select.value!==state.siemPackageProfile)select.value=state.siemPackageProfile;
  if(select)select.disabled=state.siemPackageLoading||!admin;
  if(button){
    button.disabled=state.siemPackageLoading||!admin||!!state.siemPackageError;
    button.setAttribute('aria-busy',state.siemPackageLoading?'true':'false');
    button.innerHTML=state.siemPackageLoading?'<span class="button-spinner" aria-hidden="true"></span>Preparing':'Download ZIP';
  }
  const empty=(title,body)=>{summary.textContent=title;target.innerHTML=`<div class="signal-empty"><b>${safe(title)}</b><p>${safe(body)}</p></div>`;};
  if(!admin)return empty('Security Admin required','SIEM and SOAR packages are available to Security Admins only.');
  if(state.siemPackageLoading)return empty('Preparing package','Generating sanitized mappings, searches, and setup checks.');
  if(state.siemPackageError)return empty(`Package error - ${deps.humanize(state.siemPackageError)}`.slice(0,80),'Refresh or choose a supported profile.');
  const pkg=state.currentSiemPackage||{},profiles=Array.isArray(pkg.profiles)?pkg.profiles:[];
  if(!profiles.length)return empty('Waiting for package','Refresh the command center to build the SOC package.');
  const counts=pkg.summary||{},privacy=pkg.privacy||{},label=(value)=>value===false?'omitted':'check';
  summary.textContent=`${profiles.length} profile${profiles.length===1?'':'s'} / ${counts.searches||0} searches / ${counts.packageFiles||0} files`;
  target.innerHTML=`<aside class="siem-package-sidebar"><div class="siem-kpi-grid"><div class="siem-kpi"><span>Profiles</span><b>${safe(profiles.length)}</b></div><div class="siem-kpi"><span>Searches</span><b>${safe(counts.searches||0)}</b></div><div class="siem-kpi"><span>Samples</span><b>${safe(counts.samplePayloads||0)}</b></div><div class="siem-kpi"><span>Files</span><b>${safe(counts.packageFiles||0)}</b></div></div><div class="siem-privacy-list"><span>Raw prompts <b>${label(privacy.rawPromptBodies)}</b></span><span>Token vaults <b>${label(privacy.tokenVaultValues)}</b></span><span>Raw findings <b>${label(privacy.rawFindingValues)}</b></span><span>URL paths/files <b>${label(privacy.rawUrlsOrFilePaths)}</b></span></div></aside><div class="siem-profile-list">${profiles.map((profile)=>{
    const searches=(profile.savedSearches||[]).concat(profile.detections||[]),panels=(profile.dashboardPanels||[]).concat(profile.workbookPanels||[],profile.incidentTemplates||[]),first=searches[0]||{};
    const ready=first.name||first.udmSearch||first.spl||first.kql||'Field mappings ready',check=profile.setupChecklist&&profile.setupChecklist[0]||'Setup checklist ready';
    return `<article class="siem-profile-row"><div class="siem-profile-head"><div><strong>${safe(profile.label||profile.id)}</strong><span>${safe(profile.target||'')}</span></div>${deps.statusChip('good','ZIP ready','Package contains sanitized samples, mappings, searches, and setup files.')}</div><div class="siem-profile-meta"><span>${safe((profile.fieldMappings||[]).length)} mappings</span><span>${safe((profile.samplePayloads||[]).length)} samples</span><span>${safe(searches.length)} searches</span><span>${safe(panels.length)} panels</span></div><p>${safe(profile.transport&&(profile.transport.ingestion||profile.transport.endpointPath||profile.transport.method)||'Offline setup package')}</p><div class="siem-search-list"><b>Ready content</b><ul><li>${safe(ready)}</li><li>${safe(check)}</li></ul></div></article>`;
  }).join('')}</div>`;
}
async function load(state,deps){
  if(!deps.$('#siemPackagePreview'))return null;
  if(!deps.canAdminWrite()){deps.setState({currentSiemPackage:null,siemPackageError:'security_admin_required',siemPackageLoading:false});deps.renderSiemPackage();return null;}
  deps.setState({siemPackageLoading:true,siemPackageError:''});deps.renderSiemPackage();
  try{
    const response=await deps.api(`${endpoint}${encodeURIComponent(state.siemPackageProfile)}`);
    const body=await deps.responseJsonObject(response,null);
    if(!response||!response.ok||!body){deps.setState({currentSiemPackage:null,siemPackageError:response&&response.status===400?'unsupported_profile':'load_failed'});return null;}
    deps.setState({currentSiemPackage:body});return body;
  }catch{deps.setState({currentSiemPackage:null,siemPackageError:'load_failed'});return null;}
  finally{deps.setState({siemPackageLoading:false});deps.renderSiemPackage();}
}
async function download(state,deps){
  if(!deps.canAdminWrite()){window.alert('Request not allowed for this session. Use a Security Admin account.');return;}
  const button=deps.$('#downloadSiemPackage');
  if(button){button.disabled=true;button.setAttribute('aria-busy','true');button.innerHTML='<span class="button-spinner" aria-hidden="true"></span>Downloading';}
  try{
    const response=await deps.api(`${endpoint}${encodeURIComponent(state.siemPackageProfile)}&format=zip`);
    if(!response||!response.ok){window.alert(await deps.apiErrorSummary(response,'SIEM package download failed'));return;}
    const url=URL.createObjectURL(await response.blob()),link=Object.assign(document.createElement('a'),{href:url,download:`promptwall-siem-${state.siemPackageProfile||'all'}-package.zip`});
    document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);deps.markUpdated('SIEM PACKAGE READY');
  }catch{window.alert('SIEM package download failed.');}
  finally{if(button){button.removeAttribute('aria-busy');button.innerHTML='Download ZIP';}deps.renderSiemPackage();}
}
window.PromptWallSiemPackage={render,load,download};
}());
