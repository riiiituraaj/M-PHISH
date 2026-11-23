import {defaults, Settings, Result, Observations, originOnly, excluded, escapeHtml} from "./policy";
let prefs:Settings={...defaults,protectionEnabled:false};
let epoch=0; let currentUrl=location.href; let warning:HTMLElement|null=null; let pendingAction=false;
let lastFingerprint=""; let lastObservationAt=0;
const bypassForms=new WeakSet<HTMLFormElement>(); const bypassLinks=new WeakSet<HTMLAnchorElement>(); const focused=new Map<string,number>();
const enabled=()=>prefs.protectionEnabled && !excluded(location.href,prefs);
async function refresh(){prefs={...defaults,...await chrome.storage.local.get<Settings>(defaults)};epoch++;warning?.remove();warning=null;pendingAction=false;focused.clear();lastFingerprint="";}
void refresh();
chrome.storage.onChanged.addListener((_changes,area)=>{if(area==="local")void refresh();});
chrome.runtime.onMessage.addListener((message,sender)=>{
  if(sender.id!==chrome.runtime.id)return;
  if(message.type==="settings-changed")void refresh();
  if(message.type==="assessment" && enabled() && message.url===location.href){document.documentElement.dataset.mPhishAvailability=message.result.availability;}
});
function category(input:Element):string|null {
  // Attributes describe the requested field. Never access .value, cookies, clipboard or input events.
  const type=(input.getAttribute("type")||"").toLowerCase();
  const hint=[input.getAttribute("name"),input.getAttribute("autocomplete"),input.getAttribute("id")].filter(Boolean).join(" ").toLowerCase().slice(0,200);
  if(type==="password")return "password";
  if(/one-time-code|\botp\b/.test(hint))return "otp";
  if(/cc-number|cc-csc|cc-exp|card|cvv|cvc/.test(hint))return "card";
  if(/bank|routing|\bupi\b|iban/.test(hint))return "banking";
  if(type==="email" || /email/.test(hint))return "email";
  if(type==="tel" || /tel|phone/.test(hint))return "phone";
  if(/address|postal/.test(hint))return "address";return null;
}
function snapshot():Observations {
  const inputs=[...document.querySelectorAll("input,select,textarea")].slice(0,100);
  const forms=[...document.forms].slice(0,12);
  const fields=[...new Set(inputs.map(category).filter((x):x is string=>!!x))];
  const form_actions=[...new Set(forms.map(form=>originOnly(form.action || location.href)).filter((x):x is string=>!!x))];
  return {consent:true,fields,form_actions,password_inputs:inputs.filter(x=>x.getAttribute("type")?.toLowerCase()==="password").length,forms:forms.length,frame_coverage:"top_frame_only",page_fingerprint:`${fields.join("-")}:${form_actions.join("|")}:${forms.length}`.slice(0,80)};
}
async function send(action:string,details:Record<string,unknown>):Promise<Result>{
  if(!enabled())return {availability:"paused",message:"Protection paused."};
  try{return await chrome.runtime.sendMessage({type:"interaction-event",url:location.href,action_type:action,action_details:details,observations:prefs.cloudConsent?snapshot():undefined});}
  catch{return {availability:"unavailable",message:"Protection unavailable. The extension could not complete this check."};}
}
function show(result:Result,context:{destination?:string;fields?:string[]},resume?:()=>void){
  warning?.remove();
  const root=document.createElement("div");root.id="m-phish-shield-root";warning=root;
  const shadow=root.attachShadow({mode:"open"});
  const evidence=Array.isArray(result.evidence)?result.evidence:[];
  const modal=result.intervention_modal as Record<string,unknown>|undefined;
  const profile=result.digital_trust_profile as Record<string,unknown>|undefined;
  const message=String(modal?.message||profile?.state_reason||result.message||"Review this interaction before continuing.");
  shadow.innerHTML=`<style>:host{all:initial;position:fixed;z-index:2147483647;inset:auto 16px 16px auto;font-family:system-ui;color:#f8fafc}.card{box-sizing:border-box;width:min(400px,calc(100vw - 32px));background:#101c2b;border:2px solid #e9b949;border-radius:12px;padding:20px;box-shadow:0 12px 50px #0008;font-size:14px;line-height:1.5}h2{font-size:18px;margin:0 0 12px}p{overflow-wrap:anywhere}button{font:inherit;margin:4px 6px 0 0;padding:8px 12px;border-radius:5px;border:1px solid #91a4ba;background:#f8fafc;color:#122033;cursor:pointer}button:focus-visible{outline:3px solid #60a5fa;outline-offset:3px}summary{cursor:pointer}small{display:block;color:#bac6d5}</style><section class="card" role="${resume?"alertdialog":"status"}" aria-modal="false" aria-labelledby="title"><h2 id="title">${result.availability==="unavailable"?"Protection unavailable":resume?"Action paused — review before continuing":"M-PHISH observation"}</h2><p>${escapeHtml(message)}</p>${context.destination?`<p>Observed destination: <strong>${escapeHtml(context.destination)}</strong></p>`:""}${context.fields?.length?`<p>Requested categories: ${escapeHtml(context.fields.join(", "))}</p>`:""}<details><summary>Why am I seeing this?</summary>${evidence.length?evidence.slice(0,8).map(e=>`<p>${escapeHtml(e.title)}: ${escapeHtml(e.description)} ${escapeHtml(e.id)}</p>`).join(""):`<p>${escapeHtml(message)}</p>`}<small>Top-frame native form submissions and direct executable links only. Page scripts may send data before submission; this is not universal exfiltration or malware protection.</small></details><button id="cancel" type="button">${resume?"Cancel action":"Dismiss"}</button>${resume?'<button id="continue" type="button">Continue once</button>':""}</section>`;
  (document.body||document.documentElement).appendChild(root);
  const prior=document.activeElement as HTMLElement|null;
  const close=()=>{root.remove();if(warning===root)warning=null;pendingAction=false;prior?.focus();};
  shadow.getElementById("cancel")!.addEventListener("click",close);
  shadow.getElementById("continue")?.addEventListener("click",event=>{if(!event.isTrusted)return;close();resume?.();});
  shadow.addEventListener("keydown",event=>{if((event as KeyboardEvent).key==="Escape")close();});
  if(resume)(shadow.getElementById("cancel") as HTMLButtonElement).focus();
}
async function pause(action:string,details:Record<string,unknown>,resume:()=>void){
  if(pendingAction)return;pendingAction=true;const start=epoch;const url=location.href;
  show({availability:"pending",message:"Checking the observed destination. The action is paused."},{destination:String(details.form_action||details.destination||""),fields:details.field_categories as string[]},undefined);
  const result=await send(action,details);
  if(!pendingAction)return;
  if(!enabled() || epoch!==start || location.href!==url){warning?.remove();warning=null;pendingAction=false;return;}
  if(result.availability==="stale" || result.availability==="paused"){warning?.remove();warning=null;pendingAction=false;return;}
  if(result.requires_intervention===false && result.availability!=="unavailable"){
    warning?.remove();warning=null;pendingAction=false;resume();return;
  }
  show(result,{destination:String(details.form_action||details.destination||""),fields:details.field_categories as string[]},resume);
}
document.addEventListener("submit",event=>{
  if(!enabled() || !(event.target instanceof HTMLFormElement))return;
  const form=event.target; if(bypassForms.delete(form))return;
  const fields=[...new Set([...form.querySelectorAll("input,select,textarea")].map(category).filter((x):x is string=>!!x))];
  if(!fields.some(x=>["password","otp","card","banking"].includes(x)))return;
  event.preventDefault();event.stopImmediatePropagation();
  const submitter=event.submitter as HTMLButtonElement|HTMLInputElement|null;
  const action=submitter?.getAttribute("formaction")?new URL(submitter.getAttribute("formaction")!,location.href).href:form.action;
  const destination=originOnly(action || location.href);const signature=action;
  void pause("form_submit",{form_action:destination,field_categories:fields},()=>{
    const nowAction=submitter?.getAttribute("formaction")?new URL(submitter.getAttribute("formaction")!,location.href).href:form.action;
    if(!form.isConnected || nowAction!==signature)return;
    bypassForms.add(form);try{form.requestSubmit(submitter&&submitter.isConnected?submitter:undefined);}finally{bypassForms.delete(form);}
  });
},true);
document.addEventListener("click",event=>{
  if(!enabled() || !(event.target instanceof Element))return;
  const link=event.target.closest("a");if(!(link instanceof HTMLAnchorElement))return;
  if(bypassLinks.delete(link))return;
  let executable=false;try{executable=/\.(exe|msi|bat|cmd|ps1|vbs|scr|apk|dmg|pkg)$/i.test(new URL(link.href).pathname);}catch{return;}
  if(!executable)return;event.preventDefault();event.stopImmediatePropagation();
  const exact=link.href;
  void pause("download_attempt",{destination:originOnly(exact),is_executable:true},()=>{if(link.isConnected && link.href===exact){bypassLinks.add(link);try{link.click();}finally{bypassLinks.delete(link);}}});
},true);
document.addEventListener("focusin",event=>{
  if(!enabled() || !prefs.cloudConsent || prefs.protectionMode==="local" || !(event.target instanceof Element))return;
  const field=category(event.target);if(!field || !["password","otp","card","banking"].includes(field))return;
  const form=event.target.closest("form");const destination=originOnly(form?.action||location.href);const key=`${field}:${destination}`;
  if(Date.now()-(focused.get(key)||0)<60000)return;focused.set(key,Date.now());const start=epoch;const url=location.href;
  void send(`${field}_focused`,{form_action:destination,field_categories:[field]}).then(result=>{if(enabled() && epoch===start && url===location.href && result.requires_intervention && !pendingAction)show(result,{destination:destination||undefined,fields:[field]});});
},true);
// Poll only structural attributes; no keystroke/value listeners. SPA changes invalidate stale prompts.
setInterval(()=>{
  if(location.href!==currentUrl){currentUrl=location.href;epoch++;warning?.remove();warning=null;pendingAction=false;focused.clear();lastFingerprint="";}
  if(!enabled() || !prefs.cloudConsent || prefs.protectionMode==="local" || Date.now()-lastObservationAt<15000)return;
  const observations=snapshot();const fingerprint=JSON.stringify(observations);
  if(lastFingerprint===fingerprint)return;lastFingerprint=fingerprint;lastObservationAt=Date.now();
  chrome.runtime.sendMessage({type:"observations",url:location.href,observations}).catch(()=>{});
},2000);
