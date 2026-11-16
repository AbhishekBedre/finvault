(() => {
'use strict';
const DB_NAME='finvault_local_v1', STORE='vaults', IMG_STORE='images', VAULT_ID='primary';
const $=id=>document.getElementById(id);
const pad=n=>String(n).padStart(2,'0');
const CATEGORIES=['Credit cards','Debit cards','Netbanking','Login details','FD details','BOND details','Notes'];
const CATEGORY_META={'Credit cards':{color:'#5376e8'},'Debit cards':{color:'#16a085'},'Netbanking':{color:'#8b5cf6'},'Login details':{color:'#0f9fba'},'FD details':{color:'#e39a35'},'BOND details':{color:'#df5c83'},'Notes':{color:'#64748b'}};
const catColor=r=>(CATEGORY_META[r.category]||CATEGORY_META.Notes).color; // fixed per category
// s = sensitive (hidden until revealed), m = show masked last 4 on the card, rem = date field that creates an automatic reminder
const CARD=[
 {l:'Card Type',t:'select',o:['Visa','Mastercard','RuPay','Amex']},{l:'Card Holder Name'},{l:'Co Issuer Name'},{l:'Bank Name'},
 {l:'Card Number',s:1,m:1,mode:'numeric',max:19},
 {l:'Expiry Month',t:'select',o:Array.from({length:12},(_,i)=>pad(i+1))},{l:'Expiry Year',t:'year'},
 {l:'CVV',s:1,mode:'numeric',max:4},{l:'PIN',s:1,mode:'numeric',max:8},
 {l:'Card Limit',mode:'decimal'},{l:'Payment Date',t:'date',rem:'monthly'}
];
const FIELDS={
 'Credit cards':CARD,'Debit cards':CARD,
 'Netbanking':[{l:'Account Holder Name'},{l:'Bank Name'},{l:'Account Number',s:1,m:1,mode:'numeric'},{l:'Customer ID'},{l:'Registered Mobile No',t:'tel',mode:'tel'},{l:'User ID'},{l:'Login Password',s:1},{l:'Profile Password',s:1},{l:'Transaction Password',s:1},{l:'Mobile Username'},{l:'Mobile Password',s:1},{l:'Mobile Login PIN',s:1,mode:'numeric'}],
 'Login details':[{l:'Name'},{l:'Username'},{l:'Password',s:1}],
 'FD details':[{l:'Bank / company'},{l:'Principal amount'},{l:'Interest rate'},{l:'Start date',t:'date'},{l:'Maturity date',t:'date',rem:'once'},{l:'Maturity amount'},{l:'Auto-renewal'}],
 'BOND details':[{l:'Issuer'},{l:'Investment amount'},{l:'Coupon / YTM'},{l:'Purchase date',t:'date'},{l:'Maturity date',t:'date',rem:'once'},{l:'Interest frequency'},{l:'Platform / demat'}],
 'Notes':[{l:'Topic'},{l:'Reference URL',t:'url'}]
};
const spec=c=>FIELDS[c]||[];
const SENS_RE=/password|cvv|\bpin\b|otp|security code/i;
const isSens=(cat,label)=>spec(cat).some(f=>f.l===label&&f.s)||SENS_RE.test(label);
const BEFORE=[[0,'On the day'],[1,'1 day before'],[2,'2 days before'],[3,'3 days before'],[5,'5 days before'],[7,'1 week before'],[14,'2 weeks before'],[30,'1 month before']];

const DEF_SETTINGS={alertDays:3,autoLock:5,leaveLock:60,clipClear:30};
let db, records=[], reminders=[], doneMap={}, settings={...DEF_SETTINGS}, profile={}, key=null, vaultMeta=null, userName='there', currentCategory='All', view='vault', sortNewest=true, lastUpdated=0, authMode='register', hasVault=false, timer=null, deferredPrompt=null;
const notified=new Set();

/* ---------- storage + crypto ---------- */
function openDB(){return new Promise((res,rej)=>{const r=indexedDB.open(DB_NAME,2);r.onupgradeneeded=()=>{const d=r.result;if(!d.objectStoreNames.contains(STORE))d.createObjectStore(STORE,{keyPath:'id'});if(!d.objectStoreNames.contains(IMG_STORE))d.createObjectStore(IMG_STORE,{keyPath:'id'});};r.onblocked=()=>{const e=document.getElementById('authError');if(e)e.textContent='FinVault is open in another tab or the installed app. Close it completely, then reload this page.';};r.onsuccess=()=>{r.result.onversionchange=()=>{r.result.close();};res(r.result);};r.onerror=()=>rej(r.error);});}
function dbGet(id=VAULT_ID){return new Promise((res,rej)=>{const q=db.transaction(STORE,'readonly').objectStore(STORE).get(id);q.onsuccess=()=>res(q.result||null);q.onerror=()=>rej(q.error);});}
function dbPut(v){return new Promise((res,rej)=>{const tx=db.transaction(STORE,'readwrite');tx.objectStore(STORE).put(v);tx.oncomplete=res;tx.onerror=()=>rej(tx.error);});}
function deriveKey(pw,salt){return crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']).then(b=>crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310000,hash:'SHA-256'},b,{name:'AES-GCM',length:256},false,['encrypt','decrypt']));}
async function encryptData(data,k=key,salt=vaultMeta.salt){const iv=crypto.getRandomValues(new Uint8Array(12));const enc=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,new TextEncoder().encode(JSON.stringify(data)));return {id:VAULT_ID,salt:Array.from(salt),iv:Array.from(iv),cipher:Array.from(new Uint8Array(enc)),updatedAt:Date.now(),version:1};}
async function decryptData(meta,k){const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(meta.iv)},k,new Uint8Array(meta.cipher));return JSON.parse(new TextDecoder().decode(clear));}
/* images: plain base64 data URLs, stored unencrypted in their own store, keyed by entry id */
function imgGet(id){return new Promise(res=>{try{const q=db.transaction(IMG_STORE,'readonly').objectStore(IMG_STORE).get(id);q.onsuccess=()=>res(q.result?.images||[]);q.onerror=()=>res([]);}catch{res([]);}});}
function imgPut(id,images){return new Promise((res,rej)=>{const tx=db.transaction(IMG_STORE,'readwrite');const st=tx.objectStore(IMG_STORE);if(images.length)st.put({id,images});else st.delete(id);tx.oncomplete=res;tx.onerror=()=>rej(tx.error);});}
function imgAll(){return new Promise(res=>{try{const q=db.transaction(IMG_STORE,'readonly').objectStore(IMG_STORE).getAll();q.onsuccess=()=>res(q.result||[]);q.onerror=()=>res([]);}catch{res([]);}});}
function imgReplaceAll(list){return new Promise((res,rej)=>{const tx=db.transaction(IMG_STORE,'readwrite');const st=tx.objectStore(IMG_STORE);st.clear();list.forEach(x=>st.put({id:x.id,images:x.images}));tx.oncomplete=res;tx.onerror=()=>rej(tx.error);});}
function readImage(file){return new Promise((res,rej)=>{const fr=new FileReader();fr.onerror=()=>rej(fr.error);fr.onload=()=>{const img=new Image();img.onerror=()=>rej(new Error('bad image'));img.onload=()=>{const M=1600,k=Math.min(1,M/Math.max(img.width,img.height)),w=Math.round(img.width*k),h=Math.round(img.height*k),c=document.createElement('canvas');c.width=w;c.height=h;const x=c.getContext('2d');x.fillStyle='#fff';x.fillRect(0,0,w,h);x.drawImage(img,0,0,w,h);res(c.toDataURL('image/jpeg',0.82));};img.src=fr.result;};fr.readAsDataURL(file);});}
const bytes=a=>new Uint8Array(a);
async function persist(){if(!key||!vaultMeta)return;try{const blob=await encryptData({userName,profile,records,reminders,done:doneMap,settings,lastUpdated:Date.now()});await dbPut(blob);lastUpdated=blob.updatedAt;}catch(e){console.error(e);toast('Could not save — please export a backup');}}
function loadData(data,meta){records=Array.isArray(data.records)?data.records:[];reminders=Array.isArray(data.reminders)?data.reminders:[];doneMap=data.done||{};settings={...DEF_SETTINGS,...(data.settings||{})};profile=data.profile||{};userName=data.userName||'there';lastUpdated=data.lastUpdated||meta?.updatedAt||0;}

/* ---------- helpers ---------- */
function toast(m){$('toastRoot').innerHTML='';const d=document.createElement('div');d.className='toast';d.textContent=m;$('toastRoot').appendChild(d);setTimeout(()=>d.remove(),3200);}
const escapeHTML=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const normalize=s=>String(s??'').toLocaleLowerCase();
const maskVal=v=>'•••• '+String(v).replace(/\s/g,'').slice(-4);
const subtitle=r=>r.institution||r.fields?.['Bank Name']||r.fields?.['Bank / company']||r.fields?.Issuer||r.fields?.Username||r.fields?.Topic||r.category;
let clipTimer=null,clipDue=0;
function clipClearNow(){if(!clipDue)return;clipDue=0;clearTimeout(clipTimer);try{navigator.clipboard?.writeText('').catch(()=>{});}catch{}}
function clipCheck(){if(clipDue&&Date.now()>=clipDue)clipClearNow();}
async function copyQuiet(t,sensitive){
 if(!navigator.clipboard?.writeText)return false;
 try{await navigator.clipboard.writeText(t);}catch{return false;}
 const secs=Number(settings.clipClear)||0;
 if(sensitive&&secs>0){clearTimeout(clipTimer);clipDue=Date.now()+secs*1000;clipTimer=setTimeout(clipClearNow,secs*1000);}
 return true;
}
function copyText(t,sensitive){
 if(!navigator.clipboard?.writeText){toast('Copy not supported here');return;}
 copyQuiet(t,sensitive).then(ok=>{const secs=Number(settings.clipClear)||0;toast(!ok?'Copy failed':sensitive&&secs>0?'Copied — clipboard clears in '+secs+'s':'Copied');});
}
function getTheme(){try{return localStorage.getItem('finvault_theme')||'light';}catch{return 'light';}}
function applyTheme(p){try{localStorage.setItem('finvault_theme',p);}catch{}const dark=p==='dark'||(p==='auto'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=dark?'dark':'light';$('themeColor').content=dark?'#000000':'#f5f6fa';}
matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change',()=>{if(getTheme()==='auto')applyTheme('auto');});
applyTheme(getTheme());

/* ---------- dates + reminders ---------- */
const ymd=d=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const parseD=s=>{const[y,m,d]=s.split('-').map(Number);return new Date(y,m-1,d);};
const todayD=()=>{const d=new Date();return new Date(d.getFullYear(),d.getMonth(),d.getDate());};
const diffDays=(a,b)=>Math.round((a-b)/864e5);
const clampDay=(y,m,d)=>Math.min(d,new Date(y,m+1,0).getDate());
const validDate=s=>/^\d{4}-\d{2}-\d{2}$/.test(s||'');
function nextOcc(r,t){
 const done=doneMap[r.id], s=parseD(r.date);
 if(r.repeat==='none'||!r.repeat){if(done&&done>=r.date)return null;return s;}
 let base=t;if(done){const nd=parseD(done);nd.setDate(nd.getDate()+1);if(nd>base)base=nd;}if(s>base)base=s;
 if(r.repeat==='monthly'){let y=base.getFullYear(),m=base.getMonth();for(let i=0;i<14;i++){const c=new Date(y,m,clampDay(y,m,s.getDate()));if(c>=base)return c;m++;if(m>11){m=0;y++;}}return null;}
 let y=base.getFullYear();let c=new Date(y,s.getMonth(),clampDay(y,s.getMonth(),s.getDate()));if(c<base){y++;c=new Date(y,s.getMonth(),clampDay(y,s.getMonth(),s.getDate()));}return c;
}
function allReminders(){
 const t=todayD(),list=[];
 reminders.forEach(r=>{if(validDate(r.date))list.push({...r,derived:false,before:Number(r.before)||0});});
 records.forEach(rec=>spec(rec.category).forEach(f=>{const v=rec.fields?.[f.l];if(f.rem&&validDate(v))list.push({id:`d:${rec.id}:${f.l}`,title:`${rec.title} — ${f.l}`,date:v,repeat:f.rem==='monthly'?'monthly':'none',before:Number(settings.alertDays)||0,derived:true,entryId:rec.id});}));
 return list.map(r=>{const n=nextOcc(r,t);if(!n)return null;const days=diffDays(n,t);if(r.derived&&r.repeat==='none'&&days<-30)return null;return {...r,next:n,days,due:days<=r.before};}).filter(Boolean).sort((a,b)=>a.next-b.next);
}
function updateBadge(n){const b=$('remBadge');b.textContent=n;b.classList.toggle('hidden',!n);}
async function notify(title,body){
 if(!('Notification' in window)||Notification.permission!=='granted')return;
 try{const reg=await navigator.serviceWorker?.getRegistration();if(reg){await reg.showNotification(title,{body,icon:'icon-192.png',badge:'icon-192.png',tag:'finvault-due'});return;}}catch{}
 try{new Notification(title,{body,icon:'icon-192.png'});}catch{}
}
function checkDue(){
 if(!key)return;const due=allReminders().filter(r=>r.due);updateBadge(due.length);
 const fresh=due.filter(r=>{const k=r.id+'|'+ymd(r.next);if(notified.has(k))return false;notified.add(k);return true;});
 if(!fresh.length)return;
 const title=fresh.length===1?'Reminder: '+fresh[0].title:`${fresh.length} reminders due`;
 toast('🔔 '+title);notify('FinVault',title+(fresh.length>1?' — '+fresh.slice(0,3).map(r=>r.title).join(', '):''));
}
const whenText=d=>d<0?`Overdue by ${-d} day${d===-1?'':'s'}`:d===0?'Today':d===1?'Tomorrow':`In ${d} days`;

const updateAvatar=()=>{$('avatar').textContent=(userName[0]||'A').toUpperCase();};
/* ---------- auth ---------- */
function showAuth(mode){if(!db)return;authMode=mode;const reg=mode==='register';$('authTitle').textContent=reg?'Your money, organized.':'Welcome back.';$('authSubtitle').textContent=reg?'Create your private, encrypted financial vault.':'Unlock your local financial vault.';$('nameField').classList.toggle('hidden',!reg);$('confirmField').classList.toggle('hidden',!reg);$('authSubmit').textContent=reg?'Create secure vault':'Unlock my vault';$('switchAuth').textContent=reg?(hasVault?'Already registered? Sign in':'Have an encrypted backup? Import it'):'Restore from a backup file';$('authError').textContent='';$('masterPassword').value='';$('confirmPassword').value='';$('masterPassword').autocomplete=reg?'new-password':'current-password';}
async function authSubmit(e){
 e.preventDefault();$('authError').textContent='';if(!db){$('authError').textContent='FinVault is open in another tab or the installed app. Close it completely, then reload this page.';return;}const pw=$('masterPassword').value;
 if(pw.length<10){$('authError').textContent='Use a master password of at least 10 characters.';return;}
 try{
  if(authMode==='register'){
   if(pw!==$('confirmPassword').value){$('authError').textContent='The passwords do not match.';return;}
   if(await dbGet()){hasVault=true;showAuth('login');$('authError').textContent='A vault already exists on this device. Sign in instead.';return;}
   userName=$('displayName').value.trim()||'there';const salt=crypto.getRandomValues(new Uint8Array(16));key=await deriveKey(pw,salt);vaultMeta={salt};records=[];reminders=[];doneMap={};profile={};settings={...DEF_SETTINGS};await persist();hasVault=true;await enterApp();
  }else{
   const meta=await dbGet();if(!meta){$('authError').textContent='No vault exists here. Create one first or import a backup.';return;}
   const k=await deriveKey(pw,bytes(meta.salt));let data;try{data=await decryptData(meta,k);}catch{$('authError').textContent='Incorrect password, or the vault data is damaged.';return;}
   key=k;vaultMeta={salt:bytes(meta.salt)};loadData(data,meta);await enterApp();
  }
 }catch(err){console.error(err);$('authError').textContent=db?('Could not open the vault ('+(err&&err.name||'error')+'). Reload the page; if it persists, close other FinVault tabs/apps.'):'Storage is not ready yet. Close other FinVault tabs or the installed app, then reload.';}
}
async function enterApp(){
 $('authScreen').classList.add('hidden');$('app').classList.remove('hidden');
 const hr=new Date().getHours();$('greeting').textContent=(hr<12?'Good morning':hr<18?'Good afternoon':'Good evening')+' 👋';
 updateAvatar();currentCategory='All';setView('vault','All');checkDue();clearInterval(timer);timer=setInterval(checkDue,60000);startLockTimer();requestPersist().then(()=>{if(view==='profile'&&key)renderProfile();});
}
function lockApp(reason){ocrStop();clipClearNow();clearInterval(timer);clearInterval(lockTick);key=null;records=[];reminders=[];doneMap={};profile={};settings={...DEF_SETTINGS};vaultMeta=null;notified.clear();closeModal(true);closeViewer(true);$('confirmRoot').innerHTML='';syncLock();['cards','profileView','remindersView','dueBanner'].forEach(i=>$(i).innerHTML='');$('searchInput').value='';$('clearSearch').classList.add('hidden');$('app').classList.add('hidden');$('authScreen').classList.remove('hidden');showAuth('login');if(typeof reason==='string'&&reason)$('authError').textContent=reason;}
document.addEventListener('visibilitychange',()=>{
 if(document.hidden){hiddenAt=Date.now();if(key&&Number(settings.leaveLock)===0&&Date.now()>suspendUntil)lockApp('Locked when you left the app.');return;}
 const away=hiddenAt?Date.now()-hiddenAt:0;hiddenAt=0;if(!key)return;
 const lt=Number(settings.leaveLock),m=Number(settings.autoLock)||0;
 if(Date.now()>suspendUntil){if(lt>0&&away>=lt*1000){lockApp('Locked while you were away.');return;}if(m&&away>=m*60000){lockApp('Locked after '+m+' minute'+(m>1?'s':'')+' of inactivity.');return;}}
 checkDue();clipCheck();
});

/* ---------- navigation ---------- */
function setView(v,cat){
 view=v;if(cat)currentCategory=cat;
 $('vaultView').classList.toggle('hidden',v!=='vault');$('remindersView').classList.toggle('hidden',v!=='reminders');$('profileView').classList.toggle('hidden',v!=='profile');
 if(v==='vault'){buildChips();render();}else if(v==='reminders')renderReminders();else renderProfile();
 window.scrollTo({top:0});
}
function buildChips(){const root=$('chips');root.innerHTML='';['All',...CATEGORIES].forEach(cat=>{const b=document.createElement('button');b.className='chip'+(currentCategory===cat?' active':'');b.textContent=cat;b.onclick=()=>setView('vault',cat);root.appendChild(b);});}

/* ---------- vault list ---------- */
function render(){
 const due=allReminders().filter(r=>r.due);updateBadge(due.length);
 const stale=records.length>0&&(!settings.lastBackup||Date.now()-settings.lastBackup>7*864e5);
 $('dueBanner').innerHTML=(due.length?`<div class="due-banner"><span>🔔 ${due.length} reminder${due.length>1?'s':''} need attention: ${escapeHTML(due[0].title)}${due.length>1?` +${due.length-1} more`:''}</span><button class="secondary" id="bannerBtn" type="button">View</button></div>`:'')+(stale?`<div class="due-banner"><span>💾 ${settings.lastBackup?'Last backup was '+ago(settings.lastBackup):'No backup yet'} — save a copy to Files or iCloud Drive so you never lose your vault.</span><button class="secondary" id="backupBannerBtn" type="button">Back up now</button></div>`:'');
 if($('bannerBtn'))$('bannerBtn').onclick=()=>setView('reminders');if($('backupBannerBtn'))$('backupBannerBtn').onclick=exportBackup;
 const q=normalize($('searchInput').value.trim());
 const filtered=records.filter(r=>(currentCategory==='All'||r.category===currentCategory)&&(!q||normalize([r.title,r.category,r.institution,r.notes,...Object.entries(r.fields||{}).filter(([k])=>!isSens(r.category,k)).map(e=>e[1])].join(' ')).includes(q)));
 filtered.sort((a,b)=>(sortNewest?1:-1)*((b.updatedAt||b.createdAt||0)-(a.updatedAt||a.createdAt||0)));
 $('listTitle').textContent=currentCategory==='All'?'All entries':currentCategory;$('entryCount').textContent=`${filtered.length} ${filtered.length===1?'entry':'entries'}`;
 const root=$('cards');root.innerHTML='';openRow=null;
 if(!filtered.length){const d=document.createElement('div');d.className='empty';d.innerHTML=`<div class="big">${q?'⌕':'✦'}</div><strong>${q?'No matching details':'Nothing here yet'}</strong><span>${q?'Try another keyword or category.':'Add your first entry to start building your vault.'}</span><div style="margin-top:18px">${!q?'<button class="primary" id="emptyAdd">＋ Add</button>':''}</div>`;root.appendChild(d);if($('emptyAdd'))$('emptyAdd').onclick=()=>openEditor();return;}
 filtered.forEach((r,i)=>{
  const color=catColor(r);const isCard=r.category==='Credit cards'||r.category==='Debit cards';
  const rows=[];spec(r.category).forEach(f=>{const v=r.fields?.[f.l];if(!v)return;if(f.s){if(f.m)rows.push([f.l,maskVal(v)]);}else rows.push([f.l,v]);});
  const card=document.createElement('article');card.className='entry';card.dataset.id=r.id;card.tabIndex=0;card.onclick=e=>{if(e.target.closest('button,a,input,select,textarea'))return;viewEntry(r.id);};card.onkeydown=e=>{if((e.key==='Enter'||e.key===' ')&&e.target===card){e.preventDefault();viewEntry(r.id);}};card.style.setProperty('--card-color',color);card.style.animationDelay=Math.min(i*35,240)+'ms';
  card.innerHTML=`<div class="entry-head"><span class="category-tag">${escapeHTML(r.category)}</span><button class="entry-menu" aria-label="Edit ${escapeHTML(r.title)}" title="Edit" data-edit="${r.id}">⋯</button></div><h3>${escapeHTML(r.title)}</h3>${isCard?cardFace(r):`<p class="institution">${escapeHTML(subtitle(r))}</p>`}<div class="detail-list">${(isCard?rows.filter(([k])=>k==='Card Limit'||k==='Payment Date'):rows.slice(0,3)).map(([k,v])=>`<div class="detail-row"><span>${escapeHTML(k)}</span><span>${escapeHTML(v)}</span></div>`).join('')}${r.notes?`<div class="detail-row"><span>Description</span><span>${escapeHTML(r.notes.length>65?r.notes.slice(0,62)+'…':r.notes)}</span></div>`:''}</div><div class="entry-footer"><button class="mini-btn" data-view="${r.id}">View details</button><button class="mini-btn" data-edit="${r.id}">Edit</button></div>`;
  const wrap=document.createElement('div');wrap.className='swipe-wrap';
  wrap.innerHTML='<div class="swipe-actions"><button type="button" class="sa copy">Copy</button><button type="button" class="sa edit">Edit</button><button type="button" class="sa del">Delete</button></div>';wrap.appendChild(card);
  wrap.querySelector('.copy').onclick=()=>{const q=quickValue(r);if(q)copyText(q[1],q[2]);else toast('Nothing to copy');wrap._close();};
  wrap.querySelector('.edit').onclick=()=>{wrap._close();openEditor(r.id);};
  wrap.querySelector('.del').onclick=()=>{wrap._close();deleteEntry(r.id);};
  swipeCard(wrap,card,216);root.appendChild(wrap);
 });
 root.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>openEditor(b.dataset.edit));root.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>viewEntry(b.dataset.view));
}

/* ---------- modal ---------- */
let modalTimer=null;
const reduceMotion=()=>matchMedia('(prefers-reduced-motion: reduce)').matches;
function lockPage(on){const h=document.documentElement;if(on&&!h.classList.contains('modal-open')){h.style.setProperty('--sbw',Math.max(0,innerWidth-h.clientWidth)+'px');h.classList.add('modal-open');}else if(!on)h.classList.remove('modal-open');}
function syncLock(){lockPage(!!$('modalRoot').innerHTML||!$('viewer').classList.contains('hidden')||!!$('confirmRoot').innerHTML);}
function modal(html){
 clearTimeout(modalTimer);
 const swap=!!$('modalRoot').querySelector('.modal-backdrop:not(.closing)');
 $('modalRoot').innerHTML=`<div class="modal-backdrop${swap?' no-anim':''}" id="backdrop"><section class="modal" role="dialog" aria-modal="true">${html}</section></div>`;
 lockPage(true);
 $('backdrop').addEventListener('click',e=>{if(e.target.id==='backdrop')closeModal();});
 $('modalRoot').querySelectorAll('.eye').forEach(b=>b.onclick=()=>{const i=b.previousElementSibling;i.type=i.type==='password'?'text':'password';});
}
function closeModal(now){
 clearTimeout(modalTimer);const bd=$('backdrop');
 if(!bd||now===true||reduceMotion()){$('modalRoot').innerHTML='';syncLock();return;}
 bd.style.animation='';bd.style.opacity='';const mm=bd.querySelector('.modal');if(mm){mm.style.animation='';mm.style.transform='';mm.style.willChange='';}
 bd.classList.add('closing');
 modalTimer=setTimeout(()=>{$('modalRoot').innerHTML='';syncLock();},320);
}
/* iOS-style alert for confirmations */
function confirmDialog({title,message,ok='Delete permanently',cancel='Cancel',danger=true,icon}){
 return new Promise(res=>{
  const root=$('confirmRoot');
  root.innerHTML=`<div class="alert-backdrop" id="alBackdrop"><div class="alert" role="alertdialog" aria-modal="true" aria-labelledby="alTitle" aria-describedby="alMsg"><div class="alert-body"><div class="alert-icon">${icon||(danger?'🗑':'?')}</div><h3 id="alTitle"></h3><p id="alMsg"></p></div><div class="alert-actions"><button type="button" class="${danger?'destructive':''}" id="alOk"></button><button type="button" class="cancel" id="alCancel"></button></div></div></div>`;
  $('alTitle').textContent=title;$('alMsg').textContent=message;$('alOk').textContent=ok;$('alCancel').textContent=cancel;
  syncLock();let done=false;
  const onKey=e=>{if(e.key==='Escape'){e.stopPropagation();finish(false);}};
  const finish=v=>{if(done)return;done=true;document.removeEventListener('keydown',onKey,true);const bd=$('alBackdrop');if(bd&&!reduceMotion()){bd.classList.add('closing');setTimeout(()=>{root.innerHTML='';syncLock();},200);}else{root.innerHTML='';syncLock();}res(v);};
  document.addEventListener('keydown',onKey,true);
  $('alOk').onclick=()=>finish(true);$('alCancel').onclick=()=>finish(false);$('alBackdrop').onclick=e=>{if(e.target.id==='alBackdrop')finish(false);};
  $('alCancel').focus();
 });
}
document.addEventListener('keydown',e=>{const open=!$('viewer').classList.contains('hidden');if(e.key==='Escape'){if(open)closeViewer();else if($('modalRoot').innerHTML)closeModal();}else if(open&&e.key==='ArrowRight')vwSlide(1,0);else if(open&&e.key==='ArrowLeft')vwSlide(-1,0);});

function fieldInput(f,val,idx){
 const L=escapeHTML(f.l),v=escapeHTML(val||''),id='f_'+idx;
 const attrs=`${f.mode?`inputmode="${f.mode}"`:''} ${f.max?`maxlength="${f.max}"`:''} ${f.t==='url'?'placeholder="https://"':''}`;
 let ctl;
 if(f.t==='select')ctl=`<select id="${id}" data-field="${L}"><option value="">Select</option>${f.o.map(o=>`<option ${o===val?'selected':''}>${escapeHTML(o)}</option>`).join('')}</select>`;
 else if(f.t==='year'){const y=new Date().getFullYear(),list=[];for(let i=y-3;i<=y+25;i++)list.push(String(i));if(val&&!list.includes(val))list.push(val);ctl=`<select id="${id}" data-field="${L}"><option value="">Select</option>${list.map(o=>`<option ${o===val?'selected':''}>${o}</option>`).join('')}</select>`;}
 else if(f.s)ctl=`<div class="pw-wrap"><input id="${id}" data-field="${L}" type="password" autocomplete="new-password" value="${v}" ${attrs}><button type="button" class="eye" aria-label="Show or hide ${L}">👁</button></div>`;
 else ctl=`<input id="${id}" data-field="${L}" type="${f.t||'text'}" autocomplete="off" value="${v}" ${attrs}>`;
 const hint=f.rem?`<span class="hint">🔔 Automatic reminder${f.rem==='monthly'?' — repeats every month on this day':''}</span>`:'';
 return `<div class="field"><label for="${id}">${L}</label>${ctl}${hint}</div>`;
}
const fieldsMarkup=(cat,vals)=>spec(cat).map((f,i)=>fieldInput(f,vals?.[f.l],i)).join('');
function deriveTitle(cat,f){
 const pick={'Credit cards':[f['Bank Name'],f['Card Type']].filter(Boolean).join(' '),'Debit cards':[f['Bank Name'],f['Card Type']].filter(Boolean).join(' '),'Netbanking':f['Bank Name'],'Login details':f.Name||f.Username,'FD details':f['Bank / company'],'BOND details':f.Issuer,'Notes':f.Topic}[cat];
 return pick||cat;
}
/* ---------- card scan (on-device OCR) ---------- */
/* parse:start */
const BANKS=[['HDFC Bank',/hdfc/i],['ICICI Bank',/icici/i],['State Bank of India',/state\s*bank|\bsbi\b/i],['Axis Bank',/\baxis\b/i],['Kotak Mahindra Bank',/kotak/i],['Punjab National Bank',/punjab\s*national|\bpnb\b/i],['Bank of Baroda',/bank\s*of\s*baroda|\bbob\b/i],['Canara Bank',/canara/i],['Union Bank of India',/union\s*bank/i],['Central Bank of India',/central\s*bank/i],['Bank of India',/bank\s*of\s*india/i],['Indian Bank',/indian\s*bank/i],['IndusInd Bank',/indusind/i],['Yes Bank',/\byes\s*bank/i],['IDFC FIRST Bank',/idfc/i],['Federal Bank',/federal\s*bank/i],['RBL Bank',/\brbl\b/i],['AU Small Finance Bank',/\bau\s*small|\bau\s*bank/i],['IDBI Bank',/idbi/i],['Standard Chartered',/standard\s*chartered/i],['HSBC',/hsbc/i],['American Express',/american\s*express/i],['Citibank',/citi\s*bank|\bciti\b/i],['South Indian Bank',/south\s*indian/i],['Karnataka Bank',/karnataka\s*bank/i],['Bandhan Bank',/bandhan/i],['Bank of Maharashtra',/maharashtra/i],['Indian Overseas Bank',/overseas/i],['UCO Bank',/\buco\b/i],['Jammu & Kashmir Bank',/j\s*&\s*k\s*bank|jammu/i],['Equitas Small Finance Bank',/equitas/i],['SBM Bank',/\bsbm\b/i],['DBS Bank',/\bdbs\b/i]];
const luhn=s=>{let t=0,d=false;for(let i=s.length-1;i>=0;i--){let n=+s[i];if(d){n*=2;if(n>9)n-=9;}t+=n;d=!d;}return t%10===0;};
const LOOK={O:'0',o:'0',Q:'0',D:'0',I:'1',l:'1','|':'1',S:'5',B:'8'};
function findNumber(text){
 const runs=text.match(/[0-9OoQDIl|SB](?:[ \-]?[0-9OoQDIl|SB]){12,22}/g)||[];let fallback='';
 for(const run of runs){const d=run.replace(/[^0-9OoQDIl|SB]/g,'').replace(/[OoQDIl|SB]/g,c=>LOOK[c]);
  if(d.length>=13&&d.length<=19&&luhn(d)&&/^[2-68]/.test(d))return{number:d,valid:true};
  if(d.length>19)for(const len of [16,15,19]){for(let i=0;i+len<=d.length;i++){const c=d.slice(i,i+len);if(luhn(c)&&/^[2-68]/.test(c))return{number:c,valid:true};}}
  if(!fallback&&d.length>=15&&d.length<=19&&/^\d+$/.test(d))fallback=d.slice(0,d.length===15?15:16);}
 return fallback?{number:fallback,valid:false}:null;
}
function findNetwork(num,text){
 if(num){const n2=+num.slice(0,2),n4=+num.slice(0,4);
  if(num[0]==='4')return'Visa';if(n2===34||n2===37)return'Amex';if((n2>=51&&n2<=55)||(n4>=2221&&n4<=2720))return'Mastercard';
  if(n2===60||n2===65||n2===81||n2===82||num.startsWith('508'))return'RuPay';}
 if(/rupay/i.test(text))return'RuPay';if(/master\s*card|maestro/i.test(text))return'Mastercard';if(/american\s*express|amex/i.test(text))return'Amex';if(/\bvisa\b/i.test(text))return'Visa';return'';
}
const NOT_NAME=/\b(VALID|THRU|THROUGH|FROM|GOOD|DEBIT|CREDIT|BANK|VISA|MASTER|MASTERCARD|RUPAY|AMEX|AMERICAN|EXPRESS|PLATINUM|SIGNATURE|CLASSIC|GOLD|TITANIUM|WORLD|INFINITE|CARD|EXPIRES|EXPIRY|MEMBER|SINCE|CUSTOMER|CARE|AUTHORIZED|AUTHORISED|INTERNATIONAL|LIMITED|LTD|TRAVEL|REWARDS|PREPAID|CONTACTLESS|NATIONAL|PAYMENTS|CORPORATION|INDIA|INDIAN|FINANCE|PREMIER|SELECT|BUSINESS|CVV|CVC|USE|ONLY|NOT|TRANSFERABLE|PRIVATE|MONTH|YEAR|DATE|PRIME|STATE|UNION|OF|THE|AND|FIRST|SMALL|BANDHAN|HDFC|ICICI|AXIS|SBI|KOTAK|FEDERAL|CANARA|BARODA|INDUSIND|IDFC|RBL|YES|DBS|HSBC|CITI)\b/;
function findName(text,numAt){
 const lines=text.split(/\r?\n/).map(s=>s.replace(/[^A-Za-z .'\-]/g,' ').replace(/\s+/g,' ').trim()),cands=[];
 lines.forEach((ln,i)=>{if(!/^[A-Z][A-Z .'\-]+$/.test(ln))return;const w=ln.split(' ').filter(Boolean);if(w.length<2||w.length>4||ln.length<5||ln.length>26)return;if(NOT_NAME.test(ln))return;if(w.some(x=>x.replace(/[^A-Z]/g,'').length<1))return;if(w.filter(x=>x.length>1).length<1)return;cands.push({ln,i});});
 if(!cands.length)return'';const after=cands.filter(c=>numAt>=0&&c.i>numAt);return(after[0]||cands[0]).ln.replace(/\s*\.$/,'');
}
function findExpiry(text){
 const re=/(?<![0-9])(0[1-9]|1[0-2])\s*[\/\-]\s*(\d{4}|\d{2})(?![0-9])/g;let m,best=null;
 while((m=re.exec(text))){let y=+m[2];if(m[2].length===2)y+=2000;if(y<2000||y>2099)continue;const v=y*12+ +m[1];if(!best||v>best.v)best={v,m:m[1],y:String(y)};}
 return best?{month:best.m,year:best.y}:null;
}
function parseCard(texts){
 texts=[].concat(texts);const all=texts.join('\n');let num=null;
 for(const t of texts){num=findNumber(t);if(num&&num.valid)break;}
 if(!num||!num.valid){const j=findNumber(all);if(j)num=j;}
 const lines=all.split(/\r?\n/);let numAt=-1;if(num)numAt=lines.findIndex(l=>l.replace(/[^0-9OoQDIl|SB]/g,'').includes(num.number.slice(0,6))||l.replace(/\D/g,'').includes(num.number.slice(-4)));
 const out={number:num?.number||'',numberValid:!!num?.valid,network:findNetwork(num?.number,all),name:findName(all,numAt),expiry:findExpiry(all),bank:'',cvv:'',kind:''};
 for(const[b,re]of BANKS)if(re.test(all)){out.bank=b;break;}
 const c=all.match(/(?:cvv2?|cvc2?|cid|security\s*code)\D{0,6}(\d{3,4})(?!\d)/i);if(c)out.cvv=c[1];
 if(/\bdebit\b/i.test(all))out.kind='Debit cards';else if(/\bcredit\b/i.test(all))out.kind='Credit cards';
 return out;
}
/* parse:end */
/* ocr engine: loaded only when you scan, files live in ./ocr (no network) */
const OCR_BASE=new URL('ocr/',location.href).href;let ocrWorker=null,ocrIdle=null,ocrLoad=null;
function loadScript(src){return new Promise((ok,no)=>{const s=document.createElement('script');s.src=src;s.onload=ok;s.onerror=()=>no(new Error('Could not load the reader'));document.head.appendChild(s);});}
function ocrStop(){clearTimeout(ocrIdle);const w=ocrWorker;ocrWorker=null;ocrLoad=null;if(w)w.terminate().catch(()=>{});}
let ocrOnProg=()=>{};
async function ocrGet(){
 clearTimeout(ocrIdle);if(ocrWorker)return ocrWorker;
 if(!ocrLoad)ocrLoad=(async()=>{
  if(!window.Tesseract)await loadScript(OCR_BASE+'tesseract.min.js');
  const simd=await (async()=>{try{return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11]));}catch{return false;}})();
  const w=await Tesseract.createWorker('eng',1,{workerPath:OCR_BASE+'worker.min.js',corePath:OCR_BASE+'core',langPath:OCR_BASE+'lang',gzip:true,cacheMethod:'none',logger:m=>ocrOnProg(m)});
  await w.setParameters({preserve_interword_spaces:'1',tessedit_pageseg_mode:'11'});ocrWorker=w;return w;})().catch(e=>{ocrLoad=null;throw e;});
 return ocrLoad;
}
function prepCanvas(img,invert){
 const M=1800,k=Math.min(1,M/Math.max(img.naturalWidth||img.width,img.naturalHeight||img.height)),w=Math.round((img.naturalWidth||img.width)*k),h=Math.round((img.naturalHeight||img.height)*k);
 const c=document.createElement('canvas');c.width=w;c.height=h;const x=c.getContext('2d',{willReadFrequently:true});x.drawImage(img,0,0,w,h);
 const d=x.getImageData(0,0,w,h),p=d.data;let lo=255,hi=0;const g=new Uint8Array(w*h);
 for(let i=0,j=0;i<p.length;i+=4,j++){const v=(p[i]*.299+p[i+1]*.587+p[i+2]*.114)|0;g[j]=v;if(v<lo)lo=v;if(v>hi)hi=v;}
 const span=Math.max(40,hi-lo);
 for(let i=0,j=0;i<p.length;i+=4,j++){let v=(g[j]-lo)*255/span;v=v<0?0:v>255?255:v;if(invert)v=255-v;p[i]=p[i+1]=p[i+2]=v;}
 x.putImageData(d,0,0);return c;
}
function loadImg(file){return new Promise((ok,no)=>{const u=URL.createObjectURL(file),i=new Image();i.onload=()=>{URL.revokeObjectURL(u);ok(i);};i.onerror=()=>{URL.revokeObjectURL(u);no(new Error('Could not read that image'));};i.src=u;});}
async function scanCardImage(file,step){
 const img=await loadImg(file);step('Starting the reader…',0.02);const w=await ocrGet();const texts=[];
 const run=async(canvas,label,base,opts)=>{step(label,base);await w.setParameters(opts);const r=await w.recognize(canvas);texts.push(r.data.text||'');return parseCard(texts);};
 let res=await run(prepCanvas(img,false),'Reading the card…',.3,{tessedit_char_whitelist:'',tessedit_pageseg_mode:'11'});
 if(!res.numberValid)res=await run(prepCanvas(img,false),'Looking again for the number…',.6,{tessedit_char_whitelist:'0123456789 /-',tessedit_pageseg_mode:'11'});
 if(!res.numberValid)res=await run(prepCanvas(img,true),'Trying light-on-dark text…',.8,{tessedit_char_whitelist:'',tessedit_pageseg_mode:'11'});
 await w.setParameters({tessedit_char_whitelist:'',tessedit_pageseg_mode:'11'});
 clearTimeout(ocrIdle);ocrIdle=setTimeout(ocrStop,60000);return res;
}
function openEditor(id=null){
 const old=id?records.find(r=>r.id===id):null;
 const cat=old?.category||(CATEGORIES.includes(currentCategory)?currentCategory:'Credit cards');
 modal(`<div class="modal-head"><h2>${old?'Edit entry':'Add new entry'}</h2><button class="close" id="modalClose" type="button">×</button></div><form id="entryForm"><div class="form-grid"><div class="field span2"><label for="entryCategory">Category</label><select id="entryCategory">${CATEGORIES.map(c=>`<option ${c===cat?'selected':''}>${escapeHTML(c)}</option>`).join('')}</select></div><div class="field span2"><label for="entryTitle">Title</label><input id="entryTitle" maxlength="100" placeholder="Optional — auto-filled from the details below" value="${escapeHTML(old?.title||'')}"></div><div class="field span2 ${cat==='Credit cards'||cat==='Debit cards'?'':'hidden'}" id="scanBox"><label>Scan card</label><div class="scan-drop" id="scanDrop"><div class="scan-row"><button type="button" class="secondary ${coarse()?'':'hidden'}" id="scanCam">📷 Take photo</button><button type="button" class="secondary" id="scanPick">🖼 ${coarse()?'Choose image':'Choose or drop an image'}</button></div><span class="hint">Reads the number, expiry, name, network and bank on this device — nothing is uploaded. Always check the result.</span><label class="keep"><input type="checkbox" id="scanKeep"><span>Keep this photo with the entry (saved unencrypted)</span></label><div class="scan-prog hidden" id="scanProg"><div class="bar"><i id="scanBar"></i></div><span id="scanMsg"></span></div><div class="scan-res hidden" id="scanRes"></div></div><input type="file" id="scanInCam" accept="image/*" capture="environment" class="hidden"><input type="file" id="scanIn" accept="image/*" class="hidden"></div><div id="dynamicFields" class="form-grid span2">${fieldsMarkup(cat,old?.category===cat?old.fields:null)}</div><div class="field span2"><label for="entryNotes">Description (optional)</label><textarea id="entryNotes" maxlength="4000" placeholder="Add helpful context. Avoid storing OTPs.">${escapeHTML(old?.notes||'')}</textarea></div><div class="field span2"><label>Images</label><div class="img-strip hidden" id="imgStrip"></div><div><button type="button" class="secondary" id="addImgBtn">＋ Add images</button></div><span class="hint">Images are saved on this device as plain base64 — not encrypted.</span><input type="file" id="imgInput" accept="image/*" multiple class="hidden"></div></div><div class="modal-actions"><button type="button" class="secondary" id="cancelEntry">Cancel</button><button type="submit" class="primary">Save entry</button></div>${old?'<button type="button" class="danger btn-block" id="deleteEntry">Delete entry</button>':''}</form>`);
 $('modalClose').onclick=closeModal;$('cancelEntry').onclick=closeModal;
 const entryId=old?.id||crypto.randomUUID();let imgs=[];
 const drawStrip=()=>{const st=$('imgStrip');if(!st)return;st.innerHTML='';imgs.forEach((src,i)=>{const w=document.createElement('div');w.className='img-item';const im=document.createElement('img');im.src=src;im.alt='Attachment '+(i+1);im.onclick=()=>openViewer(imgs,i);const x=document.createElement('button');x.type='button';x.className='img-x';x.textContent='×';x.setAttribute('aria-label','Remove image');x.onclick=()=>{imgs.splice(i,1);drawStrip();};w.append(im,x);st.appendChild(w);});st.classList.toggle('hidden',!imgs.length);};
 if(old)imgGet(old.id).then(l=>{if($('imgStrip')&&!imgs.length){imgs=l.slice();drawStrip();}});
 $('addImgBtn').onclick=()=>{suspendLock(120000);$('imgInput').click();};
 $('imgInput').onchange=async e=>{const files=[...e.target.files];e.target.value='';for(const f of files){try{imgs.push(await readImage(f));}catch{toast('Could not read '+f.name);}}drawStrip();};

 const setF=(label,val)=>{const el=[...$('dynamicFields').querySelectorAll('[data-field]')].find(i=>i.dataset.field===label);if(!el||!val)return false;if(el.tagName==='SELECT'&&![...el.options].some(o=>o.value===val||o.text===val)){const o=document.createElement('option');o.textContent=val;el.appendChild(o);}el.value=val;el.classList.add('scanned');el.addEventListener('input',()=>el.classList.remove('scanned'),{once:true});el.addEventListener('change',()=>el.classList.remove('scanned'),{once:true});return true;};
 let scanning=false;
 const scanMsg=(t,p)=>{$('scanProg').classList.remove('hidden');if(t!=null)$('scanMsg').textContent=t;if(p!=null)$('scanBar').style.width=Math.round(p*100)+'%';};
 const scanGo=async file=>{
  if(!file||scanning)return;if(location.protocol==='file:'){const r0=$('scanRes');r0.innerHTML='<div class="warn-line"></div>';r0.firstChild.textContent='⚠ Scanning does not work when the file is opened from a folder (file://). Open the app from https://AbhishekBedre.github.io/finvault/ or run a local server (python -m http.server) and open http://localhost:8000.';r0.classList.remove('hidden');return;}if(!/^image\//.test(file.type||'image/')){toast('Please choose an image');return;}
  scanning=true;const res=$('scanRes');res.classList.add('hidden');res.innerHTML='';
  ocrOnProg=m=>{if(!$('scanMsg'))return;const st=m.status||'';if(/traineddata|core/.test(st))scanMsg('Downloading the reader (first time only)…',Math.min(.28,.02+(m.progress||0)*.26));};
  scanMsg(ocrWorker?'Starting…':'Preparing the reader…',.02);$('scanPick').disabled=true;if($('scanCam'))$('scanCam').disabled=true;
  try{
   const r=await scanCardImage(file,scanMsg);if(!$('scanBox'))return;
   const got=[],warn=[];
   if(r.number){setF('Card Number',r.number);got.push('Card number');if(!r.numberValid)warn.push('The card number failed its check digit — one or more digits are probably misread. Please correct it.');}
   if(r.expiry){setF('Expiry Month',r.expiry.month);setF('Expiry Year',r.expiry.year);got.push('Expiry');}
   if(r.name){setF('Card Holder Name',r.name);got.push('Name');}
   if(r.network){setF('Card Type',r.network);got.push('Network');}
   if(r.bank){setF('Bank Name',r.bank);got.push('Bank');}
   if(r.cvv){setF('CVV',r.cvv);got.push('CVV');}
   const cur=$('entryCategory').value;if(r.kind&&r.kind!==cur)warn.push('The card says it is a '+(r.kind==='Debit cards'?'debit':'credit')+' card, but the category is '+(cur==='Debit cards'?'Debit cards':'Credit cards')+'.');
   $('scanProg').classList.add('hidden');
   if($('scanKeep').checked){try{imgs.push(await readImage(file));drawStrip();}catch{warn.push('The photo could not be kept.');}}
   res.innerHTML=got.length?`<div class="ok-line">✓ Filled: ${got.join(', ')}</div><div class="hint">Highlighted fields came from the scan. Please check every one against the card.</div>`:`<div class="hint">Nothing could be read. Try a sharper photo: card flat, good light, no glare, filling the frame.</div>`;
   warn.forEach(w=>{const d=document.createElement('div');d.className='warn-line';d.textContent='⚠ '+w;res.appendChild(d);});res.classList.remove('hidden');
   if(got.length&&!$('scanKeep').checked)toast('Photo discarded — only the text was kept');
  }catch(e){if($('scanProg')){$('scanProg').classList.add('hidden');const r2=$('scanRes');r2.innerHTML='<div class="warn-line"></div>';r2.firstChild.textContent='⚠ '+(/reader|fetch|network|load/i.test(e.message)?'The reader could not be loaded. Check your connection once and try again.':'The scan failed: '+e.message);r2.classList.remove('hidden');}}
  finally{scanning=false;if($('scanPick')){$('scanPick').disabled=false;if($('scanCam'))$('scanCam').disabled=false;}}
 };
 const scanOpen=cam=>{suspendLock(180000);$(cam?'scanInCam':'scanIn').click();};
 if($('scanCam'))$('scanCam').onclick=()=>scanOpen(true);$('scanPick').onclick=()=>scanOpen(false);
 ['scanInCam','scanIn'].forEach(i=>$(i).onchange=e=>{const f=e.target.files[0];e.target.value='';scanGo(f);});
 const dz=$('scanDrop');['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('over');}));['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('over');}));dz.addEventListener('drop',e=>scanGo(e.dataTransfer?.files?.[0]));
 $('entryCategory').onchange=()=>{const cur={};$('dynamicFields').querySelectorAll('[data-field]').forEach(i=>cur[i.dataset.field]=i.value);const c=$('entryCategory').value;$('scanBox').classList.toggle('hidden',!(c==='Credit cards'||c==='Debit cards'));$('dynamicFields').innerHTML=fieldsMarkup(c,{...(old?.category===c?old.fields:{}),...cur});$('dynamicFields').querySelectorAll('.eye').forEach(b=>b.onclick=()=>{const i=b.previousElementSibling;i.type=i.type==='password'?'text':'password';});};
 $('entryForm').onsubmit=async e=>{
  e.preventDefault();const category=$('entryCategory').value;const fields={};
  if(old&&old.category===category)Object.entries(old.fields||{}).forEach(([k,v])=>{if(!spec(category).some(f=>f.l===k))fields[k]=v;});
  $('dynamicFields').querySelectorAll('[data-field]').forEach(i=>{if(i.value.trim())fields[i.dataset.field]=i.value.trim();});
  const now=Date.now();
  const entry={id:entryId,category,title:$('entryTitle').value.trim()||deriveTitle(category,fields),institution:old?.institution||'',fields,notes:$('entryNotes').value.trim(),createdAt:old?.createdAt||now,updatedAt:now};
  if(old)records=records.map(r=>r.id===old.id?entry:r);else records.unshift(entry);
  try{await imgPut(entryId,imgs);}catch{toast('Images could not be saved');}await persist();closeModal();render();checkDue();toast(old?'Entry updated securely':'Entry saved securely');
 };
 if(old)$('deleteEntry').onclick=()=>deleteEntry(old.id);
}
const SINGULAR={'Credit cards':'Credit card','Debit cards':'Debit card','Netbanking':'Netbanking','Login details':'Login details','FD details':'FD details','BOND details':'Bond details','Notes':'Note'};
function viewEntry(id){
 const r=records.find(x=>x.id===id);if(!r)return;
 const isCard=r.category==='Credit cards'||r.category==='Debit cards';
 const base=[];
 spec(r.category).forEach(f=>{const v=r.fields?.[f.l];if(v)base.push({label:f.l,value:String(v),hide:!!f.s,num:!!f.m});});
 Object.entries(r.fields||{}).forEach(([k,v])=>{if(!spec(r.category).some(f=>f.l===k)&&v)base.push({label:k,value:String(v),hide:SENS_RE.test(k),num:false});});
 base.forEach(x=>{x.secret=SENS_RE.test(x.label);x.out=x.num?x.value.replace(/\s+/g,''):x.value;});   // card / account numbers go out as one continuous string
 const shareRows=r.notes?[...base,{label:'Description',value:r.notes,hide:false,num:false,secret:false,out:r.notes}]:base;
 const canNative=coarse()&&typeof navigator.share==='function';
 const sel=new Set();
 modal(`<div class="modal-head"><h2>${escapeHTML(r.title)}</h2><button class="close" id="modalClose" type="button">×</button></div><div style="margin-bottom:10px"><span class="category-tag" style="--card-color:${catColor(r)}">${escapeHTML(r.category)}</span></div>${isCard?cardFace(r):`<p style="color:var(--muted);margin:0 0 6px">${escapeHTML(subtitle(r))}</p>`}<div class="img-strip hidden" id="viewImgs"></div><div id="shareBar" class="hidden"></div><div id="viewRows"></div><div id="sharePreview" class="hidden"></div><div class="modal-actions" id="viewActions"></div>`);
 $('modalClose').onclick=closeModal;
 const buildText=(mask)=>{const lines=[r.title+' ('+(SINGULAR[r.category]||r.category)+')'];shareRows.forEach((x,i)=>{if(sel.has(i))lines.push(x.label+': '+(mask&&x.secret?'••••••••':x.out));});return lines.join('\n');};

 function drawView(){
  $('shareBar').classList.add('hidden');$('sharePreview').classList.add('hidden');$('viewRows').onchange=null;
  $('viewRows').innerHTML=base.map((x,i)=>`<div class="vrow"><span class="vl">${escapeHTML(x.label)}</span><span class="vv" id="vv${i}"></span><span class="vb">${x.hide?`<button class="mini-btn" data-show="${i}" type="button">Show</button>`:''}<button class="mini-btn" data-copy="${i}" type="button">Copy</button></span></div>`).join('')+(r.notes?`<div style="padding-top:14px"><div style="font-size:13px;color:var(--muted);margin-bottom:5px">Description</div><div style="white-space:pre-wrap;overflow-wrap:anywhere">${escapeHTML(r.notes)}</div></div>`:'');
  base.forEach((x,i)=>{$('vv'+i).textContent=x.hide?'••••••••':x.value;if(x.hide)holdReveal($('vv'+i),x.value);});
  if(base.some(x=>x.hide))$('viewRows').insertAdjacentHTML('beforeend','<p class="hint" style="margin:12px 0 0">Tip: press and hold a hidden value to peek — it hides when you let go.</p>');
  $('viewRows').querySelectorAll('[data-show]').forEach(b=>b.onclick=()=>{const i=+b.dataset.show,el=$('vv'+i),hidden=b.textContent==='Show';el.textContent=hidden?base[i].value:'••••••••';el.dataset.open=hidden?'1':'0';b.textContent=hidden?'Hide':'Show';});
  $('viewRows').querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>{const x=base[+b.dataset.copy];copyText(x.value,x.hide);});
  const a=$('viewActions');a.className='modal-actions';
  a.innerHTML=`<button class="secondary" id="cancelEntry" type="button">Close</button><button class="secondary" id="shareBtn" type="button">${canNative?'Share':'Copy details'}</button><button class="primary" id="editFromView" type="button">Edit entry</button>`;
  $('cancelEntry').onclick=closeModal;$('editFromView').onclick=()=>openEditor(id);
  $('shareBtn').onclick=()=>{sel.clear();shareRows.forEach((x,i)=>{if(!x.secret)sel.add(i);});drawShare();};
 }
 const rowShown=x=>x.secret?'••••••••':x.hide&&x.num?maskVal(x.value):(x.value.length>80?x.value.slice(0,77)+'…':x.value);
 function updatePreview(){
  const n=sel.size,hasSecret=[...sel].some(i=>shareRows[i].secret);
  $('sharePreview').innerHTML=`<div class="pv-title">Message preview</div><pre class="pv">${escapeHTML(n?buildText(true):'Nothing selected')}</pre>${hasSecret?'<div class="hint" style="margin-top:6px">🔒 Secret values are hidden here but will be sent in full.</div>':''}`;
  const go=$('shGo');go.textContent=(canNative?'Share with details':'Copy details')+' ('+n+')';go.disabled=!n;
 }
 function drawShare(){
  $('shareBar').classList.remove('hidden');$('sharePreview').classList.remove('hidden');
  $('shareBar').innerHTML=`<p class="hint" style="margin:10px 0 8px">Tick the details to include. CVV, PIN and passwords start unticked.</p><div class="chips" id="shPresets"><button class="chip" data-preset="safe" type="button">Non-secret</button><button class="chip" data-preset="all" type="button">Select all</button><button class="chip" data-preset="none" type="button">Clear</button></div>`;
  $('viewRows').innerHTML=shareRows.map((x,i)=>`<label class="srow"><input type="checkbox" data-s="${i}" ${sel.has(i)?'checked':''}><span class="sbox"></span><span class="sbody"><span class="vl">${escapeHTML(x.label)}</span><span class="vv">${escapeHTML(rowShown(x))}</span></span>${x.secret?'<span class="pill soon">⚠ Secret</span>':''}</label>`).join('');
  const a=$('viewActions');a.className='modal-actions sticky';
  a.innerHTML=`<button class="secondary" id="shCancel" type="button">Cancel</button><button class="primary" id="shGo" type="button"></button>`;
  const sync=()=>$('viewRows').querySelectorAll('input[data-s]').forEach(c=>{c.checked=sel.has(+c.dataset.s);});
  $('viewRows').onchange=e=>{const i=+e.target.dataset.s;if(Number.isNaN(i))return;e.target.checked?sel.add(i):sel.delete(i);updatePreview();};
  $('shPresets').querySelectorAll('[data-preset]').forEach(b=>b.onclick=()=>{sel.clear();if(b.dataset.preset==='safe')shareRows.forEach((x,i)=>{if(!x.secret)sel.add(i);});else if(b.dataset.preset==='all')shareRows.forEach((x,i)=>sel.add(i));sync();updatePreview();});
  $('shCancel').onclick=drawView;
  $('shGo').onclick=goShare;
  updatePreview();
 }
 async function goShare(){
  if(!sel.size)return;
  const text=buildText(false),chosen=[...sel].map(i=>shareRows[i]),secrets=chosen.filter(x=>x.secret);
  if(secrets.length){
   const ok=await confirmDialog({icon:'⚠️',title:'Send secrets as plain text?',message:'You are about to share '+secrets.map(x=>x.label).join(', ')+'. Chat and SMS messages are not encrypted by FinVault and stay in chat history and backups. Only continue if you trust the recipient.',ok:'Share anyway',cancel:'Go back'});
   if(!ok)return;
  }
  const copied=await copyQuiet(text,chosen.some(x=>x.hide||x.secret));      // always copy first
  if(canNative){
   suspendLock(120000);
   try{await navigator.share({text});toast(copied?'Shared — also copied to clipboard':'Shared');}
   catch(e){if(e&&e.name==='AbortError')toast(copied?'Not shared — the details are still copied':'Share cancelled');else toast(copied?'Copied — paste it into your chat':'Could not share or copy');}
  }else toast(copied?'Details copied — paste them anywhere':'Could not copy — select the preview text instead');
  if(copied||canNative)drawView();
 }
 drawView();
 imgGet(id).then(l=>{const st=$('viewImgs');if(!st||!l.length)return;l.forEach((src,i)=>{const w=document.createElement('div');w.className='img-item';const im=document.createElement('img');im.src=src;im.alt='Attachment '+(i+1);im.onclick=()=>openViewer(l,i);w.appendChild(im);st.appendChild(w);});st.classList.remove('hidden');});
}
async function deleteEntry(id){
 const r=records.find(x=>x.id===id);if(!r)return;
 const ok=await confirmDialog({title:'Delete permanently?',message:`“${r.title}” and its images will be permanently deleted from this device. This can’t be undone.`});
 if(!ok)return;
 records=records.filter(x=>x.id!==id);try{await imgPut(id,[]);}catch{}await persist();
 closeModal();
 const el=document.querySelector(`.entry[data-id="${id}"]`);if(el&&!reduceMotion()){el.classList.add('removing');await new Promise(r=>setTimeout(r,320));}
 if(view==='reminders')renderReminders();else render();toast('Entry deleted');
}

/* ---------- reminders view ---------- */
function renderReminders(){
 const list=allReminders();updateBadge(list.filter(r=>r.due).length);
 const root=$('remindersView');
 root.innerHTML=`<div class="page-head"><button class="secondary" id="remBack" type="button">← Back</button><h1>Reminders</h1><button class="primary" id="addRem" type="button">＋ Add</button></div><p class="page-sub">Card payments, FD &amp; bond maturities and your own dates. Entry dates are added automatically.</p>${list.length?'<div class="btn-row" style="justify-content:center;margin:-6px 0 6px"><button class="secondary" id="remAllIcs" type="button">📅 Add all to calendar</button></div><p class="page-sub" style="font-size:13px;margin-bottom:18px">Gets alerts even when the app is closed. If you change a reminder, download it again — calendar apps update the event you added before.</p>':''}<div id="remList"></div>`;
 $('addRem').onclick=()=>openReminder();$('remBack').onclick=()=>setView('vault');if($('remAllIcs'))$('remAllIcs').onclick=()=>exportICS(list,'finvault-reminders.ics');
 const box=$('remList');
 if(!list.length){box.innerHTML=`<div class="empty"><div class="big">🔔</div><strong>No upcoming reminders</strong><span>Add one here, or save a Payment Date / Maturity date on an entry.</span></div>`;return;}
 list.forEach(r=>{
  const cls=r.days<0?'over':r.due?'soon':'';const mon=r.next.toLocaleDateString(undefined,{month:'short'});
  const row=document.createElement('div');row.className='rem';
  row.innerHTML=`<div class="rem-date"><b>${r.next.getDate()}</b><span>${escapeHTML(mon)}</span></div><div class="rem-body"><strong>${escapeHTML(r.title)}</strong><div class="rem-sub">${r.next.toLocaleDateString(undefined,{weekday:'short',year:'numeric',month:'short',day:'numeric'})} · ${r.repeat==='monthly'?'Every month':r.repeat==='yearly'?'Every year':'One time'}${r.derived?' · From an entry':''}${r.note?' · '+escapeHTML(r.note):''}</div></div><span class="pill ${cls}">${whenText(r.days)}</span><div class="rem-actions"><button class="mini-btn" data-done="${escapeHTML(r.id)}">✓ Done</button><button class="mini-btn" data-ics="${escapeHTML(r.id)}">📅 Calendar</button>${r.derived?`<button class="mini-btn" data-open="${r.entryId}">Open</button>`:`<button class="mini-btn" data-editrem="${r.id}">Edit</button>`}</div>`;
  const wrap=document.createElement('div');wrap.className='rem-wrap';wrap.innerHTML='<div class="swipe-done"><span>✓ Done</span></div>';wrap.appendChild(row);box.appendChild(wrap);swipeRem(wrap,row,row.querySelector('[data-done]'));
 });
 box.querySelectorAll('[data-done]').forEach(b=>b.onclick=async()=>{const r=list.find(x=>x.id===b.dataset.done);doneMap[r.id]=ymd(r.next);await persist();renderReminders();toast(r.repeat==='none'?'Marked done':'Done — next one scheduled');});
 box.querySelectorAll('[data-open]').forEach(b=>b.onclick=()=>viewEntry(b.dataset.open));
 box.querySelectorAll('[data-ics]').forEach(b=>b.onclick=()=>{const r=list.find(x=>x.id===b.dataset.ics);if(r)exportICS([r],'finvault-'+slug(r.title)+'.ics');});
 box.querySelectorAll('[data-editrem]').forEach(b=>b.onclick=()=>openReminder(b.dataset.editrem));
}
function openReminder(id=null){
 const old=id?reminders.find(r=>r.id===id):null;
 modal(`<div class="modal-head"><h2>${old?'Edit reminder':'Add reminder'}</h2><button class="close" id="modalClose" type="button">×</button></div><form id="remForm"><div class="form-grid"><div class="field span2"><label for="remTitle">Title *</label><input id="remTitle" required maxlength="100" placeholder="e.g. Pay electricity bill" value="${escapeHTML(old?.title||'')}"></div><div class="field"><label for="remDate">Date *</label><input id="remDate" type="date" required value="${escapeHTML(old?.date||ymd(todayD()))}"></div><div class="field"><label for="remRepeat">Repeat</label><select id="remRepeat">${[['none','Does not repeat'],['monthly','Every month'],['yearly','Every year']].map(([v,t])=>`<option value="${v}" ${(old?.repeat||'none')===v?'selected':''}>${t}</option>`).join('')}</select></div><div class="field span2"><label for="remBefore">Remind me</label><select id="remBefore">${BEFORE.map(([v,t])=>`<option value="${v}" ${(old?old.before:1)===v?'selected':''}>${t}</option>`).join('')}</select></div><div class="field span2"><label for="remNote">Note (optional)</label><textarea id="remNote" maxlength="500" style="min-height:70px">${escapeHTML(old?.note||'')}</textarea></div></div><div class="modal-actions"><button type="button" class="secondary" id="cancelEntry">Cancel</button><button type="submit" class="primary">Save reminder</button></div>${old?'<button type="button" class="danger btn-block" id="delRem">Delete reminder</button>':''}</form>`);
 $('modalClose').onclick=closeModal;$('cancelEntry').onclick=closeModal;
 $('remForm').onsubmit=async e=>{e.preventDefault();const rem={id:old?.id||crypto.randomUUID(),title:$('remTitle').value.trim(),date:$('remDate').value,repeat:$('remRepeat').value,before:Number($('remBefore').value),note:$('remNote').value.trim()};if(!rem.title||!validDate(rem.date))return;if(old){if(old.date!==rem.date)delete doneMap[rem.id];reminders=reminders.map(r=>r.id===rem.id?rem:r);}else reminders.push(rem);for(const k of [...notified])if(k.startsWith(rem.id+'|'))notified.delete(k);await persist();closeModal();renderReminders();checkDue();toast('Reminder saved');};
 if(old)$('delRem').onclick=async()=>{if(!(await confirmDialog({title:'Delete permanently?',message:`“${old.title}” will be permanently deleted. This can’t be undone.`})))return;reminders=reminders.filter(r=>r.id!==old.id);delete doneMap[old.id];await persist();closeModal();renderReminders();toast('Reminder deleted');};
}
async function enableNotifications(){if(!('Notification' in window)){toast('Notifications are not supported in this browser');return;}const p=await Notification.requestPermission();toast(p==='granted'?'Notifications enabled':'Notifications were not allowed');renderProfile();}

/* ---------- profile ---------- */
const isStandalone=()=>matchMedia('(display-mode: standalone)').matches||navigator.standalone===true;
const isIOS=()=>/iphone|ipad|ipod/i.test(navigator.userAgent)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);
function installPanel(){
 if(isStandalone())return `<p>✓ FinVault is installed and running as an app.</p>`;
 if(deferredPrompt)return `<p>Install FinVault on this device for a full-screen, app-like experience that also works offline.</p><div class="btn-row"><button class="primary" id="installBtn" type="button">⬇ Install app</button></div>`;
 if(isIOS())return `<p>On iPhone/iPad (Safari): tap the <b>Share</b> button, then <b>Add to Home Screen</b>.</p><p>Note: the Home Screen app has its own storage. Export a backup from Safari, then use <i>Restore from a backup file</i> in the installed app.</p>`;
 return `<p>Open your browser menu and choose <b>Install app</b> or <b>Add to Home screen</b>. (Needs the page to be served over HTTPS.)</p>`;
}
function renderProfile(){
 const th=getTheme(),perm='Notification' in window?Notification.permission:'unsupported';
 const permText=perm==='granted'?'✓ Notifications are on':perm==='denied'?'Blocked — allow notifications in your browser/site settings':perm==='unsupported'?'Not supported in this browser':'Not enabled yet';
 const stale=records.length>0&&(!settings.lastBackup||Date.now()-settings.lastBackup>7*864e5);const lastTxt=settings.lastBackup?'Last backup: '+new Date(settings.lastBackup).toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'})+' ('+ago(settings.lastBackup)+')':'No backup yet';const opts=(list,cur)=>list.map(([v,t])=>`<option value="${v}" ${Number(cur)===v?'selected':''}>${t}</option>`).join('');
 const root=$('profileView');
 root.innerHTML=`<div class="page-head"><button class="secondary" id="profBack" type="button">← Back</button><h1>Profile</h1><span></span></div><p class="page-sub">Your details, appearance and security.</p><div class="panels">
 <section class="panel"><div class="profile-head"><div class="avatar big">${escapeHTML((userName[0]||'A').toUpperCase())}</div><div><strong>${escapeHTML(userName)}</strong><div class="hint">${escapeHTML(profile.email||'Add your details below')}</div></div></div><form id="profileForm"><div class="field"><label for="pName">Full name</label><input id="pName" maxlength="60" value="${escapeHTML(userName==='there'?'':userName)}"></div><div class="field"><label for="pEmail">Email</label><input id="pEmail" type="email" maxlength="100" autocomplete="email" value="${escapeHTML(profile.email||'')}"></div><div class="field"><label for="pMobile">Mobile number</label><input id="pMobile" type="tel" maxlength="20" autocomplete="tel" value="${escapeHTML(profile.mobile||'')}"></div><div class="field"><label for="pDob">Date of birth</label><input id="pDob" type="date" value="${escapeHTML(profile.dob||'')}"></div><button class="primary" type="submit">Save profile</button></form></section>
 <div style="display:grid;gap:16px">
 <section class="panel"><h3>Appearance</h3><div class="seg" id="themeSeg">${[['light','☀ Light'],['dark','● Black'],['auto','Auto']].map(([v,t])=>`<button type="button" data-theme="${v}" class="${th===v?'active':''}">${t}</button>`).join('')}</div><p>Black uses a pure-black background — easy on the eyes and saves battery on OLED screens. Auto follows your device setting.</p></section>
 <section class="panel"><h3>Reminders</h3><div class="field" style="margin-top:0"><label for="pAlert">Alert for entry dates (payment / maturity)</label><select id="pAlert">${BEFORE.map(([v,t])=>`<option value="${v}" ${Number(settings.alertDays)===v?'selected':''}>${t}</option>`).join('')}</select></div><p>${permText}. Alerts appear while the app is open. For alerts when it is closed, use <b>📅 Add to calendar</b> on the Reminders page.</p>${perm==='default'?'<div class="btn-row"><button class="secondary" id="enableNotif" type="button">Enable notifications</button></div>':''}</section>
 <section class="panel"><h3>Security</h3><div class="field" style="margin-top:0"><label for="pAutoLock">Auto-lock after inactivity</label><select id="pAutoLock">${opts([[1,'1 minute'],[5,'5 minutes'],[15,'15 minutes'],[0,'Never']],settings.autoLock)}</select></div><div class="field"><label for="pLeave">When I switch away from the app</label><select id="pLeave">${opts([[0,'Lock immediately'],[30,'Lock after 30 seconds'],[60,'Lock after 1 minute'],[-1,"Don't lock"]],settings.leaveLock)}</select></div><div class="field"><label for="pClip">Clear copied passwords &amp; card numbers</label><select id="pClip">${opts([[15,'After 15 seconds'],[30,'After 30 seconds'],[60,'After 1 minute'],[0,'Never']],settings.clipClear)}</select></div><p>Clipboard clearing can be blocked by iPhone Safari, which only lets a page write to the clipboard right after a tap.</p><div class="btn-row"><button class="secondary" id="pChangePw" type="button">Change master password</button></div></section>
 <section class="panel"><h3>Backup &amp; data</h3><p><span class="pill ${stale?'soon':''}">${lastTxt}</span></p><div class="btn-row"><button class="primary" id="pExport" type="button">Export backup</button><button class="secondary" id="pImport" type="button">Import backup</button></div><p>On phones this opens the share sheet — choose <b>Save to Files</b> (iCloud Drive) or Drive. ${records.length} entries · ${reminders.length} custom reminders. The vault stays encrypted with your master password; attached images are included unencrypted.</p><div style="border-top:1px solid var(--line);margin-top:12px;padding-top:12px"><strong>Storage protection</strong><p id="persistStatus" style="margin:4px 0">Checking…</p><div class="btn-row"><button class="secondary hidden" id="pPersist" type="button">Request protection</button></div></div></section>
 <section class="panel"><h3>Install app</h3>${installPanel()}</section></div></div><button class="danger logout" id="pLogout" type="button">Logout</button>`;
 $('profBack').onclick=()=>setView('vault');
 $('profileForm').onsubmit=async e=>{e.preventDefault();userName=$('pName').value.trim()||'there';profile={email:$('pEmail').value.trim(),mobile:$('pMobile').value.trim(),dob:$('pDob').value};await persist();updateAvatar();renderProfile();toast('Profile saved');};
 $('themeSeg').querySelectorAll('[data-theme]').forEach(b=>b.onclick=()=>{applyTheme(b.dataset.theme);renderProfile();});
 $('pAlert').onchange=async()=>{settings.alertDays=Number($('pAlert').value);await persist();checkDue();toast('Saved');};
 if($('enableNotif'))$('enableNotif').onclick=enableNotifications;
 $('pExport').onclick=exportBackup;$('pImport').onclick=()=>{suspendLock(120000);$('importFile').click();};$('pChangePw').onclick=openChangePassword;$('pLogout').onclick=()=>lockApp();
 [['pAutoLock','autoLock'],['pLeave','leaveLock'],['pClip','clipClear']].forEach(([id,k])=>{$(id).onchange=async()=>{settings[k]=Number($(id).value);await persist();touch();toast('Saved');};});
 persistState().then(st=>{const el=$('persistStatus');if(!el)return;el.textContent=st==='on'?'✓ Protected — the browser will not clear your vault automatically when storage is low.':st==='off'?'Not granted — the browser may clear data when space is low. Install the app, use it regularly, then tap Request.':'Not supported in this browser.';if(st==='off')$('pPersist').classList.remove('hidden');});
 $('pPersist').onclick=async()=>{const ok=await requestPersist();toast(ok?'Storage protected':'The browser did not grant it');renderProfile();};
 if($('installBtn'))$('installBtn').onclick=doInstall;
}
function openChangePassword(){
 modal(`<div class="modal-head"><h2>Change master password</h2><button class="close" id="modalClose" type="button">×</button></div><form id="pwForm"><div class="field"><label for="curPw">Current password</label><input id="curPw" type="password" autocomplete="current-password" required></div><div class="field"><label for="newPw">New password</label><input id="newPw" type="password" autocomplete="new-password" minlength="10" required placeholder="At least 10 characters"></div><div class="field"><label for="newPw2">Confirm new password</label><input id="newPw2" type="password" autocomplete="new-password" required></div><div class="error" id="pwErr" role="alert"></div><div class="modal-actions"><button type="button" class="secondary" id="cancelEntry">Cancel</button><button class="primary" type="submit">Change password</button></div></form>`);
 $('modalClose').onclick=closeModal;$('cancelEntry').onclick=closeModal;
 $('pwForm').onsubmit=async e=>{e.preventDefault();const n1=$('newPw').value;if(n1.length<10){$('pwErr').textContent='Use at least 10 characters.';return;}if(n1!==$('newPw2').value){$('pwErr').textContent='The new passwords do not match.';return;}
  try{const meta=await dbGet();const k=await deriveKey($('curPw').value,bytes(meta.salt));await decryptData(meta,k);}catch{$('pwErr').textContent='Current password is incorrect.';return;}
  const salt=crypto.getRandomValues(new Uint8Array(16));key=await deriveKey(n1,salt);vaultMeta={salt};await persist();closeModal();toast('Password changed. Older backups still use the old password.');};
}

/* ---------- backup ---------- */
const ago=ts=>{const d=Math.floor((Date.now()-ts)/864e5);return d<1?'today':d===1?'yesterday':d+' days ago';};
const slug=s=>String(s).toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,40)||'reminder';
const coarse=()=>matchMedia('(pointer:coarse)').matches;

/* auto-lock */
let lastActive=Date.now(),hiddenAt=0,suspendUntil=0,lockTick=null;
const suspendLock=ms=>{suspendUntil=Date.now()+ms;};
const touch=()=>{lastActive=Date.now();};
['pointerdown','keydown','touchstart','scroll','input'].forEach(ev=>addEventListener(ev,touch,{passive:true,capture:true}));
function startLockTimer(){clearInterval(lockTick);lastActive=Date.now();lockTick=setInterval(()=>{if(!key)return;const m=Number(settings.autoLock)||0;if(m&&Date.now()>suspendUntil&&Date.now()-lastActive>m*60000)lockApp('Locked after '+m+' minute'+(m>1?'s':'')+' of inactivity.');},10000);}

/* persistent storage */
async function requestPersist(){try{if(navigator.storage?.persist){if(await navigator.storage.persisted())return true;return await navigator.storage.persist();}}catch{}return false;}
async function persistState(){try{if(!navigator.storage?.persisted)return 'unsupported';return (await navigator.storage.persisted())?'on':'off';}catch{return 'unsupported';}}

/* file delivery: share sheet on phones (Save to Files / iCloud Drive), download elsewhere */
async function deliverFile(file,allowShare=true){
 if(allowShare&&coarse()&&navigator.canShare&&navigator.canShare({files:[file]})){
  suspendLock(120000);
  try{await navigator.share({files:[file],title:file.name});return 'shared';}
  catch(e){if(e&&e.name==='AbortError')return 'cancelled';}
 }
 const url=URL.createObjectURL(file);const a=document.createElement('a');a.href=url;a.download=file.name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),5000);return 'downloaded';
}
async function exportBackup(){
 try{const meta=await dbGet();if(!meta){toast('No saved vault found');return;}
  const images=await imgAll();
  const json=JSON.stringify({app:'FinVault',format:1,exportedAt:new Date().toISOString(),vault:meta,images},null,2);
  const file=new File([json],'finvault-backup-'+ymd(new Date())+'.json',{type:'application/json'});
  const r=await deliverFile(file);if(r==='cancelled')return;
  settings.lastBackup=Date.now();await persist();
  toast(r==='shared'?'Backup shared — check it was saved to Files':'Encrypted backup downloaded');
  if(view==='profile')renderProfile();else if(view==='vault')render();
 }catch(e){console.error(e);toast('Could not export backup');}
}

/* calendar (.ics): stable UID per reminder + rising SEQUENCE, so re-importing updates the existing event */
const icsEsc=s=>String(s??'').replace(/\\/g,'\\\\').replace(/;/g,'\;').replace(/,/g,'\\,').replace(/\r?\n/g,'\\n');
const icsFold=l=>{const out=[];let t=l;while(t.length>70){out.push(t.slice(0,70));t=' '+t.slice(70);}out.push(t);return out.join('\r\n');};
const icsDay=d=>d.getFullYear()+pad(d.getMonth()+1)+pad(d.getDate());
const icsStamp=d=>d.getUTCFullYear()+pad(d.getUTCMonth()+1)+pad(d.getUTCDate())+'T'+pad(d.getUTCHours())+pad(d.getUTCMinutes())+pad(d.getUTCSeconds())+'Z';
const icsUid=id=>'fv-'+String(id).replace(/[^A-Za-z0-9-]+/g,'-')+'@finvault.local';
function icsEvent(r,now,seq){
 const day=icsDay(r.next),before=Number(r.before)||0;
 const L=['BEGIN:VEVENT','UID:'+icsUid(r.id),'DTSTAMP:'+icsStamp(now),'LAST-MODIFIED:'+icsStamp(now),'SEQUENCE:'+seq,'DTSTART:'+day+'T090000','DTEND:'+day+'T093000','SUMMARY:'+icsEsc(r.title),'DESCRIPTION:'+icsEsc([r.note,'From FinVault'].filter(Boolean).join('\n'))];
 if(r.repeat==='monthly')L.push('RRULE:FREQ=MONTHLY');else if(r.repeat==='yearly')L.push('RRULE:FREQ=YEARLY');
 L.push('TRANSP:TRANSPARENT');
 if(before>0)L.push('BEGIN:VALARM','ACTION:DISPLAY','DESCRIPTION:'+icsEsc(r.title),'TRIGGER:-P'+before+'D','END:VALARM');
 L.push('BEGIN:VALARM','ACTION:DISPLAY','DESCRIPTION:'+icsEsc(r.title),'TRIGGER:PT0S','END:VALARM','END:VEVENT');
 return L;
}
function buildICS(list,now=new Date()){
 const seq=Math.floor(now.getTime()/1000);
 const L=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//FinVault//Reminders//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH','X-WR-CALNAME:FinVault reminders'];
 list.forEach(r=>L.push(...icsEvent(r,now,seq)));L.push('END:VCALENDAR');
 return L.map(icsFold).join('\r\n')+'\r\n';
}
async function exportICS(list,name){
 if(!list.length){toast('Nothing to add');return;}
 const file=new File([buildICS(list)],name,{type:'text/calendar'});
 const r=await deliverFile(file,false);
 if(r!=='cancelled')toast('Calendar file ready — open it to add '+(list.length>1?list.length+' reminders':'the reminder'));
}

/* image viewer */
let vwList=[],vwIdx=0;
function showViewer(){const v=$('viewer');v.classList.remove('zoom');$('vwImg').src=vwList[vwIdx];$('vwImg').alt='Image '+(vwIdx+1);$('vwCount').textContent=(vwIdx+1)+' / '+vwList.length;const many=vwList.length>1;$('vwPrev').classList.toggle('hidden',!many);$('vwNext').classList.toggle('hidden',!many);$('vwStage').scrollTo(0,0);}
let vwTimer=null;
function openViewer(list,i){clearTimeout(vwTimer);window.vwReset&&vwReset();$('vwImg').style.animation='';$('viewer').style.animation='';vwList=list.slice();vwIdx=i;$('viewer').classList.remove('hidden','closing');lockPage(true);showViewer();}
function closeViewer(now){const v=$('viewer');if(v.classList.contains('hidden'))return;clearTimeout(vwTimer);const fin=()=>{v.classList.add('hidden');v.classList.remove('zoom','closing');$('vwImg').removeAttribute('src');$('vwImg').style.animation='';v.style.animation='';window.vwReset&&vwReset();vwList=[];syncLock();};if(now===true||reduceMotion()){fin();return;}$('vwImg').style.animation='';v.style.animation='';v.classList.add('closing');vwTimer=setTimeout(fin,240);}
function stepViewer(d){if(vwList.length<2)return;vwIdx=(vwIdx+d+vwList.length)%vwList.length;showViewer();}
$('vwClose').onclick=closeViewer;$('vwPrev').onclick=()=>vwSlide(-1,0);$('vwNext').onclick=()=>vwSlide(1,0);
$('vwImg').onclick=()=>$('viewer').classList.toggle('zoom');
$('vwStage').onclick=e=>{if(e.target===$('vwStage'))closeViewer();};


/* card face */
const NETS={Visa:'#1a3a8f',Mastercard:'#b3361f',RuPay:'#0b7a4b',Amex:'#1b6fa8'};
function cardFace(r){
 const f=r.fields||{},type=f['Card Type'],num=f['Card Number']?String(f['Card Number']).replace(/\s/g,''):'',last=num.slice(-4);
 const dots=num?(num.length===15?'•••• •••••• •'+last:'•••• •••• •••• '+last):'•••• •••• •••• ••••';
 const exp=f['Expiry Month']&&f['Expiry Year']?f['Expiry Month']+'/'+String(f['Expiry Year']).slice(-2):'—';
 const color=catColor(r);
 return `<div class="cardface" style="--cf:${color}"><div class="cf-top"><div><span class="cf-bank">${escapeHTML(f['Bank Name']||r.category)}</span><span class="cf-kind">${r.category==='Credit cards'?'CREDIT CARD':'DEBIT CARD'}${f['Co Issuer Name']?' · '+escapeHTML(f['Co Issuer Name']):''}</span></div>${type?`<span class="cf-net" style="--net:${NETS[type]||'#333'}">${escapeHTML(type)}</span>`:''}</div><div class="cf-chip"></div><div class="cf-num">${dots}</div><div class="cf-bot"><div><small>CARD HOLDER</small><b>${escapeHTML(f['Card Holder Name']||'—')}</b></div><div><small>VALID THRU</small><b>${escapeHTML(exp)}</b></div></div></div>`;
}
async function importBackup(file){
 try{const obj=JSON.parse(await file.text());if(obj.app!=='FinVault'||!obj.vault?.cipher||!obj.vault?.salt){toast('This is not a valid FinVault backup');return;}
  if(await dbGet()&&!(await confirmDialog({title:'Replace current vault?',message:'The vault saved on this device will be permanently replaced by this backup. Export a backup first if you need it.',ok:'Replace vault'})))return;
  await dbPut(obj.vault);await imgReplaceAll(Array.isArray(obj.images)?obj.images.filter(x=>x&&x.id&&Array.isArray(x.images)):[]);hasVault=true;lockApp();toast('Backup imported. Sign in with its original master password.');
 }catch(e){toast('Could not read this backup file');}finally{$('importFile').value='';}
}

/* ---------- install (PWA) ---------- */
function doInstall(){if(!deferredPrompt)return;deferredPrompt.prompt();deferredPrompt.userChoice.finally(()=>{deferredPrompt=null;$('installAuth').classList.add('hidden');if(view==='profile'&&key)renderProfile();});}
addEventListener('beforeinstallprompt',e=>{e.preventDefault();deferredPrompt=e;if(!isStandalone())$('installAuth').classList.remove('hidden');if(view==='profile'&&key)renderProfile();});
addEventListener('appinstalled',()=>{deferredPrompt=null;$('installAuth').classList.add('hidden');toast('FinVault installed');});
if('serviceWorker' in navigator&&/^https?:$/.test(location.protocol))addEventListener('load',()=>navigator.serviceWorker.register('sw.js').catch(()=>{}));

/* ---------- pinch: zooming in is allowed, zooming out below 100% is not ---------- */
(()=>{let d0=0;const dist=t=>Math.hypot(t[0].clientX-t[1].clientX,t[0].clientY-t[1].clientY),sc=()=>window.visualViewport?.scale||1;
 addEventListener('touchstart',e=>{if(e.touches.length===2)d0=dist(e.touches);},{passive:true});
 addEventListener('touchmove',e=>{if(e.touches.length!==2)return;const d=dist(e.touches);if(d<d0&&sc()<=1.01)e.preventDefault();d0=d;},{passive:false});
 addEventListener('gesturechange',e=>{if(sc()*e.scale<1)e.preventDefault();},{passive:false});
})();
/* ---------- gestures (touch): spring physics, finger-tracking drags ---------- */
const buzz=ms=>{try{navigator.vibrate&&navigator.vibrate(ms);}catch{}};
function spring({from,to,v=0,k=380,c=34,step,done,until}){
 if(reduceMotion()){step(to);done&&done();return()=>{};}
 let x=from,vel=v*1000,last=performance.now(),dead=false,id=0;
 const tick=now=>{if(dead)return;const dt=Math.min(.032,Math.max(0,(now-last)/1000));last=now;const n=Math.max(1,Math.ceil(dt/.004)),h=dt/n;
  for(let i=0;i<n;i++){vel+=(-k*(x-to)-c*vel)*h;x+=vel*h;}
  step(x);if((until&&until(x))||(Math.abs(x-to)<.4&&Math.abs(vel)<8)){if(!until)step(to);dead=true;done&&done();return;}id=requestAnimationFrame(tick);};
 id=requestAnimationFrame(tick);return()=>{dead=true;cancelAnimationFrame(id);};
}
const velo=s=>{if(s.length<2)return 0;const a=s[0],b=s[s.length-1];return b.t>a.t?(b.p-a.p)/(b.t-a.t):0;};
const track=(s,p)=>{const t=performance.now();s.push({t,p});while(s.length>2&&t-s[0].t>100)s.shift();};
const clearAnim=el=>{el.style.animation='';el.style.transform='';el.style.opacity='';el.style.willChange='';};
/* 1. swipe down to close a sheet */
(function(){
 const root=$('modalRoot');let st=null,cancel=null,cur=0;
 root.addEventListener('touchstart',e=>{
  if(e.touches.length!==1)return;const bd=$('backdrop'),m=e.target.closest('.modal');if(!m||!bd||bd.classList.contains('closing'))return;
  const t=e.touches[0],r=m.getBoundingClientRect(),head=t.clientY-r.top<64||!!e.target.closest('.modal-head');
  if(!head&&e.target.closest('.img-strip,textarea,.pv'))return;
  const wasAnim=!!cancel&&cur>2;if(cancel){cancel();cancel=null;}
  st={m,bd,x:t.clientX,y:t.clientY,head,h:r.height,s:[],on:false,base:0,y0:0};
  if(wasAnim){st.on=true;st.base=cur;st.y0=t.clientY;}
 },{passive:true});
 root.addEventListener('touchmove',e=>{
  if(!st)return;const t=e.touches[0],dy=t.clientY-st.y,dx=t.clientX-st.x;
  if(!st.on){if(Math.abs(dx)>Math.abs(dy)&&Math.abs(dx)>8){st=null;return;}
   if(dy<-8){st=null;return;}
   if(dy>8&&Math.abs(dy)>Math.abs(dx)&&(st.head||st.m.scrollTop<=0)){st.on=true;st.y0=t.clientY;st.base=0;st.m.style.animation='none';st.bd.style.animation='none';st.m.style.willChange='transform';}else return;}
  e.preventDefault();let off=st.base+(t.clientY-st.y0);if(off<0)off*=.15;cur=off;
  st.m.style.transform=`translateY(${off}px)`;st.bd.style.opacity=String(1-Math.min(1,Math.max(0,off)/st.h)*.9);track(st.s,t.clientY);
 },{passive:false});
 const end=ev=>{
  if(!st||!st.on){st=null;return;}const s=st;st=null;const v=ev.type==='touchcancel'?0:velo(s.s),off=cur;
  const put=x=>{cur=x;s.m.style.transform=`translateY(${x}px)`;s.bd.style.opacity=String(1-Math.min(1,Math.max(0,x)/s.h)*.9);};
  if(off>s.h*.33||v>.55){buzz(8);cancel=spring({from:off,to:s.h+30,v:Math.max(v,.3),k:220,c:30,step:put,until:x=>x>=s.h,done:()=>{cancel=null;if($('backdrop')===s.bd)closeModal(true);}});}
  else cancel=spring({from:off,to:0,v,step:put,done:()=>{cancel=null;cur=0;s.m.style.transform='';s.bd.style.opacity='';s.m.style.willChange='';}});
 };
 root.addEventListener('touchend',end);root.addEventListener('touchcancel',end);
})();
/* 2. image viewer: swipe down to close, swipe sideways to slide to the next / previous photo */
let vwDrag=false,vwBusy=false;
const vwSlide=(d,vel)=>{
 const v=$('viewer'),img=$('vwImg');if(vwBusy||vwList.length<2)return;vwBusy=true;const W=innerWidth;let x0=window.vwCurX||0;
 const putX=x=>{window.vwCurX=x;img.style.transform=x?`translateX(${x}px)`:'';};
 img.style.animation='none';
 spring({from:x0,to:-d*W,v:vel||0,k:240,c:30,step:putX,until:x=>Math.abs(x)>=W*.98,done:()=>{
  stepViewer(d);putX(d*W);img.style.animation='none';
  const go=()=>spring({from:d*W,to:0,v:0,k:300,c:30,step:putX,done:()=>{putX(0);vwBusy=false;}});
  if(img.decode)img.decode().then(go,go);else go();
 }});
};
(function(){
 const v=$('viewer'),img=$('vwImg');let st=null,cancel=null,cur=0,curX=0;
 const putY=y=>{cur=y;const p=Math.min(1,Math.max(0,Math.abs(y))/(innerHeight*.8));img.style.transform=`translateY(${y}px) scale(${1-p*.18})`;v.style.background=`rgba(0,0,0,${(.93*(1-p)).toFixed(3)})`;};
 const putX=x=>{curX=x;window.vwCurX=x;img.style.transform=x?`translateX(${x}px)`:'';};
 const reset=()=>{img.style.transform='';v.style.background='';curX=0;window.vwCurX=0;};
 window.vwReset=reset;
 v.addEventListener('touchstart',e=>{if(vwBusy||e.touches.length!==1||v.classList.contains('zoom')||e.target.closest('button'))return;if(cancel){cancel();cancel=null;}const t=e.touches[0];st={x:t.clientX,y:t.clientY,s:[],on:false,mode:''};},{passive:true});
 v.addEventListener('touchmove',e=>{
  if(!st)return;const t=e.touches[0],dy=t.clientY-st.y,dx=t.clientX-st.x;
  if(!st.on){
   if(Math.abs(dx)>10&&Math.abs(dx)>Math.abs(dy)){if(vwList.length<2){st=null;return;}st.mode='h';}
   else if(Math.abs(dy)>10&&Math.abs(dy)>Math.abs(dx))st.mode='v';else return;
   st.on=true;vwDrag=true;st.x0=t.clientX;st.y0=t.clientY;img.style.animation='none';v.style.animation='none';}
  e.preventDefault();
  if(st.mode==='h'){putX(t.clientX-st.x0);track(st.s,t.clientX);}else{putY(t.clientY-st.y0);track(st.s,t.clientY);}
 },{passive:false});
 const end=ev=>{
  if(!st||!st.on){st=null;return;}const s=st;st=null;const vel=ev.type==='touchcancel'?0:velo(s.s);setTimeout(()=>{vwDrag=false;},50);
  if(s.mode==='h'){const x=curX;
   if(ev.type!=='touchcancel'&&(Math.abs(x)>innerWidth*.22||Math.abs(vel)>.5&&Math.abs(x)>24)){buzz(5);vwSlide(x<0?1:-1,vel);}
   else cancel=spring({from:x,to:0,v:vel,step:putX,done:()=>{cancel=null;putX(0);}});
   return;}
  const y=cur;
  if(Math.abs(y)>innerHeight*.18||Math.abs(vel)>.6){buzz(8);const dir=(y||vel)<0?-1:1;cancel=spring({from:y,to:dir*innerHeight,v:vel,k:200,c:28,step:putY,until:x=>Math.abs(x)>=innerHeight*.9,done:()=>{cancel=null;closeViewer(true);}});}
  else cancel=spring({from:y,to:0,v:vel,step:putY,done:()=>{cancel=null;cur=0;reset();}});
 };
 v.addEventListener('touchend',end);v.addEventListener('touchcancel',end);
})();
/* 3. swipe left on an entry card for Copy / Edit / Delete */
let openRow=null;
function quickValue(r){const f=r.fields||{};for(const k of ['Card Number','Account Number','Password','Username','Reference URL']){if(f[k])return[k,(k.includes('Number')?String(f[k]).replace(/\s+/g,''):String(f[k])),isSens(r.category,k)];}const e=Object.entries(f).find(([,v])=>v);return e?[e[0],String(e[1]),isSens(r.category,e[0])]:null;}
function swipeCard(wrap,card,W){
 let st=null,cancel=null,off=0;const put=x=>{off=x;card.style.transform=x?`translateX(${x}px)`:'';};
 const settle=(to,v)=>{if(cancel)cancel();cancel=spring({from:off,to,v,step:put,done:()=>{cancel=null;if(!to)wrap.classList.remove('swiping');}});};
 wrap._close=()=>{wrap.classList.remove('open');if(openRow===wrap)openRow=null;settle(0,0);};
 wrap.addEventListener('touchstart',e=>{if(e.touches.length!==1||e.target.closest('.swipe-actions'))return;if(openRow&&openRow!==wrap)openRow._close();if(cancel){cancel();cancel=null;}const t=e.touches[0];st={x:t.clientX,y:t.clientY,s:[],on:false,base:off,x0:0};},{passive:true});
 wrap.addEventListener('touchmove',e=>{
  if(!st)return;const t=e.touches[0],dx=t.clientX-st.x,dy=t.clientY-st.y;
  if(!st.on){if(Math.abs(dy)>Math.abs(dx)&&Math.abs(dy)>8){st=null;return;}if(Math.abs(dx)>8&&Math.abs(dx)>Math.abs(dy)){st.on=true;st.x0=t.clientX;card.style.animation='none';card.style.transition='none';wrap.classList.add('swiping');}else return;}
  e.preventDefault();let x=st.base+(t.clientX-st.x0);if(x>0)x*=.22;else if(x<-W)x=-W+(x+W)*.3;put(x);track(st.s,t.clientX);
 },{passive:false});
 const end=ev=>{if(!st||!st.on){st=null;return;}const v=ev.type==='touchcancel'?0:velo(st.s);st=null;let open=off<-W*.45||v<-.5;if(v>.5)open=false;wrap.classList.toggle('open',open);openRow=open?wrap:(openRow===wrap?null:openRow);if(open&&off>-W)buzz(6);settle(open?-W:0,v);};
 wrap.addEventListener('touchend',end);wrap.addEventListener('touchcancel',end);
 wrap.addEventListener('click',e=>{if(wrap.classList.contains('open')&&!e.target.closest('.swipe-actions')){e.preventDefault();e.stopPropagation();wrap._close();}},true);
}
document.addEventListener('touchstart',e=>{if(openRow&&!openRow.contains(e.target))openRow._close();},{capture:true,passive:true});
/* 4. swipe right on a reminder to mark it done */
function swipeRem(wrap,row,doneBtn){
 let st=null,cancel=null,off=0,armed=false;const T=104;
 const put=x=>{off=x;row.style.transform=x?`translateX(${x}px)`:'';const p=Math.min(1,x/T);wrap.style.setProperty('--p',p.toFixed(3));};
 const settle=(to,v,done)=>{if(cancel)cancel();cancel=spring({from:off,to,v,step:put,done:()=>{cancel=null;done&&done();}});};
 wrap.addEventListener('touchstart',e=>{if(e.touches.length!==1)return;if(cancel){cancel();cancel=null;}const t=e.touches[0];st={x:t.clientX,y:t.clientY,s:[],on:false,x0:0};armed=false;},{passive:true});
 wrap.addEventListener('touchmove',e=>{
  if(!st)return;const t=e.touches[0],dx=t.clientX-st.x,dy=t.clientY-st.y;
  if(!st.on){if(Math.abs(dy)>Math.abs(dx)&&Math.abs(dy)>8){st=null;return;}if(dx>8&&dx>Math.abs(dy)){st.on=true;st.x0=t.clientX;row.style.animation='none';wrap.classList.add('swiping');}else return;}
  e.preventDefault();let x=t.clientX-st.x0;if(x<0)x*=.15;else if(x>T)x=T+(x-T)*.5;put(x);
  const now=x>=T;if(now!==armed){armed=now;wrap.classList.toggle('armed',now);if(now)buzz(10);}track(st.s,t.clientX);
 },{passive:false});
 const end=ev=>{
  if(!st||!st.on){st=null;return;}const v=ev.type==='touchcancel'?0:velo(st.s);st=null;
  if(ev.type!=='touchcancel'&&(off>=T||(v>.7&&off>40))){
   settle(wrap.offsetWidth+20,Math.max(v,.5),()=>{const h=wrap.offsetHeight;wrap.style.height=h+'px';wrap.style.overflow='hidden';wrap.getBoundingClientRect();if(reduceMotion()){doneBtn.click();return;}wrap.style.transition='height .24s cubic-bezier(.32,.72,0,1),margin .24s,opacity .2s';wrap.style.height='0';wrap.style.marginBottom='0';wrap.style.opacity='0';setTimeout(()=>doneBtn.click(),250);});
  }else{armed=false;wrap.classList.remove('armed');settle(0,v,()=>wrap.classList.remove('swiping'));}
 };
 wrap.addEventListener('touchend',end);wrap.addEventListener('touchcancel',end);
}
/* 5. press and hold a hidden value to peek; it hides again when you let go */
function holdReveal(el,value){
 el.classList.add('holdable');let tm=null,shown=false,sx=0,sy=0;
 const hide=()=>{clearTimeout(tm);if(shown){shown=false;el.textContent='••••••••';}};
 el.addEventListener('pointerdown',e=>{if(el.dataset.open==='1')return;sx=e.clientX;sy=e.clientY;clearTimeout(tm);tm=setTimeout(()=>{shown=true;el.textContent=value;buzz(8);},260);});
 el.addEventListener('pointermove',e=>{if(!shown&&Math.hypot(e.clientX-sx,e.clientY-sy)>10)clearTimeout(tm);});
 ['pointerup','pointercancel','pointerleave'].forEach(n=>el.addEventListener(n,hide));
 el.addEventListener('contextmenu',e=>e.preventDefault());
}

/* ---------- wiring ---------- */
$('authForm').addEventListener('submit',authSubmit);
$('switchAuth').onclick=()=>{if(authMode==='register'){if(hasVault)showAuth('login');else $('importFile').click();}else $('importFile').click();};
$('installAuth').onclick=doInstall;
const syncClear=()=>$('clearSearch').classList.toggle('hidden',!$('searchInput').value);
$('searchInput').addEventListener('input',()=>{syncClear();render();});$('clearSearch').onclick=()=>{$('searchInput').value='';syncClear();render();$('searchInput').focus();};$('addBtn').onclick=()=>openEditor();
$('sortBtn').onclick=()=>{sortNewest=!sortNewest;$('sortBtn').textContent=sortNewest?'Recently updated ↓':'Oldest updated ↑';render();};
$('remBtn').onclick=()=>setView(view==='reminders'?'vault':'reminders');$('avatar').onclick=()=>setView('profile');
$('importFile').addEventListener('change',e=>{if(e.target.files?.[0])importBackup(e.target.files[0]);});
(async()=>{try{if(!window.indexedDB||!window.crypto?.subtle){$('authError').textContent='This browser does not support the required secure storage. Please use a current Safari or Chrome on HTTPS or localhost.';return;}db=await openDB();hasVault=!!(await dbGet());showAuth(hasVault?'login':'register');}catch(e){$('authError').textContent='Unable to initialize local storage in this browser.';}})();
})();
