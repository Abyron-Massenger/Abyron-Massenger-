import {createClient} from "https://esm.sh/@supabase/supabase-js@2";
const C=window.ABYRON_CONFIG||{}, sb=C.SUPABASE_URL?createClient(C.SUPABASE_URL,C.SUPABASE_ANON_KEY):null;
const $=id=>document.getElementById(id), enc=new TextEncoder(), dec=new TextDecoder();
const uid=localStorage.getItem("ab.uid")||crypto.randomUUID();localStorage.setItem("ab.uid",uid);
let privateKey,publicKey,peerKey,sessionKey;

const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x)));
const ub64=x=>Uint8Array.from(atob(x),c=>c.charCodeAt(0));
async function cryptoInit(){
 const saved=localStorage.getItem("ab.identity");
 if(saved){const j=JSON.parse(saved);publicKey=j.publicKey;privateKey=await crypto.subtle.importKey("jwk",j.privateKey,{name:"ECDH",namedCurve:"P-256"},false,["deriveKey"])}
 else{const kp=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]);publicKey=await crypto.subtle.exportKey("jwk",kp.publicKey);privateKey=kp.privateKey;const priv=await crypto.subtle.exportKey("jwk",kp.privateKey);localStorage.setItem("ab.identity",JSON.stringify({publicKey,privateKey:priv}))}
 $("publicKey").value=JSON.stringify(publicKey);
}
async function derive(p){const pk=await crypto.subtle.importKey("jwk",p,{name:"ECDH",namedCurve:"P-256"},false,[]);return crypto.subtle.deriveKey({name:"ECDH",public:pk},privateKey,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
async function encrypt(t,k){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,enc.encode(t));return{iv:b64(iv),ct:b64(ct)}}
async function decrypt(o,k){return dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:ub64(o.iv)},k,ub64(o.ct)))}
function esc(s){return s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}
function nav(){document.querySelectorAll("nav button").forEach(b=>b.onclick=()=>{document.querySelectorAll("nav button").forEach(x=>x.classList.remove("active"));b.classList.add("active");document.querySelectorAll(".page").forEach(x=>x.classList.remove("active"));$(b.dataset.page).classList.add("active");$("title").textContent=b.textContent.trim()})}
function addMsg(who,text){const d=document.createElement("div");d.className="msg "+(who==="You"?"me":"");d.innerHTML=`<small>${who}</small>${esc(text)}`;$("messages").appendChild(d)}
$("prepare").onclick=async()=>{try{peerKey=JSON.parse($("peer").value);sessionKey=await derive(peerKey);localStorage.setItem("ab.peer",JSON.stringify(peerKey));$("status").textContent="Secure session ready"}catch{alert("Invalid public key")}};
$("send").onsubmit=async e=>{e.preventDefault();const t=$("message").value.trim();if(!t)return;if(!sessionKey)return alert("Prepare a secure session first.");const p=await encrypt(t,sessionKey);const local={id:crypto.randomUUID(),sender:uid,time:Date.now(),payload:p};const q=JSON.parse(localStorage.getItem("ab.outbox")||"[]");q.push(local);localStorage.setItem("ab.outbox",JSON.stringify(q));addMsg("You",t);$("message").value="";await flushOutbox()};
async function flushOutbox(){if(!sb||!peerKey)return;const q=JSON.parse(localStorage.getItem("ab.outbox")||"[]");if(!q.length)return;const conversation=[uid,JSON.stringify(peerKey)].sort().join(":");const rows=q.map(x=>({id:x.id,conversation_id:conversation,sender_device:uid,recipient_device:JSON.stringify(peerKey),ciphertext:x.payload}));const {error}=await sb.from("messages").upsert(rows,{onConflict:"id"});if(!error)localStorage.setItem("ab.outbox","[]")}
async function realtime(){if(!sb){$("status").textContent="Local/offline mode";return}sb.channel("ab-chat").on("postgres_changes",{event:"INSERT",schema:"public",table:"messages"},async e=>{const m=e.new;if(m.recipient_device!==JSON.stringify(publicKey))return;try{const p=JSON.parse(localStorage.getItem("ab.peer"));const k=await derive(p);addMsg("Peer",await decrypt(m.ciphertext,k))}catch{}}).subscribe(s=>$("status").textContent=s==="SUBSCRIBED"?"Realtime connected":"Realtime "+s);setInterval(flushOutbox,5000)}
$("schedule").onclick=()=>{if(!$("message").value.trim())return alert("Write a message first.");$("scheduleDialog").showModal()};
$("scheduleForm").onsubmit=async e=>{e.preventDefault();if(!sessionKey)return alert("Prepare a secure session first.");const at=new Date($("scheduleAt").value).getTime();if(!at||at<=Date.now())return alert("Choose a future time.");const p=await encrypt($("message").value.trim(),sessionKey);const a=JSON.parse(localStorage.getItem("ab.scheduled")||"[]");a.push({id:crypto.randomUUID(),at,payload:p});localStorage.setItem("ab.scheduled",JSON.stringify(a));$("scheduleDialog").close();$("message").value="";renderScheduled()};
function renderScheduled(){const a=JSON.parse(localStorage.getItem("ab.scheduled")||"[]").sort((x,y)=>x.at-y.at);$("scheduledList").innerHTML=a.map(x=>`<div class="item">⏱ ${new Date(x.at).toLocaleString()} · encrypted</div>`).join("")}
function releaseScheduled(){const now=Date.now(),a=JSON.parse(localStorage.getItem("ab.scheduled")||"[]"),keep=[];for(const x of a){if(x.at<=now){const q=JSON.parse(localStorage.getItem("ab.outbox")||"[]");q.push({id:x.id,sender:uid,time:Date.now(),payload:x.payload});localStorage.setItem("ab.outbox",JSON.stringify(q))}else keep.push(x)}localStorage.setItem("ab.scheduled",JSON.stringify(keep));renderScheduled();flushOutbox()}
$("newGroup").onsubmit=async e=>{e.preventDefault();const n=$("groupName").value.trim();if(!n||!sb)return;await sb.from("groups").insert({name:n,owner_device:uid});$("groupName").value="";loadGroups()};
async function loadGroups(){if(!sb)return;const {data}=await sb.from("groups").select("name,created_at").order("created_at",{ascending:false});$("groupsList").innerHTML=(data||[]).map(x=>`<div class="item">👥 ${esc(x.name)}</div>`).join("")}
$("discover").onclick=()=>{$("nearbyLog").textContent="Discovery interface ready.\n\nWeb: capability-limited.\nAndroid: Bluetooth LE / Wi-Fi / Nearby Connections transport module required.\n\nApplication messages remain encrypted; relays forward ciphertext only."};
$("copy").onclick=()=>navigator.clipboard.writeText($("publicKey").value);
$("wipe").onclick=()=>{if(confirm("Delete local identity, queued messages and schedules?")){localStorage.clear();location.reload()}};
$("lock").onclick=()=>alert("Native Android build can use OS biometric/app-lock APIs. A browser cannot enforce a true OS-level lock.");
(async()=>{await cryptoInit();nav();renderScheduled();loadGroups();await realtime();setInterval(releaseScheduled,1000)})();