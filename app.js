import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const C = window.ABYRON_CONFIG || {};
const sb = C.SUPABASE_URL ? createClient(C.SUPABASE_URL, C.SUPABASE_ANON_KEY) : null;
const $ = id => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

const DEVICE_KEY = "ab.device_id";
const IDENTITY_KEY = "ab.identity";
const PROFILE_KEY = "ab.profile";
const PEER_KEY = "ab.peer_profile";
const OUTBOX_KEY = "ab.outbox";
const SCHEDULED_KEY = "ab.scheduled";

const uid = localStorage.getItem(DEVICE_KEY) || crypto.randomUUID();
localStorage.setItem(DEVICE_KEY, uid);

let privateKey = null;
let publicKey = null;
let peerProfile = null;
let sessionKey = null;
let realtimeChannel = null;
let renderedIds = new Set();

const b64 = x => btoa(String.fromCharCode(...new Uint8Array(x)));
const ub64 = x => Uint8Array.from(atob(x), c => c.charCodeAt(0));
const safeJson = (value, fallback = null) => { try { return JSON.parse(value); } catch { return fallback; } };
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[c]));

function setStatus(text, error = false) {
  const el = $("status");
  el.textContent = text;
  el.style.color = error ? "#ff929e" : "";
}
function usernameValid(name) { return /^[a-z0-9_]{3,24}$/.test(name); }
function currentProfile() { return safeJson(localStorage.getItem(PROFILE_KEY)); }
function conversationId(a, b) { return [a, b].sort().join(":"); }

async function cryptoInit() {
  const saved = safeJson(localStorage.getItem(IDENTITY_KEY));
  if (saved?.publicKey && saved?.privateKey) {
    publicKey = saved.publicKey;
    privateKey = await crypto.subtle.importKey("jwk", saved.privateKey, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
  } else {
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
    publicKey = await crypto.subtle.exportKey("jwk", kp.publicKey);
    privateKey = kp.privateKey;
    const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    localStorage.setItem(IDENTITY_KEY, JSON.stringify({ publicKey, privateKey: priv }));
  }
  $("publicKey").value = JSON.stringify(publicKey);
}

async function derive(peerPublic) {
  if (!peerPublic) throw new Error("Recipient public identity is missing.");
  const pk = await crypto.subtle.importKey("jwk", peerPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  return crypto.subtle.deriveKey({ name: "ECDH", public: pk }, privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encrypt(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  return { iv: b64(iv), ct: b64(ct) };
}
async function decrypt(payload, key) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(payload.iv) }, key, ub64(payload.ct)));
}

function renderIdentity() {
  const p = currentProfile();
  $("myUsername").textContent = p?.username ? `@${p.username}` : "Not registered";
  $("myDevice").textContent = `device ${uid.slice(0, 8)}`;
  $("profileStatus").textContent = p?.username ? "Profile synced" : "Create your ABYRON ID";
  $("profileStatus").className = p?.username ? "profile-status ok" : "profile-status";
}
function setProfile(profile) {
  localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  renderIdentity();
}

async function registerProfile(username) {
  if (!sb) throw new Error("Supabase is not configured.");
  username = username.trim().toLowerCase().replace(/^@/, "");
  if (!usernameValid(username)) throw new Error("Username must be 3–24 characters: a-z, 0-9 or _");

  const { data: existing, error: findError } = await sb.from("profiles").select("device_id,username,public_key").ilike("username", username).maybeSingle();
  if (findError) throw findError;
  if (existing && existing.device_id !== uid) throw new Error("That ABYRON ID is already used on another device. Choose a different username for this test device.");

  const row = { device_id: uid, username, public_key: publicKey };
  const { data, error } = await sb.from("profiles").upsert(row, { onConflict: "device_id" }).select("device_id,username,public_key").single();
  if (error) throw error;
  setProfile(data || row);
  $("profileDialog").close();
  await refreshProfileDirectory();
  setStatus(`Connected as @${username}`);
}

async function ensureProfile() {
  if (!sb) {
    if (!currentProfile()) $("profileDialog").showModal();
    return;
  }
  const local = currentProfile();
  if (local?.username) {
    const { data, error } = await sb.from("profiles").select("device_id,username,public_key").eq("device_id", uid).maybeSingle();
    if (error) throw error;
    if (!data) await registerProfile(local.username);
    else setProfile(data);
  } else {
    $("profileDialog").showModal();
  }
}

async function refreshProfileDirectory() {
  if (!sb) return;
  const { data, error } = await sb.from("profiles").select("username,device_id,created_at").neq("device_id", uid).order("created_at", { ascending: false }).limit(50);
  if (error) { console.warn(error); return; }
  $("contactsList").innerHTML = (data || []).map(x => `<div class="contact-row"><span>@${esc(x.username)}</span><small>device ${esc(x.device_id.slice(0, 8))}</small></div>`).join("") || `<div class="muted">No other profiles registered yet.</div>`;
}

async function findProfileByDevice(deviceId) {
  if (!sb) return null;
  const { data } = await sb.from("profiles").select("device_id,username,public_key").eq("device_id", deviceId).maybeSingle();
  return data || null;
}

async function searchUser() {
  if (!sb) return alert("Supabase is not connected.");
  if (!currentProfile()) return alert("Create your ABYRON ID first.");
  const raw = $("usernameSearch").value.trim().toLowerCase().replace(/^@/, "");
  if (!usernameValid(raw)) return alert("Enter a valid username, e.g. @ankush");
  if (raw === currentProfile().username) return alert("That's your own ABYRON ID.");

  setStatus(`Finding @${raw}…`);
  const { data, error } = await sb.from("profiles").select("device_id,username,public_key").ilike("username", raw).maybeSingle();
  if (error) { setStatus(`Search failed: ${error.message}`, true); return alert(error.message); }
  if (!data) { setStatus("User not found", true); return alert("No ABYRON user found with that username."); }

  try {
    peerProfile = data;
    localStorage.setItem(PEER_KEY, JSON.stringify(data));
    sessionKey = await derive(data.public_key);
    $("peerName").textContent = `@${data.username}`;
    $("peerDevice").textContent = `device ${data.device_id.slice(0, 8)}`;
    $("peerCard").classList.remove("hidden");
    $("chatWith").textContent = `Chat with @${data.username}`;
    $("chatHint").textContent = "End-to-end encrypted session ready";
    setStatus(`Secure session ready with @${data.username}`);
    await loadConversation();
  } catch (e) {
    setStatus(`Session failed: ${e.message}`, true);
    alert(`Could not create encrypted session: ${e.message}`);
  }
}

async function loadConversation() {
  $("messages").innerHTML = "";
  renderedIds = new Set();
  if (!sb || !peerProfile || !currentProfile()) return;
  const cid = conversationId(uid, peerProfile.device_id);
  const { data, error } = await sb.from("messages").select("id,sender_device,recipient_device,ciphertext,sender_public_key,created_at").eq("conversation_id", cid).order("created_at", { ascending: true }).limit(200);
  if (error) { setStatus(`Chat load failed: ${error.message}`, true); return; }
  for (const m of data || []) await renderStoredMessage(m);
}

async function renderStoredMessage(m) {
  if (renderedIds.has(m.id)) return;
  try {
    const key = m.sender_device === uid ? await derive(peerProfile.public_key) : await derive(m.sender_public_key);
    const text = await decrypt(m.ciphertext, key);
    addMsg(m.id, m.sender_device === uid ? "You" : `@${peerProfile.username}`, text);
  } catch (e) {
    addMsg(m.id, "Encrypted", "Unable to decrypt this message on this device.");
  }
}

function addMsg(id, who, text) {
  if (id && renderedIds.has(id)) return;
  if (id) renderedIds.add(id);
  const d = document.createElement("div");
  d.className = "msg " + (who === "You" ? "me" : "");
  if (id) d.dataset.messageId = id;
  d.innerHTML = `<small>${esc(who)}</small>${esc(text)}`;
  $("messages").appendChild(d);
  $("messages").scrollTop = $("messages").scrollHeight;
}

async function insertMessage(row) {
  const { error } = await sb.from("messages").insert(row);
  if (error) throw error;
}

async function sendNow(text) {
  if (!sb) return alert("Supabase is not connected.");
  if (!peerProfile || !sessionKey) return alert("Find a user first.");
  const payload = await encrypt(text, sessionKey);
  const row = { id: crypto.randomUUID(), conversation_id: conversationId(uid, peerProfile.device_id), sender_device: uid, recipient_device: peerProfile.device_id, sender_public_key: publicKey, ciphertext: payload };

  try {
    await insertMessage(row);
    addMsg(row.id, "You", text);
    $("message").value = "";
    setStatus(`Sent securely to @${peerProfile.username}`);
  } catch (e) {
    const q = safeJson(localStorage.getItem(OUTBOX_KEY), []) || [];
    q.push({ ...row, time: Date.now() });
    localStorage.setItem(OUTBOX_KEY, JSON.stringify(q));
    setStatus(`Send failed; saved offline: ${e.message}`, true);
    alert(`Message could not reach Supabase yet.\n\n${e.message}`);
  }
}

async function flushOutbox() {
  if (!sb) return;
  let q = safeJson(localStorage.getItem(OUTBOX_KEY), []) || [];
  if (!q.length) return;
  const remaining = [];
  for (const row of q) {
    const { error } = await sb.from("messages").upsert(row, { onConflict: "id" });
    if (error) remaining.push(row);
  }
  localStorage.setItem(OUTBOX_KEY, JSON.stringify(remaining));
  if (remaining.length === 0 && q.length) setStatus("Queued messages delivered");
}

async function realtime() {
  if (!sb) { setStatus("Local/offline mode", true); return; }
  if (realtimeChannel) await sb.removeChannel(realtimeChannel);
  const channelName = `ab-chat-${uid}-${crypto.randomUUID()}`;
  realtimeChannel = sb.channel(channelName);
  realtimeChannel.on("postgres_changes", { event: "INSERT", schema: "public", table: "messages", filter: `recipient_device=eq.${uid}` }, async e => {
    const m = e.new;
    if (m.recipient_device !== uid) return;
    let sender = await findProfileByDevice(m.sender_device);
    if (!sender) return;

    if (!peerProfile || peerProfile.device_id !== sender.device_id) {
      peerProfile = sender;
      localStorage.setItem(PEER_KEY, JSON.stringify(sender));
      try { sessionKey = await derive(sender.public_key); } catch { return; }
      $("peerName").textContent = `@${sender.username}`;
      $("peerDevice").textContent = `device ${sender.device_id.slice(0, 8)}`;
      $("peerCard").classList.remove("hidden");
      $("chatWith").textContent = `Chat with @${sender.username}`;
      $("chatHint").textContent = "End-to-end encrypted session ready";
    }
    await renderStoredMessage(m);
  });
  realtimeChannel.subscribe(s => {
    if (s === "SUBSCRIBED") setStatus("Realtime connected");
    else if (["CHANNEL_ERROR", "TIMED_OUT", "CLOSED"].includes(s)) setStatus(`Realtime ${s}`, true);
  });
  setInterval(flushOutbox, 5000);
}

function nav() {
  document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
    document.querySelectorAll("nav button").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    document.querySelectorAll(".page").forEach(x => x.classList.remove("active"));
    $(b.dataset.page).classList.add("active");
    $("title").textContent = b.textContent.trim();
    if (b.dataset.page === "settings") refreshProfileDirectory();
  });
}

function renderScheduled() {
  const a = (safeJson(localStorage.getItem(SCHEDULED_KEY), []) || []).sort((x, y) => x.at - y.at);
  $("scheduledList").innerHTML = a.map(x => `<div class="item">⏱ ${new Date(x.at).toLocaleString()} · encrypted</div>`).join("") || `<div class="muted">No scheduled messages.</div>`;
}
function releaseScheduled() {
  const now = Date.now();
  const a = safeJson(localStorage.getItem(SCHEDULED_KEY), []) || [];
  const keep = [];
  for (const x of a) {
    if (x.at <= now) {
      const q = safeJson(localStorage.getItem(OUTBOX_KEY), []) || [];
      q.push(x.outbox);
      localStorage.setItem(OUTBOX_KEY, JSON.stringify(q));
    } else keep.push(x);
  }
  localStorage.setItem(SCHEDULED_KEY, JSON.stringify(keep));
  renderScheduled();
  flushOutbox();
}

$("profileForm").onsubmit = async e => { e.preventDefault(); $("profileError").textContent = ""; try { await registerProfile($("username").value); } catch (err) { $("profileError").textContent = err.message || "Could not create profile."; } };
$("searchForm").onsubmit = async e => { e.preventDefault(); await searchUser(); };
$("copyUsername").onclick = async () => { const p = currentProfile(); if (p) await navigator.clipboard.writeText(`@${p.username}`); };
$("copy").onclick = () => navigator.clipboard.writeText($("publicKey").value);
$("send").onsubmit = async e => { e.preventDefault(); const t = $("message").value.trim(); if (t) await sendNow(t); };
$("schedule").onclick = () => { if (!$("message").value.trim()) return alert("Write a message first."); if (!peerProfile || !sessionKey) return alert("Find a user first."); $("scheduleDialog").showModal(); };
$("scheduleForm").onsubmit = async e => {
  e.preventDefault();
  const text = $("message").value.trim();
  const at = new Date($("scheduleAt").value).getTime();
  if (!at || at <= Date.now()) return alert("Choose a future time.");
  const payload = await encrypt(text, sessionKey);
  const a = safeJson(localStorage.getItem(SCHEDULED_KEY), []) || [];
  a.push({ id: crypto.randomUUID(), at, outbox: { id: crypto.randomUUID(), conversation_id: conversationId(uid, peerProfile.device_id), sender: uid, sender_device: uid, recipient: peerProfile.device_id, recipient_device: peerProfile.device_id, sender_public_key: publicKey, ciphertext: payload } });
  localStorage.setItem(SCHEDULED_KEY, JSON.stringify(a));
  $("scheduleDialog").close(); $("message").value = ""; renderScheduled();
};

$("newGroup").onsubmit = async e => { e.preventDefault(); const n = $("groupName").value.trim(); if (!n || !sb) return; const { error } = await sb.from("groups").insert({ name: n, owner_device: uid }); if (error) alert(error.message); $("groupName").value = ""; loadGroups(); };
async function loadGroups() { if (!sb) return; const { data } = await sb.from("groups").select("name,created_at").order("created_at", { ascending: false }); $("groupsList").innerHTML = (data || []).map(x => `<div class="item">👥 ${esc(x.name)}</div>`).join("") || `<div class="muted">No groups yet.</div>`; }
$("discover").onclick = () => { $("nearbyLog").textContent = "Web discovery is limited. Android will provide Bluetooth LE / Wi-Fi nearby transport. Messages stay encrypted before transport."; };
$("wipe").onclick = () => { if (confirm("Delete this device identity, profile cache, queued messages and schedules?")) { localStorage.clear(); location.reload(); } };
$("logoutDevice").onclick = () => { localStorage.removeItem(PROFILE_KEY); localStorage.removeItem(PEER_KEY); peerProfile = null; sessionKey = null; $("profileDialog").showModal(); renderIdentity(); };
$("lock").onclick = () => alert("Browser Lock is a UI lock placeholder. Native Android can later use OS biometric/app-lock APIs.");

(async () => {
  try {
    await cryptoInit(); nav(); renderIdentity(); renderScheduled(); await ensureProfile(); await loadGroups(); await realtime(); await refreshProfileDirectory();
    const savedPeer = safeJson(localStorage.getItem(PEER_KEY));
    if (savedPeer) {
      peerProfile = savedPeer;
      try {
        sessionKey = await derive(savedPeer.public_key);
        $("peerName").textContent = `@${savedPeer.username}`;
        $("peerDevice").textContent = `device ${savedPeer.device_id.slice(0, 8)}`;
        $("peerCard").classList.remove("hidden");
        $("chatWith").textContent = `Chat with @${savedPeer.username}`;
        $("chatHint").textContent = "End-to-end encrypted session ready";
        await loadConversation();
      } catch (e) { console.warn(e); }
    }
    setInterval(releaseScheduled, 1000);
  } catch (e) {
    console.error(e);
    setStatus(`Startup error: ${e.message}`, true);
  }
})();
