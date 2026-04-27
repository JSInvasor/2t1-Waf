// 2t1-Waf · console — vanilla JS, no build step.

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const TOKEN_KEY = "2t1_token";
let token = localStorage.getItem(TOKEN_KEY) || "";

const RULES = [
  ["sqli",       "SQL injection"],
  ["xss",        "XSS"],
  ["traversal",  "Path traversal"],
  ["cmdi",       "Command injection"],
  ["lfi",        "Local / remote file inclusion"],
  ["bot_ua",     "Bot user-agents"],
  ["rate_limit", "Rate limiting"],
];

// ============== auth ==============
async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (token) headers["authorization"] = "Bearer " + token;
  if (opts.body && !headers["content-type"]) headers["content-type"] = "application/json";
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  if (r.status === 401) {
    localStorage.removeItem(TOKEN_KEY); token = "";
    showAuth();
    throw new Error("unauthorized");
  }
  return r;
}
async function checkToken(t) {
  const r = await fetch("/api/state", { headers: { authorization: "Bearer " + t } });
  return r.ok;
}
function showAuth() { $("#auth-modal").classList.remove("hidden"); setTimeout(() => $("#token-input").focus(), 50); }
function hideAuth() { $("#auth-modal").classList.add("hidden"); }

$("#token-submit").addEventListener("click", async () => {
  const v = $("#token-input").value.trim();
  if (!v) return;
  if (await checkToken(v)) {
    token = v;
    localStorage.setItem(TOKEN_KEY, v);
    $("#token-error").classList.add("hidden");
    hideAuth();
    boot();
  } else {
    $("#token-error").classList.remove("hidden");
  }
});
$("#token-input").addEventListener("keydown", e => { if (e.key === "Enter") $("#token-submit").click(); });

$("#logout").addEventListener("click", e => {
  e.preventDefault();
  localStorage.removeItem(TOKEN_KEY); token = "";
  showAuth();
});

// ============== routing ==============
const routes = ["overview", "firewall", "traffic", "settings"];
function navigate() {
  const hash = location.hash.replace("#/", "") || "overview";
  const route = routes.includes(hash) ? hash : "overview";
  $$(".nav-item[data-route]").forEach(a => a.classList.toggle("active", a.dataset.route === route));
  $$("section.page").forEach(s => s.classList.toggle("hidden", s.dataset.page !== route));
  $("#page-path").textContent = "~/waf/" + route;
}
window.addEventListener("hashchange", navigate);

// ============== helpers ==============
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function maskToken(t) {
  if (!t) return "";
  if (t.length <= 12) return t;
  return t.slice(0, 6) + "…" + t.slice(-4);
}

let toastTimer;
function toast(msg, kind = "ok") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.className = "toast hidden", 2200);
}

function renderRows(el, items, opts = {}) {
  if (!items || !items.length) {
    el.innerHTML = '<div class="row"><span class="v">no data</span></div>';
    return;
  }
  el.innerHTML = items.map(([k, v]) =>
    `<div class="row">
       <span class="name">${escapeHtml(k)}</span>
       <span class="v">${v}</span>
       ${opts.removable ? `<button class="x" data-action="${opts.removable}" data-remove="${escapeHtml(k)}">×</button>` : ''}
     </div>`
  ).join("");
}
function renderListRows(el, items, suffix = "", action = null) {
  if (!items || !items.length) {
    el.innerHTML = '<div class="row"><span class="v">empty</span></div>';
    return;
  }
  el.innerHTML = items.map(it => {
    const k = typeof it === "string" ? it : it.label;
    const v = typeof it === "string" ? "" : it.value;
    return `<div class="row">
      <span class="name">${escapeHtml(k)}</span>
      <span class="v">${escapeHtml(v + suffix)}</span>
      ${action ? `<button class="x" data-action="${action}" data-remove="${escapeHtml(k)}">×</button>` : ''}
    </div>`;
  }).join("");
}

// ============== chart ==============
function drawRing(buckets) {
  const c = $("#ring-chart");
  if (!c) return;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = c.clientWidth, h = c.clientHeight || 170;
  c.width = w * dpr; c.height = h * dpr;
  const ctx = c.getContext("2d"); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  // grid lines
  ctx.strokeStyle = "rgba(17,17,17,0.07)"; ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) {
    const y = (h / 4) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  const max = Math.max(1, ...buckets.flatMap(b => [b.allowed, b.challenged, b.blocked]));
  const bw = w / Math.max(buckets.length, 1);
  buckets.forEach((b, i) => {
    const x = i * bw;
    if ((b.allowed + b.challenged + b.blocked) === 0) return;
    const ya = h - (b.allowed / max) * h;
    const yc = ya - (b.challenged / max) * h;
    const yb = yc - (b.blocked / max) * h;
    ctx.fillStyle = "#1f6f3a"; ctx.fillRect(x, ya, Math.max(1, bw - 1), h - ya);
    ctx.fillStyle = "#b87900"; ctx.fillRect(x, yc, Math.max(1, bw - 1), ya - yc);
    ctx.fillStyle = "#b3203a"; ctx.fillRect(x, yb, Math.max(1, bw - 1), yc - yb);
  });
}

// ============== state apply ==============
function apply(data) {
  if (!data) return;
  const m = data.metrics || {};
  const rt = data.runtime || {};
  $("#kpi-allowed").textContent       = (m.allowed || 0).toLocaleString();
  $("#kpi-challenged").textContent    = (m.challenged || 0).toLocaleString();
  $("#kpi-blocked").textContent       = (m.blocked || 0).toLocaleString();
  $("#kpi-rate-limited").textContent  = (m.rate_limited || 0).toLocaleString();
  $("#kpi-in-flight").textContent     = (data.in_flight_total || 0).toLocaleString();
  $("#kpi-upstream-errors").textContent = (m.upstream_errors || 0).toLocaleString();
  if (data.version) $("#version").textContent = "v" + data.version;
  $("#inflight-state").textContent = (data.in_flight_total || 0).toLocaleString();
  $("#ua-state").textContent = rt.under_attack ? "ON" : "off";
  $("#ua-state").style.color = rt.under_attack ? "var(--bad)" : "";

  if (m.ring) drawRing(m.ring);

  renderRows($("#top-ips"),       (m.top_ips || []));
  renderRows($("#top-paths"),     (m.top_paths || []));
  renderRows($("#top-rules"),     (m.top_rules || []));
  renderRows($("#top-countries"), (m.top_countries || []));

  // firewall
  $("#under-attack").checked = !!rt.under_attack;
  $("#threshold-challenge").value = rt.challenge_threshold ?? "";
  $("#threshold-block").value     = rt.block_threshold ?? "";
  $("#ddos-conn").value           = rt.max_concurrent_per_ip ?? "";
  $("#ddos-rpm-bps").value        = rt.rpm_under_attack_bps ?? "";

  renderRuleToggles(rt.rules || {});
  renderListRows($("#allow-rows"), rt.allow || [], "", "unallow");
  renderListRows($("#deny-rows"),  rt.deny  || [], "", "undeny");
  renderListRows($("#country-rows"), rt.blocked_countries || [], "", "country");

  // settings
  $("#runtime-dump").textContent = JSON.stringify(rt, null, 2);
  $("#auth-token").value = maskToken(rt.auth_token || "");

  // sidebar live state
  $("#status-dot").classList.add("live"); $("#status-dot").classList.remove("bad");
  $("#conn-state").textContent = "live";
}

function renderRuleToggles(state) {
  const el = $("#rule-toggles");
  el.innerHTML = RULES.map(([k, label]) => `
    <label class="tog">
      <span>${label}</span>
      <input type="checkbox" data-rule="${k}" ${state[k] ? "checked" : ""}>
      <span class="switch"></span>
    </label>
  `).join("");
}

function renderEvents(events, append = false) {
  const tbody = $("#event-tbody");
  const fA = $("#filter-allow").checked;
  const fC = $("#filter-challenge").checked;
  const fB = $("#filter-block").checked;
  const ft = $("#filter-text").value.toLowerCase();

  const accept = e => {
    if (e.action === "allow"     && !fA) return false;
    if (e.action === "challenge" && !fC) return false;
    if (e.action === "block"     && !fB) return false;
    if (ft) {
      const hay = (e.ip + " " + e.path + " " + (e.user_agent||"") + " " + (e.rule_id||"")).toLowerCase();
      if (!hay.includes(ft)) return false;
    }
    return true;
  };

  const render = e => `<tr>
    <td>${new Date(e.ts_ms).toLocaleTimeString()}</td>
    <td>${escapeHtml(e.ip)}</td>
    <td>${escapeHtml(e.country || "—")}</td>
    <td>${escapeHtml(e.method)}</td>
    <td>${escapeHtml(e.host)}</td>
    <td title="${escapeHtml(e.path)}">${escapeHtml((e.path||"").slice(0,60))}</td>
    <td><span class="badge ${e.action}">${e.action}</span></td>
    <td>${e.status}</td>
    <td>${e.score}</td>
    <td>${escapeHtml(e.rule_id || "")}</td>
  </tr>`;

  if (append) {
    const html = events.filter(accept).map(render).join("");
    if (html) tbody.insertAdjacentHTML("afterbegin", html);
    while (tbody.children.length > 500) tbody.removeChild(tbody.lastElementChild);
  } else {
    tbody.innerHTML = events.filter(accept).map(render).join("") || `<tr><td colspan="10" class="mut">no events yet</td></tr>`;
  }
}

// ============== streaming ==============
let es;
function connectStream() {
  if (es) es.close();
  es = new EventSource("/api/stream?token=" + encodeURIComponent(token));
  es.onmessage = m => {
    try {
      const data = JSON.parse(m.data);
      apply(data);
      if (data.events && data.events.length) {
        renderEvents(data.events.slice().reverse(), true);
      }
    } catch (_) {}
  };
  es.onerror = () => {
    $("#status-dot").classList.remove("live"); $("#status-dot").classList.add("bad");
    $("#conn-state").textContent = "reconnecting…";
  };
}

async function reloadEvents() {
  try {
    const r = await api("/api/events?limit=200");
    if (r.ok) renderEvents(await r.json(), false);
  } catch (_) {}
}

// ============== actions ==============
async function patchRuntime(patch) {
  const r = await api("/api/runtime", { method: "POST", body: JSON.stringify(patch) });
  if (!r.ok) { toast("Failed to update", "bad"); return false; }
  toast("Saved");
  refreshState();
  return true;
}

async function refreshState() {
  try {
    const [stateR, bannedR] = await Promise.all([api("/api/state"), api("/api/banned")]);
    if (!stateR.ok || !bannedR.ok) return;
    apply(await stateR.json());
    const banned = await bannedR.json();
    renderListRows($("#banned-rows"),
      banned.map(b => ({ label: b.ip, value: b.expires_in + "s" })), "", "unban");
  } catch (_) {}
}

document.addEventListener("change", async e => {
  if (e.target.matches("[data-rule]")) {
    await patchRuntime({ rules: { [e.target.dataset.rule]: e.target.checked } });
  }
  if (e.target.id === "under-attack") {
    await fetch("/api/under_attack?on=" + e.target.checked, {
      method: "POST", headers: { authorization: "Bearer " + token },
    });
    toast(e.target.checked ? "Under-attack mode ON" : "Under-attack mode OFF",
          e.target.checked ? "bad" : "ok");
    refreshState();
  }
});

document.addEventListener("click", async e => {
  if (e.target.matches('[data-save="thresholds"]')) {
    await patchRuntime({
      challenge_threshold: parseInt($("#threshold-challenge").value, 10),
      block_threshold:     parseInt($("#threshold-block").value, 10),
    });
  }
  if (e.target.matches('[data-save="ddos"]')) {
    await patchRuntime({
      max_concurrent_per_ip: parseInt($("#ddos-conn").value, 10),
      rpm_under_attack_bps:  parseInt($("#ddos-rpm-bps").value, 10),
    });
  }
  if (e.target.id === "allow-add") {
    const v = $("#allow-cidr").value.trim(); if (!v) return;
    const r = await api("/api/ip/allow?cidr=" + encodeURIComponent(v), { method: "POST" });
    if (r.ok) { $("#allow-cidr").value = ""; refreshState(); toast("Added"); }
    else toast("Invalid CIDR", "bad");
  }
  if (e.target.id === "deny-add") {
    const v = $("#deny-cidr").value.trim(); if (!v) return;
    const r = await api("/api/ip/deny?cidr=" + encodeURIComponent(v), { method: "POST" });
    if (r.ok) { $("#deny-cidr").value = ""; refreshState(); toast("Added"); }
    else toast("Invalid CIDR", "bad");
  }
  if (e.target.id === "country-save") {
    const list = $("#country-input").value.split(",").map(s => s.trim().toUpperCase()).filter(Boolean);
    await patchRuntime({ blocked_countries: list });
    $("#country-input").value = "";
  }
  if (e.target.id === "copy-token") {
    try {
      const r = await api("/api/state");
      const st = await r.json();
      const tok = (st.runtime || {}).auth_token || "";
      await navigator.clipboard.writeText(tok);
      toast("Token copied to clipboard");
    } catch (_) { toast("Copy failed", "bad"); }
  }
  if (e.target.matches(".x")) {
    const cidr = e.target.dataset.remove;
    const action = e.target.dataset.action;
    if (action === "unallow" || action === "undeny") {
      const r = await api(`/api/ip/${action}?cidr=` + encodeURIComponent(cidr), { method: "POST" });
      if (r.ok) { refreshState(); toast("Removed"); }
    } else if (action === "country") {
      const cur = (((await (await api("/api/state")).json()).runtime || {}).blocked_countries || []);
      await patchRuntime({ blocked_countries: cur.filter(c => c !== cidr) });
    } else if (action === "unban") {
      const r = await api("/api/unban?ip=" + encodeURIComponent(cidr), { method: "POST" });
      if (r.ok) { refreshState(); toast("Unbanned"); }
    }
  }
});

["filter-allow","filter-challenge","filter-block"].forEach(id =>
  $("#"+id).addEventListener("change", reloadEvents));
$("#filter-text").addEventListener("input", reloadEvents);

// ============== particles + halo ==============
(function ambient() {
  const canvas = document.getElementById("particles");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  let W, H, dpr, drift = [], swarm = [];
  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = canvas.clientWidth = window.innerWidth;
    H = canvas.clientHeight = window.innerHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  function seed() {
    drift = [];
    for (let i = 0; i < 60; i++) drift.push({
      x: Math.random()*W, y: Math.random()*H,
      vx: (Math.random()-0.5)*0.04, vy: (Math.random()-0.5)*0.04,
      r: Math.random()*0.9 + 0.3,
      a: Math.random()*0.3 + 0.08,
      ph: Math.random()*Math.PI*2
    });
    swarm = [];
    for (let i = 0; i < 80; i++) swarm.push({
      angle: Math.random()*Math.PI*2,
      baseRadius: Math.random()*200 + 40,
      radius: 0,
      speed: (Math.random()-0.5)*0.03 + (Math.random()>0.5?0.01:-0.01),
      size: Math.random()*1.4 + 0.5,
      wob: Math.random()*Math.PI*2
    });
  }
  window.addEventListener("resize", () => { resize(); seed(); });
  resize(); seed();

  let mx = W/2, my = H/2, hasMouse = false, swarmCx = W/2, swarmCy = H/2, t = 0;
  window.addEventListener("mousemove", e => { mx = e.clientX; my = e.clientY; hasMouse = true; });
  window.addEventListener("mouseleave", () => hasMouse = false);

  function tick() {
    t += 0.016; ctx.clearRect(0, 0, W, H);
    swarmCx += ((hasMouse ? mx : W/2) - swarmCx) * 0.05;
    swarmCy += ((hasMouse ? my : H/2) - swarmCy) * 0.05;
    for (const p of swarm) {
      p.angle += p.speed;
      p.radius = p.baseRadius + Math.sin(t*2 + p.wob) * 10;
      const px = swarmCx + Math.cos(p.angle) * p.radius;
      const py = swarmCy + Math.sin(p.angle) * p.radius;
      ctx.beginPath();
      ctx.fillStyle = `rgba(17,17,17,${hasMouse ? 0.4 : 0.13})`;
      ctx.arc(px, py, p.size, 0, Math.PI*2); ctx.fill();
    }
    for (const p of drift) {
      p.x += p.vx + Math.sin(t*0.4 + p.ph)*0.03;
      p.y += p.vy + Math.cos(t*0.4 + p.ph)*0.03;
      if (p.x < -10) p.x = W+10; if (p.x > W+10) p.x = -10;
      if (p.y < -10) p.y = H+10; if (p.y > H+10) p.y = -10;
      ctx.beginPath();
      ctx.fillStyle = `rgba(17,17,17,${p.a*(0.6 + 0.4*Math.sin(t + p.ph))})`;
      ctx.arc(p.x, p.y, p.r, 0, Math.PI*2); ctx.fill();
    }
    requestAnimationFrame(tick);
  }
  tick();
})();

(function halo() {
  const halo = document.getElementById("halo");
  if (!halo) return;
  let tx = window.innerWidth/2, ty = window.innerHeight/2, x = tx, y = ty;
  window.addEventListener("mousemove", e => { tx = e.clientX; ty = e.clientY; });
  function loop() {
    x += (tx - x) * 0.07; y += (ty - y) * 0.07;
    halo.style.transform = `translate(${x}px,${y}px) translate(-50%,-50%)`;
    requestAnimationFrame(loop);
  }
  loop();
})();

// ============== boot ==============
async function boot() {
  navigate();
  if (!token) { showAuth(); return; }
  if (!(await checkToken(token))) { localStorage.removeItem(TOKEN_KEY); showAuth(); return; }
  await refreshState();
  await reloadEvents();
  connectStream();
}
boot();
