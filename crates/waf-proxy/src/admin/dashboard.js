// 2t1-Waf dashboard. No build step, no framework — vanilla JS, single file.

const $  = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));

const TOKEN_KEY = "2t1_token";
let token = localStorage.getItem(TOKEN_KEY) || "";
let lastEventTs = 0;

const RULE_KEYS = ["sqli","xss","traversal","cmdi","lfi","bot_ua","rate_limit"];
const RULE_LABELS = {
  sqli: "SQL injection",
  xss: "XSS",
  traversal: "Path traversal",
  cmdi: "Command injection",
  lfi: "Local/Remote file inclusion",
  bot_ua: "Bot user-agents",
  rate_limit: "Rate limiting",
};

// ============== auth ==============

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (token) headers["authorization"] = "Bearer " + token;
  if (opts.body && !headers["content-type"]) headers["content-type"] = "application/json";
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  if (r.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    token = "";
    showAuth();
    throw new Error("unauthorized");
  }
  return r;
}

async function checkToken(t) {
  const r = await fetch("/api/state", { headers: { authorization: "Bearer " + t } });
  return r.ok;
}

function showAuth() {
  $("#auth-modal").classList.remove("hidden");
  setTimeout(() => $("#token-input").focus(), 50);
}
function hideAuth() {
  $("#auth-modal").classList.add("hidden");
}

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
$("#token-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#token-submit").click();
});

// ============== routing ==============

const routes = ["overview", "firewall", "traffic", "settings"];

function navigate() {
  const hash = location.hash.replace("#/", "") || "overview";
  const route = routes.includes(hash) ? hash : "overview";
  $$(".sidebar nav a").forEach(a => a.classList.toggle("active", a.dataset.route === route));
  $$("section.page").forEach(s => s.classList.toggle("hidden", s.dataset.page !== route));
  $("#page-title").textContent = route[0].toUpperCase() + route.slice(1);
}
window.addEventListener("hashchange", navigate);

// ============== rendering helpers ==============

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
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
       ${opts.removable ? `<button class="x" data-remove="${escapeHtml(k)}">remove</button>` : ""}
     </div>`
  ).join("");
}

function renderSimpleRows(el, items, suffix = "", removable = null) {
  if (!items || !items.length) {
    el.innerHTML = '<div class="row"><span class="v">no data</span></div>';
    return;
  }
  el.innerHTML = items.map(it => {
    const k = typeof it === "string" ? it : it.label;
    const v = typeof it === "string" ? "" : it.value;
    return `<div class="row">
      <span class="name">${escapeHtml(k)}</span>
      <span class="v">${escapeHtml(v + suffix)}</span>
      ${removable ? `<button class="x" data-remove="${escapeHtml(k)}" data-action="${removable}">remove</button>` : ""}
    </div>`;
  }).join("");
}

let toastTimer;
function toast(msg, kind = "ok") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = "toast hidden"; }, 2400);
}

// ============== chart ==============

function drawRing(buckets) {
  const c = $("#ring-chart");
  if (!c) return;
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = c.clientHeight || 160;
  c.width = w * dpr; c.height = h * dpr;
  const ctx = c.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const max = Math.max(1, ...buckets.flatMap(b => [b.allowed, b.challenged, b.blocked]));
  const bw = w / Math.max(buckets.length, 1);
  buckets.forEach((b, i) => {
    const x = i * bw;
    const all = b.allowed + b.challenged + b.blocked;
    if (!all) return;
    const ya = h - (b.allowed / max) * h;
    const yc = ya - (b.challenged / max) * h;
    const yb = yc - (b.blocked / max) * h;
    ctx.fillStyle = "#3ddc97"; ctx.fillRect(x, ya, Math.max(1, bw - 1), h - ya);
    ctx.fillStyle = "#f7b500"; ctx.fillRect(x, yc, Math.max(1, bw - 1), ya - yc);
    ctx.fillStyle = "#ff5470"; ctx.fillRect(x, yb, Math.max(1, bw - 1), yc - yb);
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

  if (m.ring) drawRing(m.ring);

  renderRows($("#top-ips"),       (m.top_ips || []));
  renderRows($("#top-paths"),     (m.top_paths || []));
  renderRows($("#top-rules"),     (m.top_rules || []));
  renderRows($("#top-countries"), (m.top_countries || []));

  // firewall page
  $("#under-attack").checked = !!rt.under_attack;
  $("#threshold-challenge").value = rt.challenge_threshold ?? "";
  $("#threshold-block").value     = rt.block_threshold ?? "";
  $("#ddos-conn").value           = rt.max_concurrent_per_ip ?? "";
  $("#ddos-rpm-bps").value        = rt.rpm_under_attack_bps ?? "";

  renderRuleToggles(rt.rules || {});

  renderSimpleRows($("#allow-rows"), rt.allow || [], "", "unallow");
  renderSimpleRows($("#deny-rows"),  rt.deny  || [], "", "undeny");
  renderSimpleRows($("#country-rows"), rt.blocked_countries || [], "", "country");

  $("#runtime-dump").textContent = JSON.stringify(rt, null, 2);
  $("#auth-token").placeholder = (rt.auth_token || "").slice(0, 8) + "…";

  $("#conn-state").textContent = "live";
  $(".pulse").classList.remove("bad");
}

function renderRuleToggles(state) {
  const el = $("#rule-toggles");
  el.innerHTML = RULE_KEYS.map(k => `
    <label class="tog">
      <span>${RULE_LABELS[k]}</span>
      <input type="checkbox" data-rule="${k}" ${state[k] ? "checked" : ""}>
      <span class="switch"></span>
    </label>
  `).join("");
}

function renderEvents(events, append = false) {
  const tbody = $("#event-tbody");
  const filterAllow     = $("#filter-allow").checked;
  const filterChallenge = $("#filter-challenge").checked;
  const filterBlock     = $("#filter-block").checked;
  const filterText      = $("#filter-text").value.toLowerCase();

  const accept = (e) => {
    if (e.action === "allow"     && !filterAllow)     return false;
    if (e.action === "challenge" && !filterChallenge) return false;
    if (e.action === "block"     && !filterBlock)     return false;
    if (filterText) {
      const hay = (e.ip + " " + e.path + " " + (e.user_agent||"") + " " + (e.rule_id||"")).toLowerCase();
      if (!hay.includes(filterText)) return false;
    }
    return true;
  };

  const render = (e) => `<tr>
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
    tbody.insertAdjacentHTML("afterbegin", html);
    while (tbody.children.length > 500) tbody.removeChild(tbody.lastElementChild);
  } else {
    tbody.innerHTML = events.filter(accept).map(render).join("") || `<tr><td colspan="10" class="mut">no events yet</td></tr>`;
  }
}

// ============== streaming ==============

let es;
function connectStream() {
  if (es) es.close();
  // EventSource can't set headers, so we use ?token=… as a fallback.
  es = new EventSource("/api/stream?token=" + encodeURIComponent(token));
  es.onmessage = (m) => {
    try {
      const data = JSON.parse(m.data);
      apply(data);
      if (data.events && data.events.length) {
        // events arrive oldest-first; render in reverse for new-first prepend.
        renderEvents(data.events.slice().reverse(), true);
        const last = data.events[data.events.length - 1];
        if (last) lastEventTs = last.ts_ms;
      }
    } catch (e) { /* keep going */ }
  };
  es.onerror = () => {
    $("#conn-state").textContent = "reconnecting…";
    $(".pulse").classList.add("bad");
  };
}

async function reloadEvents() {
  try {
    const r = await api("/api/events?limit=200");
    if (r.ok) {
      const evs = await r.json();
      renderEvents(evs, false);
    }
  } catch (e) {}
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
    const state = await stateR.json();
    const banned = await bannedR.json();
    apply(state);
    renderSimpleRows($("#banned-rows"),
      banned.map(b => ({ label: b.ip, value: b.expires_in + "s" })),
      "", "unban");
  } catch (e) {}
}

document.addEventListener("change", async (e) => {
  if (e.target.matches("[data-rule]")) {
    const k = e.target.dataset.rule;
    await patchRuntime({ rules: { [k]: e.target.checked } });
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

document.addEventListener("click", async (e) => {
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
    const v = $("#allow-cidr").value.trim();
    if (!v) return;
    const r = await api("/api/ip/allow?cidr=" + encodeURIComponent(v), { method: "POST" });
    if (r.ok) { $("#allow-cidr").value = ""; refreshState(); toast("Added"); } else { toast("Invalid CIDR", "bad"); }
  }
  if (e.target.id === "deny-add") {
    const v = $("#deny-cidr").value.trim();
    if (!v) return;
    const r = await api("/api/ip/deny?cidr=" + encodeURIComponent(v), { method: "POST" });
    if (r.ok) { $("#deny-cidr").value = ""; refreshState(); toast("Added"); } else { toast("Invalid CIDR", "bad"); }
  }
  if (e.target.id === "country-save") {
    const list = $("#country-input").value.split(",").map(s => s.trim()).filter(Boolean);
    await patchRuntime({ blocked_countries: list });
    $("#country-input").value = "";
  }
  if (e.target.id === "auth-save") {
    const v = $("#auth-token").value.trim();
    if (v.length < 16) { toast("Token must be ≥16 chars", "bad"); return; }
    await patchRuntime({ /* token rotation happens via runtime.json directly */ });
    toast("Edit runtime.json to rotate the token (server restart required for now)", "bad");
  }
  if (e.target.matches(".x")) {
    const cidr = e.target.dataset.remove;
    const action = e.target.dataset.action;
    if (action === "unallow" || action === "undeny") {
      const r = await api(`/api/ip/${action}?cidr=` + encodeURIComponent(cidr), { method: "POST" });
      if (r.ok) { refreshState(); toast("Removed"); }
    } else if (action === "country") {
      const cur = (((await (await api("/api/state")).json()).runtime || {}).blocked_countries || []);
      const next = cur.filter(c => c !== cidr);
      await patchRuntime({ blocked_countries: next });
    } else if (action === "unban") {
      const r = await api("/api/unban?ip=" + encodeURIComponent(cidr), { method: "POST" });
      if (r.ok) { refreshState(); toast("Unbanned"); }
    }
  }
});

$("#filter-allow").addEventListener("change", reloadEvents);
$("#filter-challenge").addEventListener("change", reloadEvents);
$("#filter-block").addEventListener("change", reloadEvents);
$("#filter-text").addEventListener("input", () => {
  // Debounce-ish — re-render existing tbody rather than refetch.
  reloadEvents();
});

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
