// 2t1-Waf · console — vanilla JS, no build step.

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const TOKEN_KEY = "2t1_token";
let token = localStorage.getItem(TOKEN_KEY) || "";

/// Active timeframe for the Overview page.
/// "live" = follow the SSE stream (60s ring buffer in metrics).
/// "30m"|"1h"|"6h"|"24h" = SQLite-backed historical view; SSE is
///                          paused while a historical range is selected.
let activeRange = "live";
let historicalTimer = null;

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
const routes = ["overview", "defense", "firewall", "traffic", "settings"];

const UAM_NAMES = ["Off", "Low", "Medium", "High", "Extreme"];
const DEFENSE_KEYS = [
  ["bot_score", "Bot score (header / UA fingerprint)"],
  ["behavior",  "Behavior (per-IP entropy / regularity)"],
  ["ddos",      "DDoS patterns (anomalous requests)"],
  ["honeypots", "Honeypot paths (instant ban)"],
  ["subnet",    "Subnet ceilings (/24 + /64)"],
  ["replay",    "Request replay flood"],
  ["dist_ua",   "Distributed UA (botnet signature)"],
];
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
function cssEscape(s) {
  return String(s).replace(/[^\w-]/g, "\\$&");
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

function setupCanvas(c, fixedH) {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = c.clientWidth, h = fixedH || c.clientHeight || 170;
  c.width = w * dpr; c.height = h * dpr;
  const ctx = c.getContext("2d"); ctx.scale(dpr, dpr);
  return { ctx, w, h };
}

function smoothPath(ctx, points, w, h) {
  // Catmull-Rom-ish smoothing using quadratic curves between midpoints.
  if (points.length < 2) return;
  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i];
    const p1 = points[i+1];
    const xc = (p0.x + p1.x) / 2;
    const yc = (p0.y + p1.y) / 2;
    ctx.quadraticCurveTo(p0.x, p0.y, xc, yc);
  }
  const last = points[points.length-1];
  ctx.lineTo(last.x, last.y);
}

function drawRing(buckets) {
  const c = $("#ring-chart");
  if (!c) return;
  const { ctx, w, h } = setupCanvas(c, 220);
  ctx.clearRect(0, 0, w, h);

  // grid lines
  ctx.strokeStyle = "rgba(17,17,17,0.06)"; ctx.lineWidth = 1;
  for (let i = 1; i < 5; i++) {
    const y = (h / 5) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  // axis labels (start / end seconds)
  const axis = $("#chart-axis");
  if (axis) {
    const now = new Date();
    const past = new Date(now.getTime() - 60000);
    const fmt = d => d.toTimeString().slice(0,8);
    axis.innerHTML = `<span>${fmt(past)}</span><span>${fmt(now)}</span>`;
  }

  const allowed   = buckets.map(b => b.allowed   || 0);
  const challenge = buckets.map(b => b.challenged || 0);
  const blocked   = buckets.map(b => b.blocked   || 0);
  const stack3 = buckets.map((_, i) => allowed[i] + challenge[i] + blocked[i]);
  const stack2 = buckets.map((_, i) => allowed[i] + challenge[i]);
  const stack1 = allowed;

  const max = Math.max(1, ...stack3);
  const stepX = w / Math.max(buckets.length - 1, 1);

  const toPoints = (arr) => arr.map((v, i) => ({
    x: i * stepX,
    y: h - (v / max) * h,
  }));

  const drawArea = (pts, fill, stroke) => {
    ctx.beginPath();
    smoothPath(ctx, pts, w, h);
    ctx.lineTo(pts[pts.length-1].x, h);
    ctx.lineTo(pts[0].x, h);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
    if (stroke) {
      ctx.beginPath(); smoothPath(ctx, pts, w, h);
      ctx.strokeStyle = stroke; ctx.lineWidth = 1.5; ctx.stroke();
    }
  };

  drawArea(toPoints(stack3), "rgba(179,32,58,0.18)",  "#b3203a");
  drawArea(toPoints(stack2), "rgba(184,121,0,0.18)",  "#b87900");
  drawArea(toPoints(stack1), "rgba(31,111,58,0.18)",  "#1f6f3a");
}

function drawRatio(buckets) {
  const c = $("#ratio-chart");
  if (!c) return;
  const { ctx, w, h } = setupCanvas(c, 220);
  ctx.clearRect(0, 0, w, h);

  ctx.strokeStyle = "rgba(17,17,17,0.06)"; ctx.lineWidth = 1;
  for (let i = 1; i < 5; i++) {
    const y = (h / 5) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  const ratios = buckets.map(b => {
    const t = (b.allowed||0) + (b.challenged||0) + (b.blocked||0);
    return t ? (b.blocked||0) / t : 0;
  });
  const stepX = w / Math.max(buckets.length - 1, 1);
  const pts = ratios.map((v, i) => ({ x: i * stepX, y: h - v * h }));

  ctx.beginPath();
  smoothPath(ctx, pts, w, h);
  ctx.lineTo(pts[pts.length-1].x, h);
  ctx.lineTo(pts[0].x, h);
  ctx.closePath();
  ctx.fillStyle = "rgba(179,32,58,0.15)"; ctx.fill();

  ctx.beginPath(); smoothPath(ctx, pts, w, h);
  ctx.strokeStyle = "#b3203a"; ctx.lineWidth = 2; ctx.stroke();
}

// ============== state apply ==============
// last 60s vs previous 60s (computed each tick from snapshots)
let prevWindow = { total: null, allowed: null, blocked: null, challenged: null, rps: null };
let lastRoll = 0;
function rollCompareWindow(total, allowed, blocked, challenged, rps) {
  const now = Date.now();
  if (!lastRoll) { lastRoll = now; return; }
  if (now - lastRoll < 60_000) return;
  prevWindow = { total, allowed, blocked, challenged, rps };
  lastRoll = now;
}
function setCmp(sel, cur, prev) {
  const el = $(sel); if (!el) return;
  el.textContent = (cur||0).toLocaleString();
  const dEl = $(sel + "-d"); if (!dEl) return;
  const delta = (cur||0) - (prev||0);
  if (prev === 0 || prev == null) {
    dEl.textContent = (delta > 0 ? "+" : "") + delta.toLocaleString();
    dEl.className = "cmp-delta " + (delta > 0 ? "up" : delta < 0 ? "down" : "");
    return;
  }
  const pct = Math.round(100 * delta / prev);
  const arrow = delta > 0 ? "↑" : delta < 0 ? "↓" : "·";
  dEl.textContent = `${arrow} ${(pct >= 0 ? "+" : "")}${pct}%`;
  dEl.className = "cmp-delta " + (delta > 0 ? "up" : delta < 0 ? "down" : "");
}

function apply(data) {
  if (!data) return;
  const m = data.metrics || {};
  const rt = data.runtime || {};
  const ring = m.ring || [];

  // last-60s window from ring
  const win60 = ring.reduce((a, b) => ({
    a: a.a + (b.allowed||0),
    c: a.c + (b.challenged||0),
    b: a.b + (b.blocked||0),
  }), {a:0,c:0,b:0});
  const win60Total = win60.a + win60.c + win60.b;
  const rps = Math.round(win60Total / Math.max(ring.length, 1));

  // KPI strip (lifetime totals)
  const lifetimeTotal = (m.allowed||0) + (m.challenged||0) + (m.blocked||0);
  $("#stat-total")?.textContent && ($("#stat-total").textContent = lifetimeTotal.toLocaleString());
  $("#stat-allowed")    && ($("#stat-allowed").textContent    = (m.allowed||0).toLocaleString());
  $("#stat-blocked")    && ($("#stat-blocked").textContent    = (m.blocked||0).toLocaleString());
  $("#stat-challenged") && ($("#stat-challenged").textContent = (m.challenged||0).toLocaleString());
  $("#stat-uniq-ips")   && ($("#stat-uniq-ips").textContent   = (m.unique_ips||0).toLocaleString());
  $("#stat-uniq-countries") && ($("#stat-uniq-countries").textContent = (m.unique_countries||0).toLocaleString());

  $("#stat-rps")        && ($("#stat-rps").textContent        = rps.toLocaleString());
  $("#stat-block-rate") && ($("#stat-block-rate").textContent = (win60Total ? Math.round(100 * win60.b / win60Total) : 0) + "%");
  $("#stat-inflight")   && ($("#stat-inflight").textContent   = (data.in_flight_total||0).toLocaleString());

  $("#block-ratio-mini") && ($("#block-ratio-mini").textContent = (win60Total ? Math.round(100 * win60.b / win60Total) : 0) + "%");

  if (data.version) $("#version").textContent = "v" + data.version;
  $("#inflight-state").textContent = (data.in_flight_total || 0).toLocaleString();
  $("#ua-state").textContent = rt.under_attack ? "ON" : "off";
  $("#ua-state").style.color = rt.under_attack ? "var(--bad)" : "";

  // Compare row (current 60s window vs previous 60s sample we held).
  if (prevWindow.total !== null) {
    setCmp("#cmp-total",      win60Total,      prevWindow.total);
    setCmp("#cmp-allowed",    win60.a,         prevWindow.allowed);
    setCmp("#cmp-blocks",     win60.b,         prevWindow.blocked);
    setCmp("#cmp-challenges", win60.c,         prevWindow.challenged);
    setCmp("#cmp-rps",        rps,             prevWindow.rps);
  }

  if (ring.length) {
    drawRing(ring);
    drawRatio(ring);
  }

  // Roll the comparison window every 60 seconds.
  rollCompareWindow(win60Total, win60.a, win60.b, win60.c, rps);

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

  // dstat
  updateDstat(m, data.in_flight_total || 0);

  // defense
  applyDefense(rt, m);
}

function applyDefense(rt, m) {
  const lvl = rt.uam_level ?? 0;
  $("#uam-current").textContent = "level " + lvl + " · " + (UAM_NAMES[lvl] || "?");
  $$(".uam-lvl").forEach(b => b.dataset.active = (parseInt(b.dataset.uam,10) === lvl) ? "1" : "0");

  const cm = rt.challenge_mode ?? 0;
  $$("#challenge-mode-seg .seg-btn").forEach(b =>
    b.dataset.active = (parseInt(b.dataset.cm,10) === cm) ? "1" : "0");

  $("#auto-uam-on").checked = !!rt.auto_uam_enabled;
  $("#auto-uam-threshold").value = rt.auto_uam_threshold ?? "";

  // defense toggles
  const dEl = $("#defense-toggles");
  if (dEl && !dEl.dataset.rendered) {
    dEl.innerHTML = DEFENSE_KEYS.map(([k, label]) => `
      <label class="tog">
        <span>${label}</span>
        <input type="checkbox" data-defense="${k}">
        <span class="switch"></span>
      </label>
    `).join("");
    dEl.dataset.rendered = "1";
  }
  const ds = rt.defenses || {};
  $$("[data-defense]").forEach(inp => inp.checked = !!ds[inp.dataset.defense]);

  // subnet ceilings
  if ($("#subnet-rpm"))  $("#subnet-rpm").value  = rt.subnet_rpm  ?? "";
  if ($("#subnet-conn")) $("#subnet-conn").value = rt.subnet_conn ?? "";
  // honeypot path list (only fill when not focused)
  const hp = $("#honeypot-paths");
  const paths = rt.honeypot_paths || [];
  if (hp && document.activeElement !== hp) hp.value = paths.join("\n");
  if ($("#honeypot-count")) $("#honeypot-count").textContent = paths.length;

  // top attackers — same as top IPs for now (block-weighted)
  const topAtk = m.top_ips ? m.top_ips.slice(0, 10) : [];
  renderRows($("#top-attackers"), topAtk);

  // block ratio over the ring
  const ring = m.ring || [];
  const sum = ring.reduce((a, b) => ({
    a: a.a + (b.allowed||0),
    c: a.c + (b.challenged||0),
    b: a.b + (b.blocked||0),
  }), {a:0,c:0,b:0});
  const total = sum.a + sum.c + sum.b;
  const pct = total ? Math.round((sum.b / total) * 100) : 0;
  $("#block-ratio").textContent = pct + "%";
  drawDefenseSpark(ring);
}

function drawDefenseSpark(buckets) {
  const c = $("#defense-spark");
  if (!c) return;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = c.clientWidth, h = c.clientHeight || 80;
  c.width = w * dpr; c.height = h * dpr;
  const ctx = c.getContext("2d"); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  // Show block ratio per bucket as a sparkline.
  const pts = buckets.map(b => {
    const t = (b.allowed||0) + (b.challenged||0) + (b.blocked||0);
    return t ? (b.blocked||0) / t : 0;
  });
  const bw = w / Math.max(pts.length, 1);
  ctx.strokeStyle = "#b3203a"; ctx.lineWidth = 1.5;
  ctx.beginPath();
  pts.forEach((v, i) => {
    const x = i * bw + bw/2;
    const y = h - v * h;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
  // baseline
  ctx.strokeStyle = "rgba(17,17,17,0.08)"; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(0, h - 0.5); ctx.lineTo(w, h - 0.5); ctx.stroke();
}

// ============ dstat ============
let prevTotals = null;
function pad(n, w) { return String(n).padStart(w); }
function updateDstat(m, inflight) {
  const cur = {
    a: m.allowed || 0,
    c: m.challenged || 0,
    b: m.blocked || 0,
    r: m.rate_limited || 0,
  };
  if (!prevTotals) { prevTotals = cur; return; }
  const dA = Math.max(0, cur.a - prevTotals.a);
  const dC = Math.max(0, cur.c - prevTotals.c);
  const dB = Math.max(0, cur.b - prevTotals.b);
  const dR = Math.max(0, cur.r - prevTotals.r);
  const total = dA + dC + dB;
  prevTotals = cur;

  const time = new Date().toTimeString().slice(0,8);
  const row = `${time}  ${pad(total,7)}  ${pad(dA,7)}  ${pad(dC,6)}  ${pad(dB,7)}  ${pad(dR,7)}  ${pad(inflight,9)}`;
  let cls = "dstat-line";
  if (dB > 0) cls += " bad-spike";
  else if (dC > 0) cls += " warn-spike";
  else if (total === 0) cls += " idle";

  const body = $("#dstat-body");
  if (!body) return;
  body.insertAdjacentHTML("afterbegin", `<span class="${cls}">${row}</span>\n`);
  while (body.childElementCount > 60) body.removeChild(body.lastElementChild);
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

function renderDetail(e) {
  const reasons = (e.reasons || []).map(r => `
    <div class="dr">
      <span class="dr-rule">${escapeHtml(r.rule_id)}</span>
      <span class="dr-cat">${escapeHtml(r.category)}</span>
      <span class="dr-score">+${r.score}</span>
      <span class="dr-detail">${escapeHtml(r.detail || "")}</span>
    </div>
  `).join("") || `<div class="mut">no signals fired</div>`;

  const headers = (e.headers || []).map(([k, v]) => `
    <div class="dh"><span class="dh-k">${escapeHtml(k)}</span><span class="dh-v">${escapeHtml(v)}</span></div>
  `).join("") || `<div class="mut">no headers captured</div>`;

  const ja4h = e.ja4h || "";
  const parts = ja4h.split("_");
  const ja4hParts = parts.length === 4
    ? `<div class="ja4h-parts">
         <div><span class="ja4h-k">a</span><code>${escapeHtml(parts[0])}</code><span class="ja4h-d">method+ver+cookie+ref+nheaders+lang</span></div>
         <div><span class="ja4h-k">b</span><code>${escapeHtml(parts[1])}</code><span class="ja4h-d">header order hash</span></div>
         <div><span class="ja4h-k">c</span><code>${escapeHtml(parts[2])}</code><span class="ja4h-d">cookie names hash</span></div>
         <div><span class="ja4h-k">d</span><code>${escapeHtml(parts[3])}</code><span class="ja4h-d">cookie values hash</span></div>
       </div>`
    : "";

  return `
    <div class="evt-panel">
      <div class="evt-panel-grid">
        <div class="evt-panel-block">
          <div class="evt-panel-title">Why · ${(e.reasons||[]).length} reason(s) · score ${e.score}</div>
          ${reasons}
        </div>
        <div class="evt-panel-block">
          <div class="evt-panel-title">Request</div>
          <div class="dh"><span class="dh-k">request id</span><span class="dh-v">${escapeHtml(e.request_id)}</span></div>
          <div class="dh"><span class="dh-k">http</span><span class="dh-v">${escapeHtml(e.http_version)}</span></div>
          <div class="dh"><span class="dh-k">method</span><span class="dh-v">${escapeHtml(e.method)} ${escapeHtml(e.path)}</span></div>
          <div class="dh"><span class="dh-k">query</span><span class="dh-v">${escapeHtml(e.query || "—")}</span></div>
          <div class="dh"><span class="dh-k">host</span><span class="dh-v">${escapeHtml(e.host)}</span></div>
          <div class="dh"><span class="dh-k">user-agent</span><span class="dh-v">${escapeHtml(e.user_agent || "—")}</span></div>
          <div class="dh"><span class="dh-k">country</span><span class="dh-v">${escapeHtml(e.country || "—")}</span></div>
        </div>
      </div>
      <div class="evt-panel-block">
        <div class="evt-panel-title">JA4H · <code class="ja4h-full">${escapeHtml(ja4h)}</code></div>
        ${ja4hParts}
      </div>
      <div class="evt-panel-block">
        <div class="evt-panel-title">Headers (in arrival order)</div>
        <div class="dh-list">${headers}</div>
      </div>
    </div>
  `;
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

  const render = e => {
    const ja4hShort = (e.ja4h || "").slice(0, 18);
    return `<tr class="evt-row" data-rid="${escapeHtml(e.request_id)}">
      <td class="evt-toggle">›</td>
      <td>${new Date(e.ts_ms).toLocaleTimeString()}</td>
      <td>${escapeHtml(e.ip)}</td>
      <td>${escapeHtml(e.country || "—")}</td>
      <td>${escapeHtml(e.method)}</td>
      <td>${escapeHtml(e.host)}</td>
      <td title="${escapeHtml(e.path)}">${escapeHtml((e.path||"").slice(0,50))}</td>
      <td><span class="badge ${e.action}">${e.action}</span></td>
      <td>${e.status}</td>
      <td>${e.score}</td>
      <td>${escapeHtml(e.rule_id || "")}</td>
      <td class="evt-ja4h" title="${escapeHtml(e.ja4h || "")}">${escapeHtml(ja4hShort)}…</td>
    </tr>
    <tr class="evt-detail hidden" data-detail-rid="${escapeHtml(e.request_id)}"><td colspan="12">${renderDetail(e)}</td></tr>`;
  };

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
  if (e.target.matches("[data-defense]")) {
    await patchRuntime({ defenses: { [e.target.dataset.defense]: e.target.checked } });
  }
  if (e.target.id === "under-attack") {
    await fetch("/api/under_attack?on=" + e.target.checked, {
      method: "POST", headers: { authorization: "Bearer " + token },
    });
    toast(e.target.checked ? "Under-attack mode ON" : "Under-attack mode OFF",
          e.target.checked ? "bad" : "ok");
    refreshState();
  }
  if (e.target.id === "auto-uam-on") {
    await patchRuntime({ auto_uam_enabled: e.target.checked });
    toast(e.target.checked ? "Auto-UAM watching" : "Auto-UAM off");
  }
});

// Range pill clicks (Live / 30m / 1h / 6h / 24h)
document.addEventListener("click", e => {
  const pill = e.target.closest(".range-pill");
  if (!pill) return;
  const range = pill.dataset.range;
  if (range === activeRange) return;
  $$(".range-pill").forEach(p => p.setAttribute("aria-selected", p === pill ? "true" : "false"));
  setRange(range);
});

function setRange(range) {
  activeRange = range;
  if (historicalTimer) { clearInterval(historicalTimer); historicalTimer = null; }
  if (range === "live") {
    // Reconnect SSE — apply() resumes driving the charts in real time.
    connectStream();
    return;
  }
  // Pause SSE for historical view; counter increments would be misleading
  // when the chart is showing minutes / hours of replayed data.
  if (es) { es.close(); es = null; }
  $("#status-dot").classList.remove("live"); $("#status-dot").classList.add("bad");
  $("#conn-state").textContent = "frozen · " + range;
  loadHistorical(range);
  // Refresh every 30s so the operator sees new data accumulate without
  // hammering the SQLite reader.
  historicalTimer = setInterval(() => loadHistorical(range), 30_000);
}

async function loadHistorical(range) {
  try {
    const [seriesR, eventsR] = await Promise.all([
      api(`/api/events/series?range=${encodeURIComponent(range)}`),
      api(`/api/events/range?range=${encodeURIComponent(range)}&limit=500`),
    ]);
    if (!seriesR.ok || !eventsR.ok) return;
    const buckets = await seriesR.json();
    const events  = await eventsR.json();
    applyHistorical(buckets, events, range);
  } catch (e) { /* silent — pill stays selected */ }
}

function applyHistorical(buckets, events, range) {
  // Tally totals over the window for the KPI strip.
  let allowed = 0, challenged = 0, blocked = 0, tarpit = 0;
  for (const b of buckets) {
    allowed   += b.allowed   || 0;
    challenged += b.challenged || 0;
    blocked   += b.blocked   || 0;
    tarpit    += b.tarpit    || 0;
  }
  const total = allowed + challenged + blocked + tarpit;
  $("#stat-total")    && ($("#stat-total").textContent    = total.toLocaleString());
  $("#stat-allowed")  && ($("#stat-allowed").textContent  = allowed.toLocaleString());
  $("#stat-blocked")  && ($("#stat-blocked").textContent  = (blocked+tarpit).toLocaleString());
  $("#stat-challenged") && ($("#stat-challenged").textContent = challenged.toLocaleString());

  // Distinct IPs and rule rules from the events sample.
  const uniqIps = new Set(events.map(e => e.ip));
  const cc      = new Set(events.map(e => e.country).filter(Boolean));
  $("#stat-uniq-ips")        && ($("#stat-uniq-ips").textContent        = uniqIps.size.toLocaleString());
  $("#stat-uniq-countries")  && ($("#stat-uniq-countries").textContent  = cc.size.toLocaleString());
  const span_s = rangeToSeconds(range);
  $("#stat-rps")        && ($("#stat-rps").textContent        = Math.round(total / Math.max(span_s, 1)).toLocaleString());
  $("#stat-block-rate") && ($("#stat-block-rate").textContent = (total ? Math.round(100 * (blocked+tarpit) / total) : 0) + "%");

  $("#block-ratio-mini") && ($("#block-ratio-mini").textContent = (total ? Math.round(100 * (blocked+tarpit) / total) : 0) + "%");

  // Draw the smoothed area chart against the per-second buckets.
  const chartBuckets = buckets.map(b => ({
    allowed: b.allowed||0, challenged: b.challenged||0,
    blocked: (b.blocked||0) + (b.tarpit||0),
  }));
  if (chartBuckets.length) {
    drawRing(chartBuckets);
    drawRatio(chartBuckets);
  }

  // Replay the events into the live-traffic table (rendered with the
  // same row/expand machinery as Live mode).
  renderEvents(events, false);
}

function rangeToSeconds(range) {
  switch (range) {
    case "30m": return 30 * 60;
    case "1h":  return 3600;
    case "6h":  return 6 * 3600;
    case "24h": return 24 * 3600;
    default:    return 60;
  }
}

document.addEventListener("click", async e => {
  // Event row → toggle the detail row right below it
  const evtRow = e.target.closest(".evt-row");
  if (evtRow && !e.target.matches("a, button, input")) {
    const rid = evtRow.dataset.rid;
    const detail = document.querySelector(`tr.evt-detail[data-detail-rid="${cssEscape(rid)}"]`);
    if (detail) {
      const open = !detail.classList.contains("hidden");
      detail.classList.toggle("hidden", open);
      evtRow.classList.toggle("evt-open", !open);
    }
    return;
  }
  // UAM level buttons
  const uamBtn = e.target.closest("[data-uam]");
  if (uamBtn) {
    const lvl = parseInt(uamBtn.dataset.uam, 10);
    const r = await api("/api/uam?level=" + lvl, { method: "POST" });
    if (r.ok) { toast("UAM " + UAM_NAMES[lvl]); refreshState(); }
    return;
  }
  // PANIC button
  if (e.target.id === "panic-btn") {
    const r = await api("/api/uam?panic=true", { method: "POST" });
    if (r.ok) { toast("⚠ PANIC engaged · UAM Extreme", "bad"); refreshState(); }
    return;
  }
  // Challenge mode segment
  const cmBtn = e.target.closest("[data-cm]");
  if (cmBtn) {
    const cm = parseInt(cmBtn.dataset.cm, 10);
    await patchRuntime({ challenge_mode: cm });
    return;
  }
  // Auto-UAM threshold save
  if (e.target.matches('[data-save="auto-uam"]')) {
    await patchRuntime({ auto_uam_threshold: parseInt($("#auto-uam-threshold").value, 10) });
    return;
  }
  // Subnet ceilings save
  if (e.target.matches('[data-save="subnet"]')) {
    await patchRuntime({
      subnet_rpm:  parseInt($("#subnet-rpm").value, 10),
      subnet_conn: parseInt($("#subnet-conn").value, 10),
    });
    return;
  }
  // Honeypot list save
  if (e.target.id === "honeypot-save") {
    const paths = $("#honeypot-paths").value
      .split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    await patchRuntime({ honeypot_paths: paths });
    toast(`Saved ${paths.length} traps`);
    return;
  }
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
