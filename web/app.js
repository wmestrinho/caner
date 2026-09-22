"use strict";
// caner dashboard: poll /api/snapshot, render three panels. No framework, no build.

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const api = (p) => p + (TOKEN ? (p.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(TOKEN) : "");
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function dur(sec) {
  if (sec == null) return "—";
  if (sec < 90) return Math.round(sec) + "s";
  if (sec < 5400) return Math.round(sec / 60) + "m";
  if (sec < 172800) return Math.round(sec / 3600) + "h";
  return Math.round(sec / 86400) + "d";
}

function renderFindings(snap) {
  const all = [];
  for (const key of ["proc", "crash", "net"]) {
    const d = snap[key] && snap[key].data;
    if (snap[key] && snap[key].error) {
      all.push({ level: "warn", text: key + " scanner failed — see server log" });
    }
    if (d && d.findings) d.findings.forEach((f) => all.push(f));
  }
  const rank = { alert: 0, warn: 1, info: 2 };
  all.sort((a, b) => (rank[a.level] ?? 3) - (rank[b.level] ?? 3));
  $("findings").innerHTML = all.length
    ? all.map((f) => `<div class="finding ${esc(f.level)}">
         <span class="tag t-${esc(f.level)}">${esc(f.level)}</span><p>${esc(f.text)}</p></div>`).join("")
    : `<div class="finding info"><span class="tag t-ok">ok</span><p>Nothing to report.</p></div>`;
}

function renderMem(entry) {
  const d = entry && entry.data;
  if (!d) return;
  $("memsum").textContent =
    `${d.available_mb} MB available of ${d.total_mb} MB · swap ${d.swap_used_mb} MB · ` +
    `reclaimable ${d.reclaimable_mb} MB · updated ${dur(entry.age_s)} ago`;
  $("memrows").innerHTML = d.groups.map((g) => {
    const state = g.protected ? `<span class="tag t-dim">protected</span>`
      : g.reclaimable ? `<span class="tag t-warn">reclaimable</span>`
      : `<span class="tag t-ok">active</span>`;
    return `<tr class="${g.stale ? "stale" : ""}">
      <td>${esc(g.label)}${g.scopes.length ? `<br><span class="muted mono">${esc(g.scopes[0])}</span>` : ""}</td>
      <td class="num">${g.rss_mb} MB</td><td class="num">${g.count}</td>
      <td class="num">${dur(g.oldest_s)}</td><td>${state}</td></tr>`;
  }).join("");
}

function renderCrash(entry) {
  const d = entry && entry.data;
  if (!d) return;
  $("crashsum").textContent =
    `${d.total_dumps} dump(s) → ${d.signatures} signature(s) · ${d.oom_kills} OOM kill(s) · ` +
    `${d.coredump_disk_mb} MB on disk · updated ${dur(entry.age_s)} ago`;
  $("crashrows").innerHTML = d.groups.length ? d.groups.map((g) => {
    const notes = [];
    if (g.storm) notes.push(`<span class="tag t-warn">storm</span>`);
    notes.push(g.still_running ? `<span class="tag t-ok">app running</span>`
                               : `<span class="tag t-dim">app gone</span>`);
    g.known_issues.forEach((k) =>
      notes.push(`<a href="${esc(k.url)}" target="_blank" rel="noopener noreferrer">known issue</a>`));
    return `<tr><td class="mono">${esc(g.exe_short)}<br><span class="muted">${esc(g.last_iso)}</span></td>
      <td><span class="tag t-alert">${esc(g.signal)}</span></td>
      <td class="num">${g.count}</td>
      <td class="mono">${g.sig_frames.slice(0, 2).map(esc).join("<br>")}</td>
      <td>${notes.join(" ")}</td></tr>`;
  }).join("") : `<tr><td colspan="5" class="muted">No core dumps recorded.</td></tr>`;
}

function renderNet(entry) {
  const d = entry && entry.data;
  if (!d) return;
  $("netsum").textContent =
    `${d.resolvers.length} resolver(s) · IPv6 route ${d.ipv6_route ? "yes" : "no"} · ` +
    `updated ${dur(entry.age_s)} ago`;
  $("netrows").innerHTML = d.endpoints.map((e) => {
    const cls = e.status === "ok" ? "t-ok" : e.status === "degraded" ? "t-alert" : "t-warn";
    const rows = e.resolvers.map((r) => {
      const ips = r.error
        ? `<span class="t-warn">${esc(r.error)}</span>`
        : (r.ips.length ? r.ips.map((i) =>
            `<span class="mono">${esc(i.ip)}</span> <span class="${i.ok ? "t-ok" : "t-alert"}">${
              i.ok ? i.ms + " ms" : esc(i.error || "unreachable")}</span>`).join(" · ")
          : `<span class="muted">no answer</span>`);
      return `<li><span class="who mono">${esc(r.resolver)}</span>
                <span class="tag t-dim">${esc(r.kind)}</span><span>${ips}</span></li>`;
    }).join("");
    return `<div class="ep"><h3>${esc(e.host)}:${e.port}
      <span class="tag ${cls}">${esc(e.status)}</span>
      ${e.divergent ? `<span class="tag t-info">resolvers disagree</span>` : ""}
      <span class="muted">${esc(e.label || "")}</span></h3><ul class="rsv">${rows}</ul></div>`;
  }).join("");
}

async function tick() {
  try {
    const res = await fetch(api("/api/snapshot"), { cache: "no-store" });
    if (res.status === 401) {
      $("findings").innerHTML =
        `<div class="finding alert"><span class="tag t-alert">auth</span>
         <p>Missing or bad token. Append <code>?token=…</code> to the URL.</p></div>`;
      return;
    }
    const snap = await res.json();
    $("host").textContent = snap.meta.hostname;
    $("ver").textContent = snap.meta.version;
    $("selfrss").textContent = snap.meta.self_rss_mb + " MB";
    renderFindings(snap);
    renderMem(snap.proc);
    renderCrash(snap.crash);
    renderNet(snap.net);
  } catch (err) {
    $("findings").innerHTML =
      `<div class="finding warn"><span class="tag t-warn">offline</span>
       <p>Cannot reach caner: ${esc(err.message)}</p></div>`;
  }
}

$("rescan").addEventListener("click", async () => {
  await fetch(api("/api/rescan"), { cache: "no-store" }).catch(() => {});
  setTimeout(tick, 600);
});
tick();
setInterval(tick, 5000);
