// Pages — every control calls a real backend command. No fabricated values.
import { invoke, esc, fmtElapsed } from "./api";
import { icon } from "./icons";
import type { Dict } from "./i18n";

export interface Ctx {
  t: Dict;
  toast: (msg: string, kind?: "ok" | "err" | "") => void;
  confirm: (title: string, body: string, okLabel: string, danger?: boolean) => Promise<boolean>;
  showDetail: (title: string, rows: [string, string][], actionsHtml?: string) => void;
  refreshTopbar: () => void;
}

function badge(state: string): string {
  const s = state.toLowerCase();
  let cls = "b-unknown";
  if (/(healthy|on|signed|trusted|ok|enabled|automatic|running|show|minimum)/.test(s)) cls = "b-ok";
  if (/(needs attention|off|disabled|unsigned|malicious|threat|error|failed|required)/.test(s)) cls = "b-bad";
  if (/(warning|suspicious|unknown|manual|unable|informational|optional)/.test(s)) cls = "b-warning";
  if (s.includes("potentially")) cls = "b-warning";
  return `<span class="badge ${cls}">${esc(state)}</span>`;
}

function table(headers: string[], rows: string[][]): string {
  return `<table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
    rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${headers.length}" class="muted">${"—"}</td></tr>`
  }</tbody></table>`;
}

// ── Overview ──────────────────────────────────────────────
export async function renderOverview(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.sysOverview)}</h1><p class="sub">${esc(t.firstScanNote)}</p><p class="muted">${esc(t.loading)}</p>`;
  try {
    const [ov, sec, live, upd] = await Promise.all([
      invoke<any>("cmd_get_system_overview").catch(() => null),
      invoke<any>("cmd_get_security_status").catch(() => null),
      invoke<any>("cmd_get_live_stats").catch(() => null),
      invoke<any>("cmd_update_status").catch(() => null),
    ]);
    const o = ov as Record<string, any> | null;
    const l = live as Record<string, any> | null;
    const disks = (o?.["storage"] as unknown as { mount: string; free_gb: number; total_gb: number }[]) || [];
    el.innerHTML = `
      <h1>${esc(t.sysOverview)}</h1><p class="sub">${esc(t.firstScanNote)}</p>
      <div class="grid c3">
        <div class="card"><h3>${icon("win")} ${esc(t.winVer)}</h3>
          <dl class="kv"><dt>${esc(t.winVer)}</dt><dd>${esc((o?.["windows_version"] as string) || t.unable)}</dd>
          <dt>Build</dt><dd class="mono">${esc((o?.["build"] as string) || "—")}</dd>
          <dt>Host</dt><dd class="mono">${esc((o?.["hostname"] as string) || "—")}</dd>
          <dt>User</dt><dd class="mono">${esc((o?.["username"] as string) || "—")}</dd>
          <dt>${esc(t.uptime)}</dt><dd>${esc((o?.["uptime_human"] as string) || "—")}</dd></dl></div>
        <div class="card" id="live-card"><h3>${icon("cpu")} ${esc(t.cpu)} / ${esc(t.ram)}</h3>
          <dl class="kv"><dt>${esc(t.cpu)}</dt><dd>${esc((o?.["cpu"] as string) || t.unable)}</dd>
          <dt>Cores</dt><dd>${esc(String(o?.["cpu_cores"] ?? "—"))}</dd>
          <dt>${esc(t.ram)}</dt><dd>${esc(String(o?.["ram_total_gb"] ?? "—"))} GB total · ${esc(String(o?.["ram_free_gb"] ?? "—"))} GB free</dd>
          <dt>${esc(t.gpu)}</dt><dd>${esc(((l?.["gpu"]) as string) || t.unable)}</dd>
          <dt id="live-row">${esc(t.live)}</dt><dd id="live-val">CPU ${esc(String((l as Record<string, unknown>)?.["cpu_pct"] ?? "—"))}% · RAM ${esc(String((l as Record<string, unknown>)?.["ram_pct"] ?? "—"))}%</dd></dl>
          <div class="btn-row"><button class="btn" data-act="refresh-live">${icon("gauge")} ${esc(t.refresh)}</button></div></div>
        <div class="card"><h3>${icon("shield")} ${esc(t.secOverview)}</h3>
          <dl class="kv"><dt>${esc(t.defender)}</dt><dd>${esc((o?.["defender"] as string) || t.unable)}</dd>
          <dt>${esc(t.firewall)}</dt><dd>${esc((o?.["firewall"] as string) || t.unable)}</dd>
          <dt>${esc(t.updatesL)}</dt><dd>${esc((o?.["update"] as string) || t.unable)}</dd></dl></div>
      </div>
      <h2>${esc(t.storageL)}</h2>
      <div class="card">${table(["Mount", "Free", "Total"], disks.map((d) => [`<span class="mono">${esc(d.mount)}</span>`, `${esc(String(d.free_gb))} GB`, `${esc(String(d.total_gb))} GB`]))}</div>
      <h2>${esc(t.recActions)}</h2><div class="card" id="rec"></div>`;
    const rec = el.querySelector("#rec") as HTMLElement;
    const vuln = (await invoke<unknown[]>("cmd_get_vuln_checks").catch(() => [])) as { name: string; state: string; detail: string }[];
    const actionable = vuln.filter((v) => v.state === "Needs Attention" || v.state === "Warning");
    rec.innerHTML = actionable.length
      ? `<ul>${actionable.map((v) => `<li><b>${esc(v.name)}</b> — ${badge(v.state)}<br><span class="muted">${esc(v.detail)}</span></li>`).join("")}</ul><p class="muted">${esc(t.firstScanNote)}</p>`
      : `<p>${esc(t.healthy)} — ${esc(t.noResults)}</p>`;
    el.querySelector('[data-act="refresh-live"]')?.addEventListener("click", () => renderOverview(el, ctx));
    // On-demand live refresh only when the user enabled real-time monitor (default off).
    try {
      const s = await invoke<{ realtime_monitor: boolean }>("cmd_get_settings").catch(() => null);
      if (s?.realtime_monitor) {
        const w = window as unknown as { __owLive?: number };
        if (w.__owLive) clearInterval(w.__owLive);
        w.__owLive = window.setInterval(async () => {
          if (!document.getElementById("live-val")) { clearInterval(w.__owLive); return; }
          const cur = await invoke<Record<string, unknown>>("cmd_get_live_stats").catch(() => null);
          const v = document.getElementById("live-val");
          if (v && cur) v.textContent = `CPU ${String(cur["cpu_pct"])}% · RAM ${String(cur["ram_pct"])}%`;
        }, 2000);
      }
    } catch { /* manual refresh remains */ }
  } catch (e) {
    el.innerHTML = `<h1>${esc(t.sysOverview)}</h1><p>${esc(String(e))}</p>`;
  }
}

// ── Security ──────────────────────────────────────────────
export async function renderSecurity(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.security)}</h1><p class="sub">${esc(t.audit)}</p><p class="muted">${esc(t.loading)}</p>`;
  const [st, audit, vuln] = await Promise.all([
    invoke<Record<string, string>>("cmd_get_security_status").catch(() => null),
    invoke<{ id: string; name: string; state: string; detail: string; kind: string }[]>("cmd_get_security_audit").catch(() => []),
    invoke<{ id: string; name: string; state: string; detail: string; kind: string }[]>("cmd_get_vuln_checks").catch(() => []),
  ]);
  el.innerHTML = `
    <h1>${esc(t.security)}</h1><p class="sub">${esc(t.audit)}</p>
    <div class="grid c3">
      <div class="card"><h3>${esc(t.defender)}</h3><p>${badge(st?.["defender"] || t.unable)}</p><p class="muted mono">${esc(st?.["definitions"] ? `${t.defs}: ${st["definitions"]}` : "")}</p></div>
      <div class="card"><h3>${esc(t.rt)}</h3><p>${badge(st?.["realtime"] || t.unable)}</p></div>
      <div class="card"><h3>${esc(t.firewall)}</h3><p>${esc(st?.["firewall"] || t.unable)}</p></div>
      <div class="card"><h3>${esc(t.threatCount)}</h3><p class="mono">${esc(st?.["threat_count"] || t.unable)}</p></div>
      <div class="card"><h3>${esc(t.lastScan)}</h3><p class="mono">${esc(st?.["last_scan"] || t.unable)}</p></div>
      <div class="card"><h3>${esc(t.updatesL)}</h3><p>${esc(st?.["updates"] || t.unable)}</p></div>
    </div>
    <h2>${esc(t.audit)}</h2><div class="card">${table([t.name, t.status, t.description], (audit || []).map((a) => [esc(a.name), badge(a.state), esc(a.detail)]))}</div>
    <h2>${esc(t.vuln)}</h2><div class="card">${table([t.name, t.status, t.description], (vuln || []).map((a) => [esc(a.name) + ` <span class="muted">[${esc(a.kind)}]</span>`, badge(a.state), esc(a.detail)]))}</div>
    <div class="btn-row">
      <button class="btn" data-act="exp-json">${icon("report")} ${esc(t.secReport)} (JSON)</button>
      <button class="btn" data-act="exp-html">${icon("report")} ${esc(t.secReport)} (HTML)</button>
      <button class="btn" data-act="exp-txt">${icon("report")} ${esc(t.secReport)} (TXT)</button>
    </div>`;
  const exp = async (f: string) => {
    try {
      const p = await invoke<string>("cmd_export_security_report", { format: f, scanId: null });
      ctx.toast(`Saved: ${p}`, "ok");
    } catch (e) { ctx.toast(String(e), "err"); }
  };
  el.querySelector('[data-act="exp-json"]')?.addEventListener("click", () => exp("json"));
  el.querySelector('[data-act="exp-html"]')?.addEventListener("click", () => exp("html"));
  el.querySelector('[data-act="exp-txt"]')?.addEventListener("click", () => exp("txt"));
}

// ── Scan ──────────────────────────────────────────────────
let currentScan: string | null = null;
export function renderScan(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `
    <h1>${esc(t.systemScan)}</h1><p class="sub">${esc(t.scanType)}</p>
    <div class="card">
      <div class="radio-row" role="radiogroup">
        ${["Quick", "Standard", "Deep"].map((l, i) => `<label><input type="radio" name="scan-level" value="${l}" ${i === 0 ? "checked" : ""}/> ${esc((t as Record<string, string>)[l.toLowerCase()] || l)} ${i === 0 ? `<span class="muted">— common locations & active threats</span>` : i === 1 ? `<span class="muted">— broader persistence locations</span>` : `<span class="muted">— most comprehensive practical sweep</span>`}</label>`).join("")}
      </div>
      <div class="btn-row"><button class="btn primary" data-act="start">${icon("scan")} ${esc(t.startScan)}</button></div>
      <p class="muted">Uses Windows Defender signals plus real filesystem inspection. Unsigned or unfamiliar is never labelled malware without evidence.</p>
    </div>
    <div class="card" id="scan-live" style="display:none"></div>
    <h2>${esc(t.complete)} / History</h2><div class="card" id="scan-hist"><p class="muted">${esc(t.loading)}</p></div>`;
  const live = el.querySelector("#scan-live") as HTMLElement;
  const histEl = el.querySelector("#scan-hist") as HTMLElement;
  const loadHist = async () => {
    const h = await invoke<Record<string, unknown>[]>("cmd_get_scan_history").catch(() => []);
    histEl.innerHTML = table(["Date", "Type", "Files", "Threats", "Warnings", "Duration"], (h || []).map((r) => [
      `<span class="mono">${esc(String(r["date"]))}</span>`, esc(String(r["level"])), esc(String(r["files_scanned"])),
      esc(String(r["threats"])), esc(String((r["suspicious"] as number || 0) + (r["pup"] as number || 0))), fmtElapsed(Number(r["duration_secs"] || 0)),
    ]));
  };
  loadHist();
  el.querySelector('[data-act="start"]')?.addEventListener("click", async () => {
    const level = (el.querySelector('input[name="scan-level"]:checked') as HTMLInputElement)?.value || "Quick";
    try {
      const r = await invoke<{ scan_id: string }>("cmd_start_scan", { level });
      currentScan = r.scan_id;
      live.style.display = "";
      live.innerHTML = `<h3>${esc(t.scanning)} (${esc(level)})</h3>
        <div class="scan-stat"><span>${esc(t.filesScanned)}<b id="sc-files">0</b></span><span>${esc(t.threatsFound)}<b id="sc-threats">0</b></span><span>${esc(t.elapsed)}<b id="sc-elapsed">00:00</b></span></div>
        <p class="muted">${esc(t.curLoc)}:<br><span class="mono" id="sc-loc">…</span></p>
        <div class="btn-row"><button class="btn" data-act="pause">${esc(t.pause)}</button><button class="btn" data-act="resume">${esc(t.resume)}</button><button class="btn danger" data-act="cancel">${esc(t.cancel)}</button></div>`;
      live.querySelector('[data-act="pause"]')?.addEventListener("click", () => currentScan && invoke("cmd_pause_scan", { scanId: currentScan }).catch((e) => ctx.toast(String(e), "err")));
      live.querySelector('[data-act="resume"]')?.addEventListener("click", () => currentScan && invoke("cmd_resume_scan", { scanId: currentScan }).catch((e) => ctx.toast(String(e), "err")));
      live.querySelector('[data-act="cancel"]')?.addEventListener("click", () => currentScan && invoke("cmd_cancel_scan", { scanId: currentScan }).catch((e) => ctx.toast(String(e), "err")));
    } catch (e) { ctx.toast(String(e), "err"); }
  });
  // progress events are wired globally in main.ts via updateScanLive()
  (el as HTMLElement & { _live?: HTMLElement })._live = live;
  void loadHist;
}

export function updateScanLive(payload: { scan_id: string; running: boolean; current_location: string; files_scanned: number; threats: number; suspicious: number; pup: number; elapsed_secs: number }) {
  const loc = document.getElementById("sc-loc");
  if (!loc) return;
  loc.textContent = payload.current_location;
  const f = document.getElementById("sc-files");
  if (f) f.textContent = String(payload.files_scanned);
  const th = document.getElementById("sc-threats");
  if (th) th.textContent = String(payload.threats + payload.suspicious + payload.pup);
  const e = document.getElementById("sc-elapsed");
  if (e) e.textContent = fmtElapsed(payload.elapsed_secs);
  if (!payload.running) {
    const live = document.getElementById("scan-live");
    if (live) live.insertAdjacentHTML("beforeend", `<p><b>Scan finished.</b> See Threats for detections with evidence, and Reports for history.</p>`);
    currentScan = null;
  }
}

// ── Threats ───────────────────────────────────────────────
export async function renderThreats(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.threats)}</h1><p class="sub">Trusted / Microsoft / Signed / Unknown / Suspicious / Potentially Unwanted / Malicious — only with evidence.</p><div class="card" id="th"><p class="muted">${esc(t.loading)}</p></div>`;
  const box = el.querySelector("#th") as HTMLElement;
  const load = async () => {
    const list = await invoke<Record<string, string>[]>("cmd_list_threats").catch(() => []);
    box.innerHTML = table([t.file, t.risk, t.publisher, t.signature, ""], (list || []).map((d) => [
      `<span class="mono">${esc(d["file"])}</span><br><span class="muted mono">${esc(d["path"])}</span>`,
      badge(d["risk"] || "Unknown"), esc(d["publisher"] || "Unknown"), esc(d["signature"] || "Unknown"),
      `<button class="btn" data-id="${esc(d["id"])}" data-act="detail">${esc(t.details)}</button>`,
    ])) + (list && list.length ? "" : `<p class="muted">${esc(t.noResults)} No detections. Run a System Scan first.</p>`);
    box.querySelectorAll('[data-act="detail"]').forEach((b) =>
      b.addEventListener("click", () => {
        const d = (list || []).find((x) => x["id"] === (b as HTMLElement).dataset["id"]);
        if (!d) return;
        ctx.showDetail(d["file"] || "Detection", [
          [t.file, d["file"] || ""], [t.path, d["path"] || ""], [t.publisher, d["publisher"] || "Unknown"],
          [t.signature, d["signature"] || "Unknown"], [t.hash, d["hash"] || ""], [t.source, d["source"] || ""],
          [t.risk, d["risk"] || ""], [t.reason, d["reason"] || ""],
        ], `<div class="btn-row">
          <button class="btn" data-x="quar">${esc(t.quarantine)}</button>
          <button class="btn danger" data-x="del">${esc(t.remove)}</button>
          <button class="btn" data-x="ign">${esc(t.ignore)}</button>
          <button class="btn" data-x="loc">${esc(t.openLoc)}</button></div>`);
        const root = document.getElementById("dialog-root")!;
        root.querySelector('[data-x="quar"]')?.addEventListener("click", async () => {
          if (!await ctx.confirm("Quarantine file", `What will happen: the file is moved to %LOCALAPPDATA%\\Open Windows\\Quarantine.\nFile: ${d["path"]}\nReason: ${d["reason"]}\nImpact: the program will stop running. Reversible via quarantine folder.`, t.quarantine)) return;
          try { ctx.toast(await invoke<string>("cmd_quarantine_file", { id: d["id"] }), "ok"); (document.querySelector(".dialog") as HTMLElement)?.remove(); document.querySelector("#dialog-root .overlay")?.remove(); load(); } catch (e) { ctx.toast(String(e), "err"); }
        });
        root.querySelector('[data-x="del"]')?.addEventListener("click", async () => {
          if (!await ctx.confirm("Delete file permanently", `File: ${d["path"]}\nReason: ${d["reason"]}\nImpact: permanent and NOT reversible. Prefer Quarantine.`, t.remove, true)) return;
          try { ctx.toast(await invoke<string>("cmd_remove_file", { id: d["id"] }), "ok"); (document.querySelector(".dialog") as HTMLElement)?.remove(); document.querySelector("#dialog-root .overlay")?.remove(); load(); } catch (e) { ctx.toast(String(e), "err"); }
        });
        root.querySelector('[data-x="ign"]')?.addEventListener("click", async () => {
          try { ctx.toast(await invoke<string>("cmd_ignore_detection", { id: d["id"] }), "ok"); (document.querySelector(".dialog") as HTMLElement)?.remove(); document.querySelector("#dialog-root .overlay")?.remove(); load(); } catch (e) { ctx.toast(String(e), "err"); }
        });
        root.querySelector('[data-x="loc"]')?.addEventListener("click", async () => {
          try { ctx.toast(await invoke<string>("cmd_open_location", { path: d["path"] }), "ok"); } catch (e) { ctx.toast(String(e), "err"); }
        });
      })
    );
  };
  await load();
}

// ── Cleanup ───────────────────────────────────────────────
export async function renderCleanup(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.cleanup)}</h1><p class="sub">${esc(t.analyze)} → ${esc(t.review)} → ${esc(t.clean)}. Sizes shown are measured, never estimated.</p>
    <div class="btn-row"><button class="btn primary" data-act="analyze">${icon("scan")} ${esc(t.analyze)}</button></div>
    <div class="card" id="cl"><p class="muted">Run Analyze to measure reclaimable space.</p></div>`;
  el.querySelector('[data-act="analyze"]')?.addEventListener("click", async () => {
    const box = el.querySelector("#cl") as HTMLElement;
    box.innerHTML = `<p class="muted">${esc(t.loading)}</p>`;
    const cats = await invoke<{ id: string; name: string; path: string; bytes: number; bytes_human: string; files: number; note: string }[]>("cmd_analyze_cleanup").catch(() => []);
    const total = (cats || []).reduce((a, c) => a + c.bytes, 0);
    box.innerHTML = table([t.name, "Size", t.path, ""], (cats || []).map((c) => [
      `<label><input type="checkbox" data-id="${esc(c.id)}" checked/> <b>${esc(c.name)}</b><br><span class="muted">${esc(c.note)}</span></label>`,
      `<b>${esc(c.bytes_human)}</b><br><span class="muted">${c.files} files</span>`, `<span class="mono muted">${esc(c.path)}</span>`, "",
    ])) + `<p><b>${esc(t.totalReclaim)}: ${(total / 1073741824).toFixed(1)} GB</b></p>
    <div class="btn-row"><button class="btn primary" data-act="clean">${icon("clean")} ${esc(t.clean)} selected</button></div>`;
    box.querySelector('[data-act="clean"]')?.addEventListener("click", async () => {
      const ids = [...box.querySelectorAll("input[type=checkbox]:checked")].map((c) => (c as HTMLInputElement).dataset["id"]!);
      if (!ids.length) { ctx.toast("Select at least one category.", "err"); return; }
      if (!await ctx.confirm("Clean selected categories", `The following will be removed:\n${ids.join(", ")}\n\nRecycle Bin emptying is permanent. Others remove only stale temp/cache/log payloads.`, t.clean, true)) return;
      try {
        const r = await invoke<{ freed: string; details: unknown }>("cmd_clean_cleanup", { ids });
        ctx.toast(`Freed ${r.freed}`, "ok");
      } catch (e) { ctx.toast(String(e), "err"); }
    });
  });
}

// ── Optimizer ─────────────────────────────────────────────
export async function renderOptimizer(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.optimizer)}</h1><p class="sub">Performance · Privacy · Windows UI · Gaming · Background Activity · Updates · File Explorer · Power · Networking. Every tweak shows state, risk and a revert path.</p>
    <div class="toolbar"><select id="cat"><option>All</option><option>Performance</option><option>Privacy</option><option>Windows UI</option><option>Gaming</option><option>Background Activity</option><option>Updates</option><option>File Explorer</option><option>Power</option><option>Networking</option></select>
    <select id="prof"><option>Balanced</option><option>Performance</option><option>Privacy</option><option>Minimal</option></select>
    <button class="btn" data-act="preview">${esc(t.preview)}</button>
    <button class="btn" data-act="restore">${icon("shield")} ${esc(t.createRestore)}</button></div>
    <div class="card" id="prof-prev"></div>
    <div class="card" id="tw"><p class="muted">${esc(t.loading)}</p></div>`;
  const tw = el.querySelector("#tw") as HTMLElement;
  const load = async (cat: string) => {
    const list = await invoke<{ id: string; name: string; description: string; category: string; current: string; recommended: string; risk: string; side_effects: string }[]>("cmd_list_tweaks", { category: cat === "All" ? null : cat }).catch(() => []);
    tw.innerHTML = table([t.name, "Current", "Recommended", t.risk, ""], (list || []).map((w) => [
      `<b>${esc(w.name)}</b> <span class="muted">[${esc(w.category)}]</span><br><span class="muted">${esc(w.description)}<br>Side effects: ${esc(w.side_effects)}</span>`,
      `<span class="mono">${esc(w.current)}</span>`, `<span class="mono">${esc(w.recommended)}</span>`, badge(w.risk),
      `<button class="btn" data-a="${esc(w.id)}">${esc(t.apply)}</button> <button class="btn" data-r="${esc(w.id)}">${esc(t.revert)}</button>`,
    ]));
    tw.querySelectorAll("[data-a]").forEach((b) => b.addEventListener("click", async () => {
      const id = (b as HTMLElement).dataset["a"]!;
      if (!await ctx.confirm("Apply tweak", "The previous registry value is saved to Change History for Undo. For major changes, create a restore point first.", t.apply)) return;
      try { ctx.toast(await invoke<string>("cmd_apply_tweak", { id }), "ok"); load((el.querySelector("#cat") as HTMLSelectElement).value); } catch (e) { ctx.toast(String(e), "err"); }
    }));
    tw.querySelectorAll("[data-r]").forEach((b) => b.addEventListener("click", async () => {
      try { ctx.toast(await invoke<string>("cmd_revert_tweak", { id: (b as HTMLElement).dataset["r"]! }), "ok"); load((el.querySelector("#cat") as HTMLSelectElement).value); } catch (e) { ctx.toast(String(e), "err"); }
    }));
  };
  await load("All");
  (el.querySelector("#cat") as HTMLSelectElement).addEventListener("change", (e) => load((e.target as HTMLSelectElement).value));
  el.querySelector('[data-act="restore"]')?.addEventListener("click", async () => {
    try { ctx.toast(await invoke<string>("cmd_create_restore_point", { description: "Open Windows checkpoint" }), "ok"); } catch (e) { ctx.toast(String(e), "err"); }
  });
  el.querySelector('[data-act="preview"]')?.addEventListener("click", async () => {
    const prof = (el.querySelector("#prof") as HTMLSelectElement).value;
    const prev = await invoke<{ id: string; name: string; current: string; will_set: string; risk: string; needs_admin: boolean }[]>("cmd_preview_profile", { profile: prof }).catch(() => []);
    const box = el.querySelector("#prof-prev") as HTMLElement;
    box.innerHTML = `<h3>Preset “${esc(prof)}” — exactly what will change (security features are never in this list)</h3>` +
      table([t.name, "Current", "Will set", "Admin?"], (prev || []).map((p) => [esc(p.name), `<span class="mono">${esc(p.current)}</span>`, `<span class="mono">${esc(p.will_set)}</span>`, p.needs_admin ? "Yes" : "No"])) +
      `<div class="btn-row"><button class="btn primary" data-go="1">${esc(t.applyProfile)}: ${esc(prof)}</button></div>`;
    box.querySelector("[data-go]")?.addEventListener("click", async () => {
      if (!await ctx.confirm(`Apply preset “${prof}”`, (prev || []).map((p) => `• ${p.name}: ${p.current} → ${p.will_set}`).join("\n"), t.applyProfile)) return;
      try { ctx.toast(await invoke<string>("cmd_apply_profile", { profile: prof, ids: (prev || []).map((p) => p.id) }), "ok"); load("All"); } catch (e) { ctx.toast(String(e), "err"); }
    });
  });
}

// ── Startup ───────────────────────────────────────────────
export async function renderStartup(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.startup)}</h1><p class="sub">Registry Run keys, Startup folders and logon scheduled tasks. Entries are disabled reversibly — never auto-removed.</p><div class="card" id="s"><p class="muted">${esc(t.loading)}</p></div>`;
  const box = el.querySelector("#s") as HTMLElement;
  const load = async () => {
    const data = await invoke<{ startup: { id: string; name: string; publisher: string; path: string; source: string; enabled: boolean; impact: string; signature: string }[]; tasks: { name: string; state: string; action: string; author: string }[] }>("cmd_list_startup").catch(() => null);
    box.innerHTML = `<h3>Startup entries (${data?.startup.length || 0})</h3>` + table([t.name, t.publisher, t.path, t.source, t.status, t.signature, ""], (data?.startup || []).map((s) => [
      esc(s.name), esc(s.publisher || "—"), `<span class="mono">${esc(s.path)}</span>`, esc(s.source), s.enabled ? badge("On") : badge("Off"), badge(s.signature),
      `${s.id.startsWith("reg:") ? `<button class="btn" data-id="${esc(s.id)}" data-en="${s.enabled ? 0 : 1}">${s.enabled ? esc(t.disable) : esc(t.enable)}</button>` : ""} <button class="btn" data-loc="${esc(s.path)}">${esc(t.openLoc)}</button>`,
    ])) + `<h3>Scheduled tasks (logon-relevant subset)</h3>` + table(["Task", "State", "Action"], (data?.tasks || []).slice(0, 100).map((x) => [esc(x.name), esc(x.state), `<span class="mono">${esc(x.action)}</span>`]));
    box.querySelectorAll("[data-id]").forEach((b) => b.addEventListener("click", async () => {
      const id = (b as HTMLElement).dataset["id"]!;
      const en = (b as HTMLElement).dataset["en"] === "1";
      if (!await ctx.confirm(en ? "Enable startup entry" : "Disable startup entry", `${id}\n\nDisabling is reversible in Change History.`, en ? t.enable : t.disable)) return;
      try { ctx.toast(await invoke<string>("cmd_set_startup_enabled", { id, enabled: en }), "ok"); load(); } catch (e) { ctx.toast(String(e), "err"); }
    }));
    box.querySelectorAll("[data-loc]").forEach((b) => b.addEventListener("click", async () => {
      try { ctx.toast(await invoke<string>("cmd_open_location", { path: (b as HTMLElement).dataset["loc"]! }), "ok"); } catch (e) { ctx.toast(String(e), "err"); }
    }));
  };
  await load();
}

// ── Services ──────────────────────────────────────────────
export async function renderServices(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.services)}</h1><p class="sub">Start / Stop / Restart / Startup type. Critical services require explicit override — never blindly disabled.</p>
    <div class="toolbar"><input type="text" id="q" placeholder="${esc(t.searchPh)}" style="min-width:280px"/><button class="btn" data-act="go">${esc(t.refresh)}</button>
    <button class="btn" data-act="sys">${icon("service")} Open Services (services.msc)</button></div>
    <div class="card" id="s"><p class="muted">${esc(t.loading)}</p></div>`;
  const box = el.querySelector("#s") as HTMLElement;
  const load = async () => {
    const q = (el.querySelector("#q") as HTMLInputElement).value || null;
    const list = await invoke<{ name: string; display: string; status: string; startup: string; description: string }[]>("cmd_list_services", { query: q }).catch(() => []);
    box.innerHTML = table(["Service", t.status, t.startupType, ""], (list || []).map((s) => [
      `<b>${esc(s.display)}</b><br><span class="mono muted">${esc(s.name)}</span><br><span class="muted">${esc(s.description)}</span>`,
      badge(s.status), esc(s.startup),
      `<button class="btn" data-n="${esc(s.name)}" data-a="start">${esc(t.start)}</button> <button class="btn" data-n="${esc(s.name)}" data-a="stop">${esc(t.stop)}</button> <button class="btn" data-n="${esc(s.name)}" data-a="restart">${esc(t.restart)}</button><br><br><button class="btn" data-s="${esc(s.name)}">Startup…</button>`,
    ]));
    box.querySelectorAll("[data-n]").forEach((b) => b.addEventListener("click", async () => {
      const n = (b as HTMLElement).dataset["n"]!;
      const a = (b as HTMLElement).dataset["a"]!;
      const go = async (confirmed: boolean) => {
        try { ctx.toast(await invoke<string>("cmd_service_action", { name: n, action: a, confirmedCritical: confirmed }), "ok"); load(); }
        catch (e) {
          const msg = String(e);
          if (msg.includes("CRITICAL_GUARD")) {
            if (await ctx.confirm("Disable Windows Service", `Service: ${n}\n\nPotential impact: ${msg.replace("CRITICAL_GUARD:", "").trim()}\n\nOnly proceed if you understand the consequences.`, a, true)) go(true);
          } else ctx.toast(msg, "err");
        }
      };
      if (!await ctx.confirm(`${a} service`, `Service: ${n}\nPotential impact: may affect Windows functionality.`, a)) return;
      go(false);
    }));
    box.querySelectorAll("[data-s]").forEach((b) => b.addEventListener("click", async () => {
      const n = (b as HTMLElement).dataset["s"]!;
      const mode = prompt("Startup type: Automatic / Manual / Disabled", "Manual");
      if (!mode) return;
      const go = async (confirmed: boolean) => {
        try { ctx.toast(await invoke<string>("cmd_set_service_startup", { name: n, startup: mode, confirmedCritical: confirmed }), "ok"); load(); }
        catch (e) {
          const msg = String(e);
          if (msg.includes("CRITICAL_GUARD")) {
            if (await ctx.confirm("Change critical service", msg.replace("CRITICAL_GUARD:", "").trim(), "Change", true)) go(true);
          } else ctx.toast(msg, "err");
        }
      };
      if (!await ctx.confirm("Change startup type", `Service: ${n}\nNew type: ${mode}\nPotential impact: may affect boot or functionality.`, "Change")) return;
      go(false);
    }));
  };
  await load();
  el.querySelector('[data-act="go"]')?.addEventListener("click", load);
  el.querySelector('[data-act="sys"]')?.addEventListener("click", async () => {
    try { await invoke("cmd_open_location", { path: "C:\\Windows\\System32\\services.msc" }); } catch (e) { ctx.toast(String(e), "err"); }
  });
}

// ── Processes ─────────────────────────────────────────────
export async function renderProcesses(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.processes)}</h1><p class="sub">${esc(t.live)} — on-demand snapshot. Sort by CPU / Memory / Disk. Per-process network requires ETW and is not shown rather than invented.</p>
    <div class="toolbar"><select id="sort"><option value="cpu">CPU</option><option value="memory">${esc(t.memory)}</option><option value="disk">${esc(t.disk)}</option><option value="name">${esc(t.name)}</option></select>
    <input type="text" id="q" placeholder="filter…" style="min-width:220px"/><button class="btn" data-act="go">${esc(t.refresh)}</button>
    <span class="muted">High CPU/RAM is shown as data with a recommendation — never labelled malware for using resources.</span></div>
    <div class="card" id="p"><p class="muted">${esc(t.loading)}</p></div>`;
  const box = el.querySelector("#p") as HTMLElement;
  const load = async () => {
    const sort = (el.querySelector("#sort") as HTMLSelectElement).value;
    const q = (el.querySelector("#q") as HTMLInputElement).value || null;
    const list = await invoke<{ pid: number; name: string; cpu: number; ram_mb: number; disk: string; path: string }[]>("cmd_list_processes", { sortBy: sort, query: q }).catch(() => []);
    box.innerHTML = table([t.name, t.pid, "CPU %", `${t.memory} MB`, `${t.disk} I/O`, t.path, ""], (list || []).map((p) => {
      const rec = p.cpu > 25 ? `<br><span class="muted">High CPU — check what it is before acting.</span>` : p.ram_mb > 500 ? `<br><span class="muted">High RAM (${p.ram_mb} MB) — consider closing it normally first.</span>` : "";
      return [`<b>${esc(p.name)}</b>${rec}`, `<span class="mono">${p.pid}</span>`, String(p.cpu), String(p.ram_mb), esc(p.disk || "—"), `<span class="mono muted">${esc(p.path)}</span>`,
        `<button class="btn danger" data-k="${p.pid}" data-n="${esc(p.name)}">${esc(t.terminate)}</button> <button class="btn" data-o="${esc(p.path)}">${esc(t.openLoc)}</button> <a class="btn" href="https://www.google.com/search?q=${encodeURIComponent(p.name + " process")}" target="_blank" rel="noreferrer">${esc(t.searchOnline)}</a>`];
    }));
    box.querySelectorAll("[data-k]").forEach((b) => b.addEventListener("click", async () => {
      const pid = Number((b as HTMLElement).dataset["k"]);
      const go = async (force: boolean) => {
        try { ctx.toast(await invoke<string>("cmd_kill_process", { pid, forceCritical: force }), "ok"); load(); }
        catch (e) {
          const msg = String(e);
          if (msg.includes("critical") && await ctx.confirm("Terminate system process", msg + "\n\nTerminating can crash Windows.", t.terminate, true)) go(true);
          else if (!msg.includes("critical")) ctx.toast(msg, "err");
        }
      };
      if (!await ctx.confirm("Terminate process", `PID ${pid}. Prefer closing the app normally first.`, t.terminate, true)) return;
      go(false);
    }));
    box.querySelectorAll("[data-o]").forEach((b) => b.addEventListener("click", async () => {
      try { ctx.toast(await invoke<string>("cmd_open_location", { path: (b as HTMLElement).dataset["o"]! }), "ok"); } catch (e) { ctx.toast(String(e), "err"); }
    }));
  };
  await load();
  el.querySelector('[data-act="go"]')?.addEventListener("click", load);
}

// ── Applications ──────────────────────────────────────────
export async function renderApps(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.apps)}</h1><p class="sub">Installed / Optional / Potentially Unwanted / Suspicious / Unknown — with the reason for each recommendation.</p>
    <div class="toolbar"><input type="text" id="q" placeholder="filter…" style="min-width:260px"/><button class="btn" data-act="go">${esc(t.refresh)}</button></div>
    <div class="card" id="a"><p class="muted">${esc(t.loading)}</p></div>`;
  const box = el.querySelector("#a") as HTMLElement;
  const load = async () => {
    const q = (el.querySelector("#q") as HTMLInputElement).value || null;
    const list = await invoke<{ name: string; publisher: string; version: string; install_path: string; uninstall: string; classification: string; reason: string }[]>("cmd_list_apps", { query: q }).catch(() => []);
    box.innerHTML = table([t.name, t.publisher, "Class", t.reason, ""], (list || []).map((a) => [
      `<b>${esc(a.name)}</b><br><span class="muted mono">${esc(a.version)} · ${esc(a.install_path)}</span>`, esc(a.publisher || "—"), badge(a.classification), esc(a.reason),
      a.uninstall ? `<button class="btn" data-u="${esc(a.uninstall)}">Uninstall…</button>` : "",
    ]));
    box.querySelectorAll("[data-u]").forEach((b) => b.addEventListener("click", async () => {
      try { ctx.showDetail("Uninstall", [["Vendor uninstaller", (b as HTMLElement).dataset["u"]!]]); ctx.toast(await invoke<string>("cmd_uninstall_hint", { uninstall: (b as HTMLElement).dataset["u"]! }), "ok"); } catch (e) { ctx.toast(String(e), "err"); }
    }));
  };
  await load();
  el.querySelector('[data-act="go"]')?.addEventListener("click", load);
}

// ── Privacy ───────────────────────────────────────────────
export async function renderPrivacy(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.winPrivacy)}</h1><p class="sub">Telemetry · Diagnostics · Advertising ID · Location · Background Apps · Permissions · Windows Search · Activity History. No promise of complete privacy; edition-dependent settings are marked.</p><div class="card" id="p"><p class="muted">${esc(t.loading)}</p></div>`;
  const box = el.querySelector("#p") as HTMLElement;
  const load = async () => {
    const list = await invoke<{ id: string; name: string; category: string; state: string; detail: string }[]>("cmd_list_privacy").catch(() => []);
    box.innerHTML = table([t.name, "Category", t.status, ""], (list || []).map((p) => [
      `<b>${esc(p.name)}</b><br><span class="mono muted">${esc(p.detail)}</span>`, esc(p.category), badge(p.state),
      `<button class="btn" data-id="${esc(p.id)}" data-off="${p.state === "On" ? 1 : 0}">${p.state === "On" ? esc(t.disable) : esc(t.enable)}</button>`,
    ]));
    box.querySelectorAll("[data-id]").forEach((b) => b.addEventListener("click", async () => {
      const id = (b as HTMLElement).dataset["id"]!;
      const off = (b as HTMLElement).dataset["off"] === "1";
      if (!await ctx.confirm("Change privacy setting", `${id} → ${off ? "Off" : "On"}. Takes effect after sign-out on some editions.`, t.apply)) return;
      try { ctx.toast(await invoke<string>("cmd_set_privacy", { id, off }), "ok"); load(); } catch (e) { ctx.toast(String(e), "err"); }
    }));
  };
  await load();
}

// ── WinUtil ───────────────────────────────────────────────
export async function renderWinutil(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.winutilTitle)}</h1><p class="sub">Official tool — system-wide changes, requires Administrator. Nothing runs automatically.</p><p class="muted">${esc(t.loading)}</p>`;
  const info = await invoke<Record<string, unknown>>("cmd_winutil_info").catch(() => null);
  el.innerHTML = `
    <h1>${esc(t.winutilTitle)}</h1><p class="sub">${esc(info?.["description"] as string || "")}</p>
    <div class="card"><h3>Official Tool</h3>
      <dl class="kv"><dt>Command</dt><dd class="mono">${esc(String(info?.["command"] || ""))}</dd>
      <dt>Source URL</dt><dd class="mono">${esc(String(info?.["source_url"] || ""))}</dd>
      <dt>Review</dt><dd class="mono">${esc(String(info?.["review_url"] || ""))}</dd>
      <dt>Admin</dt><dd>${(info?.["is_admin"] as boolean) ? badge("Administrator") : badge("Limited Mode")}</dd></dl>
      <p class="muted">${esc(String(info?.["warning"] || ""))}</p>
      <div class="btn-row">
        <a class="btn" href="${esc(String(info?.["review_url"] || "https://github.com/ChrisTitusTech/winutil"))}" target="_blank" rel="noreferrer">${icon("file")} ${esc(t.reviewSrc)}</a>
        <button class="btn" data-act="copy">Copy command</button>
      </div>
      <label><input type="checkbox" id="ack"/> I reviewed the source, understand it downloads remote code, and want to run it with Administrator privileges.</label>
      <div class="btn-row"><button class="btn primary" data-act="run">${icon("scan")} ${esc(t.openWinutil)}</button></div>
    </div>
    <div class="card"><h3>Same task types, implemented natively in Open Windows (no third-party code copied)</h3>
      <p>${esc(((info?.["categories"]) as string[] || []).join(" · "))}</p>
      <p class="muted">Use System Optimizer (Tweaks), Applications (Install/Remove guidance), System Repair (Troubleshooting), Windows Update, and Settings for Configuration.</p></div>
    <div class="card"><h3>Output</h3><pre class="out" id="wout">Not run.</pre></div>`;
  el.querySelector('[data-act="copy"]')?.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(String(info?.["command"] || "")); ctx.toast("Copied.", "ok"); } catch { ctx.toast("Copy failed.", "err"); }
  });
  el.querySelector('[data-act="run"]')?.addEventListener("click", async () => {
    if (!(el.querySelector("#ack") as HTMLInputElement).checked) { ctx.toast("Please confirm you reviewed the source first.", "err"); return; }
    if (!await ctx.confirm("Launch WinUtil", `Exact command:\n${info?.["command"]}\nSource: ${info?.["source_url"]}\n\nIt downloads remote code and needs Administrator. Output and errors will be shown.`, t.openWinutil, true)) return;
    (el.querySelector("#wout") as HTMLElement).textContent = "Running… (WinUtil opens its own UI; console output appears here)";
    try { (el.querySelector("#wout") as HTMLElement).textContent = await invoke<string>("cmd_winutil_launch", { confirmed: true }); ctx.toast("WinUtil finished.", "ok"); }
    catch (e) { (el.querySelector("#wout") as HTMLElement).textContent = String(e); ctx.toast(String(e), "err"); }
  });
}

// ── Repair ────────────────────────────────────────────────
export function renderRepair(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.repair)}</h1><p class="sub">System File Checker · DISM health checks · image repair · update diagnostics. Real command output — success is never fabricated.</p>
    <div class="btn-row"><button class="btn" data-act="restore">${icon("shield")} ${esc(t.createRestore)}</button></div>
    <div class="grid c2">
      ${[["sfc-check", t.sfcCheck, "What it does: verifies protected files (read-only). Requires Administrator."], ["dism-check", t.dismCheck, "What it does: checks the Windows image (read-only). Requires Administrator."], ["sfc-repair", t.sfcRepair, "Impact: repairs files, may take 15+ min. Requires Administrator."], ["dism-repair", t.dismRepair, "Impact: repairs the image from Windows Update. Requires Administrator."]].map(([a, label, d]) => `<div class="card"><h3>${esc(label)}</h3><p class="muted">${esc(d)}</p><button class="btn" data-act="${a}">Run</button></div>`).join("")}
    </div>
    <h2>Results</h2><div class="card"><pre class="out" id="rout">No operation run yet.</pre></div>`;
  const run = async (cmd: string) => {
    (el.querySelector("#rout") as HTMLElement).textContent = "Running… (this can take a long time for repairs)";
    try { (el.querySelector("#rout") as HTMLElement).textContent = await invoke<string>(cmd); ctx.toast("Completed — see output.", "ok"); }
    catch (e) { (el.querySelector("#rout") as HTMLElement).textContent = String(e); ctx.toast(String(e), "err"); }
  };
  el.querySelector('[data-act="sfc-check"]')?.addEventListener("click", () => run("cmd_sfc_check"));
  el.querySelector('[data-act="dism-check"]')?.addEventListener("click", () => run("cmd_dism_check"));
  el.querySelector('[data-act="sfc-repair"]')?.addEventListener("click", async () => { if (await ctx.confirm("Repair system files", "Runs sfc /scannow. May take 15+ minutes.", t.confirmL, true)) run("cmd_sfc_repair"); });
  el.querySelector('[data-act="dism-repair"]')?.addEventListener("click", async () => { if (await ctx.confirm("Repair Windows image", "Runs DISM /RestoreHealth. Uses Windows Update unless a local source is configured.", t.confirmL, true)) run("cmd_dism_repair"); });
  el.querySelector('[data-act="restore"]')?.addEventListener("click", async () => {
    try { ctx.toast(await invoke<string>("cmd_create_restore_point", { description: "Open Windows pre-repair checkpoint" }), "ok"); } catch (e) { ctx.toast(String(e), "err"); }
  });
}

// ── Storage ───────────────────────────────────────────────
export function renderStorage(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.storageAn)}</h1><p class="sub">Actual disk usage with drill-down. Deletion always warns and never removes system paths automatically.</p>
    <div class="toolbar"><input type="text" id="path" value="C:\\" style="min-width:220px"/><button class="btn primary" data-act="an">${esc(t.analyze)}</button></div>
    <div class="card" id="s"></div>
    <h2>${esc(t.dupFinder)}</h2>
    <div class="toolbar"><input type="text" id="dpath" value="C:\\Users" style="min-width:220px"/><input type="number" id="min" value="1024" min="1" style="width:110px"/><span class="muted">min KB</span><button class="btn" data-act="dup">Find (hashing)</button></div>
    <div class="card" id="d"><p class="muted">Duplicate detection hashes same-size files (SHA-256). Nothing is deleted automatically.</p></div>`;
  (el.querySelector('[data-act="an"]') as HTMLButtonElement).addEventListener("click", async () => {
    const path = (el.querySelector("#path") as HTMLInputElement).value;
    const box = el.querySelector("#s") as HTMLElement;
    box.innerHTML = `<p class="muted">${esc(t.loading)}</p>`;
    try {
      const r = await invoke<{ base: string; categories: Record<string, string>; entries: { path: string; bytes: number; human: string; files: number }[] }>("cmd_analyze_storage", { path });
      box.innerHTML = `<p>Categories — ${Object.entries(r.categories).map(([k, v]) => `<b>${esc(k)}</b>: ${esc(v)}`).join(" · ")}</p>` +
        table(["Folder", "Size", "Files", ""], r.entries.map((e) => [`<span class="mono">${esc(e.path)}</span>`, esc(e.human), String(e.files), `<button class="btn" data-drill="${esc(e.path)}">Open</button>`]));
      box.querySelectorAll("[data-drill]").forEach((b) => b.addEventListener("click", () => { (el.querySelector("#path") as HTMLInputElement).value = (b as HTMLElement).dataset["drill"]!; (el.querySelector('[data-act="an"]') as HTMLButtonElement).click(); }));
    } catch (e) { box.innerHTML = `<p>${esc(String(e))}</p>`; }
  });
  (el.querySelector('[data-act="dup"]') as HTMLButtonElement).addEventListener("click", async () => {
    const box = el.querySelector("#d") as HTMLElement;
    box.innerHTML = `<p class="muted">${esc(t.loading)}</p>`;
    try {
      const groups = await invoke<{ hash: string; size: number; human: string; files: string[] }[]>("cmd_find_duplicates", { path: (el.querySelector("#dpath") as HTMLInputElement).value, minKb: Number((el.querySelector("#min") as HTMLInputElement).value || 1024) });
      box.innerHTML = groups.length ? groups.map((g, i) => `<div style="margin-bottom:10px"><b>Group ${i + 1}</b> — ${esc(g.human)} · <span class="mono muted">${esc(g.hash.slice(0, 16))}…</span><br>${g.files.map((f) => `<label><input type="checkbox" data-f="${esc(f)}"/> <span class="mono">${esc(f)}</span></label>`).join("<br>")}</div>`).join("") + `<div class="btn-row"><button class="btn danger" data-del="1">Delete selected</button> <button class="btn" data-loc="1">Open location</button></div>` : `<p class="muted">${esc(t.noResults)}</p>`;
      box.querySelector("[data-del]")?.addEventListener("click", async () => {
        const paths = [...box.querySelectorAll("input[data-f]:checked")].map((c) => (c as HTMLInputElement).dataset["f"]!);
        if (!paths.length) { ctx.toast("Select files first.", "err"); return; }
        if (!await ctx.confirm("Delete duplicates", `${paths.length} file(s):\n${paths.slice(0, 10).join("\n")}${paths.length > 10 ? "\n…" : ""}\n\nKeep at least one copy of each group.`, t.remove, true)) return;
        try { ctx.toast(await invoke<string>("cmd_delete_files", { paths }), "ok"); } catch (e) { ctx.toast(String(e), "err"); }
      });
    } catch (e) { box.innerHTML = `<p>${esc(String(e))}</p>`; }
  });
}

// ── Network ───────────────────────────────────────────────
export function renderNetwork(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.networkL)}</h1><p class="sub">Interfaces · IP · DNS · Ping · Route · Connectivity. Export available.</p>
    <div class="btn-row"><button class="btn primary" data-act="info">${esc(t.refresh)}</button><button class="btn" data-act="conn">${esc(t.connectivity)}</button><button class="btn" data-act="exp">${esc(t.export)}</button></div>
    <div class="card"><pre class="out" id="nout">Press Refresh.</pre></div>
    <div class="grid c2"><div class="card"><h3>${esc(t.ping)}</h3><div class="toolbar"><input type="text" id="ph" value="8.8.8.8"/><button class="btn" data-act="ping">${esc(t.runTest)}</button></div><pre class="out" id="pout">—</pre></div>
    <div class="card"><h3>${esc(t.dns)}</h3><div class="toolbar"><input type="text" id="dh" value="microsoft.com"/><button class="btn" data-act="dns">${esc(t.runTest)}</button></div><pre class="out" id="dout">—</pre></div></div>`;
  el.querySelector('[data-act="info"]')?.addEventListener("click", async () => {
    try {
      const r = await invoke<{ adapters: unknown; ipconfig: string; routes: string; dns: string }>("cmd_network_info");
      (el.querySelector("#nout") as HTMLElement).textContent = `ADAPTERS:\n${JSON.stringify(r.adapters, null, 2)}\n\nIPCONFIG:\n${r.ipconfig}\n\nROUTES:\n${r.routes}\n\nDNS:\n${r.dns}`;
    } catch (e) { ctx.toast(String(e), "err"); }
  });
  el.querySelector('[data-act="conn"]')?.addEventListener("click", async () => {
    try { (el.querySelector("#nout") as HTMLElement).textContent = await invoke<string>("cmd_connectivity_test"); } catch (e) { ctx.toast(String(e), "err"); }
  });
  el.querySelector('[data-act="exp"]')?.addEventListener("click", async () => {
    try { ctx.toast(`Saved: ${await invoke<string>("cmd_export_diagnostics")}`, "ok"); } catch (e) { ctx.toast(String(e), "err"); }
  });
  el.querySelector('[data-act="ping"]')?.addEventListener("click", async () => {
    try { (el.querySelector("#pout") as HTMLElement).textContent = await invoke<string>("cmd_ping", { host: (el.querySelector("#ph") as HTMLInputElement).value }); } catch (e) { ctx.toast(String(e), "err"); }
  });
  el.querySelector('[data-act="dns"]')?.addEventListener("click", async () => {
    try { (el.querySelector("#dout") as HTMLElement).textContent = await invoke<string>("cmd_dns_lookup", { host: (el.querySelector("#dh") as HTMLInputElement).value }); } catch (e) { ctx.toast(String(e), "err"); }
  });
}

// ── Updates / Reports / Settings ──────────────────────────
export async function renderUpdates(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.updates)}</h1><p class="sub">Read-only. Open Windows never disables Windows Update.</p><div class="card" id="u"><p class="muted">${esc(t.loading)}</p></div>`;
  try {
    const r = await invoke<{ status: string; restart_required: boolean; recent: unknown; policy: string }>("cmd_update_status");
    (el.querySelector("#u") as HTMLElement).innerHTML = `<dl class="kv"><dt>Status</dt><dd>${esc(r.status)}</dd><dt>Restart required</dt><dd>${r.restart_required ? badge("Yes") : badge("No")}</dd><dt>Policy</dt><dd class="muted">${esc(r.policy)}</dd></dl><pre class="out">${esc(JSON.stringify(r.recent, null, 2))}</pre>`;
  } catch (e) { (el.querySelector("#u") as HTMLElement).innerHTML = `<p>${esc(String(e))}</p>`; }
}

export async function renderReports(el: HTMLElement, ctx: Ctx) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.reports)}</h1><p class="sub">${esc(t.sysReport)} — TXT / JSON / HTML. No sensitive contents included.</p>
    <div class="btn-row"><button class="btn" data-f="txt">${esc(t.genReport)} (TXT)</button><button class="btn" data-f="json">${esc(t.genReport)} (JSON)</button><button class="btn" data-f="html">${esc(t.genReport)} (HTML)</button></div>
    <h2>${esc(t.beforeAfter)}</h2><div class="card" id="ba"><p class="muted">${esc(t.loading)}</p></div>`;
  el.querySelectorAll("[data-f]").forEach((b) => b.addEventListener("click", async () => {
    try { ctx.toast(`Saved: ${await invoke<string>("cmd_generate_health_report", { format: (b as HTMLElement).dataset["f"]! })}`, "ok"); } catch (e) { ctx.toast(String(e), "err"); }
  }));
  try {
    const ba = await invoke<Record<string, unknown>>("cmd_get_before_after");
    (el.querySelector("#ba") as HTMLElement).innerHTML = `<dl class="kv">${Object.entries(ba).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("")}</dl><p class="muted">Only counted changes are shown. No performance improvement is estimated.</p>`;
  } catch (e) { (el.querySelector("#ba") as HTMLElement).innerHTML = `<p>${esc(String(e))}</p>`; }
}

export async function renderSettings(el: HTMLElement, ctx: Ctx, state: { lang: string; theme: string; onSettings: () => void }) {
  const { t } = ctx;
  el.innerHTML = `<h1>${esc(t.settings)}</h1><p class="sub">${esc(t.general)} · ${esc(t.language)} · ${esc(t.theme)} · ${esc(t.scanPrefs)} · ${esc(t.notif)}</p>
    <div class="grid c2">
    <div class="card"><h3>${esc(t.general)}</h3>
      <label>${esc(t.language)}<br><select id="lang"><option value="en">English</option><option value="ar">العربية</option></select></label><br><br>
      <label>${esc(t.theme)}<br><select id="theme"><option value="system">${esc(t.systemT)}</option><option value="dark">${esc(t.dark)}</option><option value="light">${esc(t.light)}</option></select></label><br><br>
      <label>${esc(t.scanPrefs)}<br><select id="scan"><option>Quick</option><option>Standard</option><option>Deep</option></select></label><br><br>
      <label><input type="checkbox" id="notif"/> ${esc(t.notif)}</label><br>
      <label><input type="checkbox" id="rtm"/> Real-time monitor (off by default, efficient APIs)</label><br><br>
      <button class="btn primary" data-act="save">Save</button></div>
    <div class="card"><h3>${esc(t.changeHist)}</h3><div id="hist"><p class="muted">${esc(t.loading)}</p></div></div></div>
    <h2>${esc(t.logs)}</h2><div class="card"><div class="btn-row"><button class="btn" data-act="exp">${esc(t.exportLogs)}</button><button class="btn" data-act="clr">${esc(t.clearLogs)}</button><button class="btn" data-act="rl">Refresh</button></div><div id="logs"></div></div>`;
  const s = await invoke<{ language: string; theme: string; scan_default: string; notifications: boolean; realtime_monitor: boolean }>("cmd_get_settings").catch(() => ({ language: state.lang, theme: state.theme, scan_default: "Quick", notifications: true, realtime_monitor: false }));
  (el.querySelector("#lang") as HTMLSelectElement).value = s.language;
  (el.querySelector("#theme") as HTMLSelectElement).value = s.theme;
  (el.querySelector("#scan") as HTMLSelectElement).value = s.scan_default;
  (el.querySelector("#notif") as HTMLInputElement).checked = s.notifications;
  (el.querySelector("#rtm") as HTMLInputElement).checked = s.realtime_monitor;
  el.querySelector('[data-act="save"]')?.addEventListener("click", async () => {
    try {
      await invoke("cmd_set_settings", { settings: { language: (el.querySelector("#lang") as HTMLSelectElement).value, theme: (el.querySelector("#theme") as HTMLSelectElement).value, scan_default: (el.querySelector("#scan") as HTMLSelectElement).value, notifications: (el.querySelector("#notif") as HTMLInputElement).checked, realtime_monitor: (el.querySelector("#rtm") as HTMLInputElement).checked, cleanup_confirm: true } });
      ctx.toast("Settings saved.", "ok"); state.onSettings();
    } catch (e) { ctx.toast(String(e), "err"); }
  });
  const loadHist = async () => {
    const h = await invoke<{ id: string; date: string; category: string; change: string; previous_value: string; new_value: string; reversible: boolean }[]>("cmd_get_change_history").catch(() => []);
    (el.querySelector("#hist") as HTMLElement).innerHTML = table(["Date", "Change", "Prev → New", ""], (h || []).slice(0, 50).map((x) => [
      `<span class="mono">${esc(x.date)}</span><br><span class="muted">${esc(x.category)}</span>`, esc(x.change), `<span class="mono">${esc(x.previous_value)} → ${esc(x.new_value)}</span>`,
      x.reversible ? `<button class="btn" data-u="${esc(x.id)}">${esc(t.undo)}</button>` : `<span class="muted">—</span>`,
    ]));
    el.querySelectorAll("[data-u]").forEach((b) => b.addEventListener("click", async () => {
      try { ctx.toast(await invoke<string>("cmd_undo_change", { id: (b as HTMLElement).dataset["u"]! }), "ok"); loadHist(); } catch (e) { ctx.toast(String(e), "err"); }
    }));
  };
  const loadLogs = async () => {
    const l = await invoke<{ timestamp: string; action: string; detail: string; result: string }[]>("cmd_get_logs").catch(() => []);
    (el.querySelector("#logs") as HTMLElement).innerHTML = table(["Time", "Action", "Result"], (l || []).slice(0, 100).map((x) => [`<span class="mono">${esc(x.timestamp)}</span>`, `<b>${esc(x.action)}</b><br><span class="muted">${esc(x.detail)}</span>`, esc(x.result)]));
  };
  await Promise.all([loadHist(), loadLogs()]);
  el.querySelector('[data-act="exp"]')?.addEventListener("click", async () => { try { ctx.toast(`Saved: ${await invoke<string>("cmd_export_logs")}`, "ok"); } catch (e) { ctx.toast(String(e), "err"); } });
  el.querySelector('[data-act="clr"]')?.addEventListener("click", async () => { if (await ctx.confirm("Clear logs", "Application logs will be deleted.", t.clearLogs, true)) { try { ctx.toast(await invoke<string>("cmd_clear_logs"), "ok"); loadLogs(); } catch (e) { ctx.toast(String(e), "err"); } } });
  el.querySelector('[data-act="rl"]')?.addEventListener("click", loadLogs);
}
