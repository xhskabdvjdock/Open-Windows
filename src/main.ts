// Open Windows shell: sidebar, topbar, router, search, dialogs, themes, i18n RTL.
import { invoke, onEvent, esc, isTauri } from "./api";
import { icon } from "./icons";
import { dicts, type Lang } from "./i18n";
import {
  renderOverview, renderSecurity, renderScan, updateScanLive, renderThreats,
  renderCleanup, renderOptimizer, renderStartup, renderServices, renderProcesses,
  renderApps, renderPrivacy, renderWinutil, renderRepair, renderStorage,
  renderNetwork, renderUpdates, renderReports, renderSettings, type Ctx,
} from "./pages";

type Route = "overview" | "security" | "scan" | "threats" | "cleanup" | "optimizer" | "startup" | "services" | "processes" | "apps" | "privacy" | "winutil" | "repair" | "storage" | "network" | "updates" | "reports" | "settings";

const state = { lang: "en" as Lang, theme: "system", route: "overview" as Route, collapsed: false, isAdmin: false, welcomed: localStorage.getItem("ow Welcomed") === "1" };
const t = () => dicts[state.lang];

const NAV: { sec: string; items: { id: Route; ic: string }[] }[] = [
  { sec: "", items: [{ id: "overview", ic: "overview" }] },
  { sec: "security", items: [{ id: "security", ic: "shield" }, { id: "scan", ic: "scan" }, { id: "threats", ic: "threat" }] },
  { sec: "optimization", items: [{ id: "cleanup", ic: "clean" }, { id: "optimizer", ic: "gauge" }, { id: "startup", ic: "startup" }, { id: "services", ic: "service" }, { id: "processes", ic: "proc" }, { id: "apps", ic: "app" }] },
  { sec: "privacy", items: [{ id: "privacy", ic: "lock" }] },
  { sec: "tools", items: [{ id: "winutil", ic: "win" }, { id: "repair", ic: "repair" }, { id: "storage", ic: "disk" }, { id: "network", ic: "net" }, { id: "updates", ic: "update" }, { id: "reports", ic: "report" }] },
  { sec: "settings", items: [{ id: "settings", ic: "settings" }] },
];

function routeLabel(r: Route): string {
  const d = t() as unknown as Record<string, string>;
  const map: Record<Route, string> = { overview: d.overview, security: d.security, scan: d.systemScan, threats: d.threats, cleanup: d.cleanup, optimizer: d.optimizer, startup: d.startup, services: d.services, processes: d.processes, apps: d.apps, privacy: d.winPrivacy, winutil: d.winutil, repair: d.repair, storage: d.storage, network: d.network, updates: d.updates, reports: d.reports, settings: d.settings };
  return map[r];
}

export function toast(msg: string, kind: "" | "ok" | "err" = "") {
  const box = document.getElementById("toasts")!;
  const d = document.createElement("div");
  d.className = `toast ${kind}`;
  d.textContent = msg.slice(0, 600);
  box.appendChild(d);
  setTimeout(() => d.remove(), 5200);
}

export function confirmDlg(title: string, body: string, okLabel: string, danger = false): Promise<boolean> {
  return new Promise((resolve) => {
    const root = document.getElementById("dialog-root")!;
    const ov = document.createElement("div");
    ov.className = "overlay";
    ov.innerHTML = `<div class="dialog" role="alertdialog"><h3>${esc(title)}</h3><pre class="out">${esc(body)}</pre>
      <div class="btn-row"><button class="btn" data-c="0">${esc(t().cancelL)}</button><button class="btn ${danger ? "danger" : "primary"}" data-c="1">${esc(okLabel)}</button></div></div>`;
    root.appendChild(ov);
    ov.querySelector('[data-c="0"]')?.addEventListener("click", () => { ov.remove(); resolve(false); });
    ov.querySelector('[data-c="1"]')?.addEventListener("click", () => { ov.remove(); resolve(true); });
    ov.addEventListener("click", (e) => { if (e.target === ov) { ov.remove(); resolve(false); } });
  });
}

export function showDetail(title: string, rows: [string, string][], actionsHtml = "") {
  const root = document.getElementById("dialog-root")!;
  const ov = document.createElement("div");
  ov.className = "overlay";
  ov.innerHTML = `<div class="dialog"><h3>${esc(title)}</h3><dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join("")}</dl>${actionsHtml}<div class="btn-row"><button class="btn" data-c="0">Close</button></div></div>`;
  root.appendChild(ov);
  ov.querySelector('[data-c="0"]')?.addEventListener("click", () => ov.remove());
  ov.addEventListener("click", (e) => { if (e.target === ov) ov.remove(); });
}

const ctx: Ctx = { t: t(), toast, confirm: confirmDlg, showDetail, refreshTopbar: () => void 0 };

function applyTheme() {
  let th = state.theme;
  if (th === "system") th = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.dataset.theme = th;
}

function applyLang() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === "ar" ? "rtl" : "ltr";
  ctx.t = t();
}

function renderSidebar() {
  const sb = document.getElementById("sidebar")!;
  sb.classList.toggle("collapsed", state.collapsed);
  const d = t() as unknown as Record<string, string>;
  sb.innerHTML = `<div class="brand"><span class="mark">W</span>${state.collapsed ? "" : `<span class="lbl">${esc(d.app)}</span>`}</div>` +
    NAV.map((g) => `${g.sec && !state.collapsed ? `<div class="nav-sec">${esc((d as Record<string, string>)[g.sec] || g.sec)}</div>` : ""}` +
      g.items.map((it) => `<button class="nav-item ${state.route === it.id ? "active" : ""}" data-r="${it.id}" title="${esc(routeLabel(it.id))}">${icon(it.ic)}${state.collapsed ? "" : `<span class="lbl">${esc(routeLabel(it.id))}</span>`}</button>`).join("")).join("");
  sb.querySelectorAll("[data-r]").forEach((b) => b.addEventListener("click", () => navigate((b as HTMLElement).dataset["r"] as Route)));
}

function renderTopbar() {
  const tb = document.getElementById("topbar")!;
  const d = t();
  tb.innerHTML = `
    <button class="icon-btn" id="collapse" title="Collapse sidebar">${icon("chev")}</button>
    <button class="icon-btn" id="search-btn" title="Search (Ctrl+K)">${icon("search")}</button>
    <span class="muted" style="font-size:12px">${esc(routeLabel(state.route))}</span>
    <span class="spacer"></span>
    <span class="pill-admin ${state.isAdmin ? "yes" : "no"}">${state.isAdmin ? esc(d.admin) : esc(d.limited)}</span>
    ${state.isAdmin ? "" : `<button class="btn" id="elevate">${esc(d.restartAdmin)}</button>`}
    <select id="lang-sel" title="${esc(d.language)}"><option value="en">EN</option><option value="ar">عربي</option></select>
    <select id="theme-sel" title="${esc(d.theme)}"><option value="system">${esc(d.systemT)}</option><option value="dark">${esc(d.dark)}</option><option value="light">${esc(d.light)}</option></select>`;
  (tb.querySelector("#collapse") as HTMLButtonElement).onclick = () => { state.collapsed = !state.collapsed; renderSidebar(); };
  (tb.querySelector("#search-btn") as HTMLButtonElement).onclick = openSearch;
  (tb.querySelector("#lang-sel") as HTMLSelectElement).value = state.lang;
  (tb.querySelector("#theme-sel") as HTMLSelectElement).value = state.theme;
  (tb.querySelector("#lang-sel") as HTMLSelectElement).onchange = async (e) => {
    state.lang = (e.target as HTMLSelectElement).value as Lang;
    applyLang(); renderSidebar(); renderTopbar(); await navigate(state.route);
    try { const s = await invoke<Record<string, unknown>>("cmd_get_settings"); await invoke("cmd_set_settings", { settings: { ...(s as object), language: state.lang } }); } catch { /* offline-safe */ }
  };
  (tb.querySelector("#theme-sel") as HTMLSelectElement).onchange = async (e) => {
    state.theme = (e.target as HTMLSelectElement).value;
    applyTheme(); renderTopbar();
    try { const s = await invoke<Record<string, unknown>>("cmd_get_settings"); await invoke("cmd_set_settings", { settings: { ...(s as object), theme: state.theme } }); } catch { /* ignore */ }
  };
  tb.querySelector("#elevate")?.addEventListener("click", async () => {
    try { toast(await invoke<string>("cmd_restart_as_admin"), "ok"); } catch (e) { toast(String(e), "err"); }
  });
  ctx.refreshTopbar = renderTopbar;
}

async function navigate(r: Route) {
  const w = window as unknown as { __owLive?: number };
  if (w.__owLive) { clearInterval(w.__owLive); w.__owLive = undefined; }
  state.route = r;
  renderSidebar(); renderTopbar();
  const page = document.getElementById("page")!;
  page.scrollTop = 0;
  try {
    switch (r) {
      case "overview": await renderOverview(page, ctx); break;
      case "security": await renderSecurity(page, ctx); break;
      case "scan": renderScan(page, ctx); break;
      case "threats": await renderThreats(page, ctx); break;
      case "cleanup": await renderCleanup(page, ctx); break;
      case "optimizer": await renderOptimizer(page, ctx); break;
      case "startup": await renderStartup(page, ctx); break;
      case "services": await renderServices(page, ctx); break;
      case "processes": await renderProcesses(page, ctx); break;
      case "apps": await renderApps(page, ctx); break;
      case "privacy": await renderPrivacy(page, ctx); break;
      case "winutil": await renderWinutil(page, ctx); break;
      case "repair": renderRepair(page, ctx); break;
      case "storage": renderStorage(page, ctx); break;
      case "network": renderNetwork(page, ctx); break;
      case "updates": await renderUpdates(page, ctx); break;
      case "reports": await renderReports(page, ctx); break;
      case "settings": await renderSettings(page, ctx, { lang: state.lang, theme: state.theme, onSettings: async () => { await loadSettings(); applyLang(); applyTheme(); renderSidebar(); renderTopbar(); } }); break;
    }
  } catch (e) {
    page.innerHTML = `<h1>${esc(routeLabel(r))}</h1><p>${esc(String(e))}</p>`;
  }
}

// Global search
function openSearch() {
  const ov = document.getElementById("search-overlay")!;
  const d = t();
  const all: Route[] = ["overview", "security", "scan", "threats", "cleanup", "optimizer", "startup", "services", "processes", "apps", "privacy", "winutil", "repair", "storage", "network", "updates", "reports", "settings"];
  ov.classList.remove("hidden");
  ov.innerHTML = `<div class="search-box"><input type="text" id="sq" placeholder="${esc(d.searchPh)}"/><div class="search-list" id="sl"></div></div>`;
  const input = ov.querySelector("#sq") as HTMLInputElement;
  const list = ov.querySelector("#sl") as HTMLElement;
  const draw = (q: string) => {
    const f = all.filter((r) => routeLabel(r).toLowerCase().includes(q.toLowerCase()));
    list.innerHTML = f.map((r) => `<button data-r="${r}">${icon("search")}${esc(routeLabel(r))}</button>`).join("") || `<p class="muted" style="padding:10px">${esc(d.noResults)}</p>`;
    list.querySelectorAll("[data-r]").forEach((b) => b.addEventListener("click", () => { ov.classList.add("hidden"); navigate((b as HTMLElement).dataset["r"] as Route); }));
  };
  draw("");
  input.oninput = () => draw(input.value);
  input.focus();
  ov.onclick = (e) => { if (e.target === ov) ov.classList.add("hidden"); };
}

async function loadSettings() {
  try {
    const s = await invoke<{ language: string; theme: string }>("cmd_get_settings");
    if (s.language === "ar" || s.language === "en") state.lang = s.language as Lang;
    if (["dark", "light", "system"].includes(s.theme)) state.theme = s.theme;
  } catch { /* defaults */ }
  try { state.isAdmin = await invoke<boolean>("cmd_is_admin"); } catch { state.isAdmin = false; }
}

async function welcome() {
  if (state.welcomed) return;
  const d = t();
  const ok = await confirmDlg(d.welcome, `${d.welcomeSub}\n\n[${d.startCheck}]`, d.startCheck);
  localStorage.setItem("ow Welcomed", "1");
  state.welcomed = true;
  if (ok) navigate("overview");
}

async function boot() {
  await loadSettings();
  applyLang(); applyTheme();
  renderSidebar(); renderTopbar();
  if (!isTauri) {
    // Honest fail-fast: in a plain browser tab there is no Rust backend, so
    // every reading would (correctly) be "Unable to determine". Say so
    // explicitly instead of showing a wall of unable-to-determine cards.
    const d = t();
    const page = document.getElementById("page")!;
    page.innerHTML = `<div class="card" style="border-inline-start:3px solid var(--bad);max-width:720px">
      <h1>${esc(d.backendTitle)}</h1><pre class="out">${esc(d.backendBody)}</pre></div>`;
    toast(d.backendTitle, "err");
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openSearch(); }
    });
    return;
  }
  await navigate("overview");
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openSearch(); }
  });
  matchMedia("(prefers-color-scheme: light)").addEventListener?.("change", () => { if (state.theme === "system") applyTheme(); });
  await onEvent<Record<string, unknown>>("scan-progress", (p) => updateScanLive(p as never as Parameters<typeof updateScanLive>[0]));
  welcome();
}

boot();
