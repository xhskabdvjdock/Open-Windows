# Open Windows

A lightweight Windows security, cleanup, optimization, diagnostics and system-management utility.

**Stack:** Rust core (system APIs, Defender, registry, SFC/DISM) + Tauri 2 (native WebView2, no Electron) + minimal TypeScript frontend (~65 KB). Idle: no background polling by default; heavy scans run in background threads with real progress events.

## Run / Build

```powershell
npm install
npm run tauri dev        # desktop dev (WebView2)
npm run build            # frontend -> dist/
npm run tauri build      # installer (requires Tauri prerequisites)
cargo check --manifest-path src-tauri/Cargo.toml
```

## Architecture

```text
src-tauri/src/
  core/        paths, logging, privileges, history, settings, restore points
  system/      overview, live stats, health report, before/after
  security/    defender, firewall, audit, vuln checks
  scanner/     Quick / Standard / Deep (real walks + Defender signals, pause/cancel)
  threats/     quarantine / remove / ignore (never auto-deletes)
  processes/   sysinfo + taskkill (critical-process guard)
  startup/     Run keys, Startup folders, logon scheduled tasks
  services/    Win32 services (critical-service guard)
  apps/        uninstall registry classification (honest, not malware-labelling)
  cleanup/     measured sizes + reviewed deletion
  optimization/registry tweaks with revert + profiles (never weakens security)
  privacy/     controllable settings only
  repairs/     SFC / DISM with captured output (admin)
  storage/     analyzer + SHA-256 duplicate finder
  network/     interfaces, ping, DNS, routes, connectivity, export
  updates/     read-only status (never disables WU)
  winutil/     safe Chris Titus Tech WinUtil interface (explicit confirm + admin)
src/
  main.ts pages.ts i18n.ts icons.ts api.ts styles.css
```

## Safety rules enforced

- Every destructive action requires confirmation; quarantine preferred over delete.
- Registry/system changes record previous values in Change History with Undo.
- Restore points offered before major operations (verified via Windows).
- No fake scores, scans, statistics or optimization percentages — only measured values; undetectable states show **Unable to determine**.
- Defender/firewall/updates are never disabled as "optimization".
- Unsigned/unfamiliar is never called malware without a trusted detection source.
- WinUtil: exact command `irm https://christitus.com/win | iex` shown with source https://github.com/ChrisTitusTech/winutil, explicit confirmation + admin required, output captured, never auto-run.
- Arabic UI uses RTL layout and Thamaniya-first typeface (`Thamaniya, IBM Plex Sans Arabic, …`).
