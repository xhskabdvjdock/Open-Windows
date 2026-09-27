// Tauri invoke wrapper — works inside Tauri; outside (browser dev) returns honest errors.
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";

declare global {
  interface Window { __TAURI__?: unknown; __TAURI_INTERNALS__?: unknown; }
}

export const isTauri =
  typeof window !== "undefined" && (!!window.__TAURI__ || !!window.__TAURI_INTERNALS__);

export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri) throw new Error("Backend requires the desktop app (Tauri). Run via `tauri dev`.");
  return tauriInvoke<T>(cmd, args as never);
}

export async function onEvent<T>(name: string, cb: (payload: T) => void): Promise<() => void> {
  if (!isTauri) return () => {};
  const un = await tauriListen<T>(name, (e) => cb(e.payload));
  return un;
}

export function fmtElapsed(s: number): string {
  const m = Math.floor(s / 60).toString().padStart(2, "0");
  const ss = Math.floor(s % 60).toString().padStart(2, "0");
  const h = Math.floor(s / 3600);
  return h > 0 ? `${String(h).padStart(2, "0")}:${m}:${ss}` : `${m}:${ss}`;
}

export function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}
