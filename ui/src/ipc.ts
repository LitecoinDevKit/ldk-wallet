/**
 * Tauri IPC, unless this page is the screenshot fixture.
 * A packaged app always has `__TAURI_INTERNALS__` and never enters the fixture.
 */

type InvokeArgs = Record<string, unknown> | undefined;

export async function invoke<T>(cmd: string, args?: InvokeArgs): Promise<T> {
  if (shotsRequested() && !inTauri()) {
    const { shotsInvoke } = await import("./shots-fixture");
    return shotsInvoke<T>(cmd);
  }
  const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
  return tauriInvoke<T>(cmd, args);
}

function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function shotsRequested(): boolean {
  if (typeof window === "undefined") return false;
  return new URLSearchParams(window.location.search).has("shots");
}
