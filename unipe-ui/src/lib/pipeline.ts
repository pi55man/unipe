import type { Alert } from "./alerts";

export type PipeState = "up" | "idle" | "stale";

export type PipelineSnapshot = {
  alerts: Alert[];
  alert_count: number;
  alerts_path: string;
  alerts_stamp: string;
  alerts_unchanged: boolean;
  status: Record<string, unknown> | null;
  status_path: string;
  entities: unknown | null;
  entities_path: string;
  entities_stamp: string;
  entities_unchanged: boolean;
  socket_path: string;
  exporter_up: boolean;
  engine_up: boolean;
  flows_per_sec: number;
  tap_one_directional: boolean;
  tap_message: string;
  live: boolean;
  polled_at: number;
};

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function readPipeline(
  previousStamp?: string,
  previousEntitiesStamp?: string,
  loadEntities = false,
): Promise<PipelineSnapshot | null> {
  if (!isTauri()) return null;
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<PipelineSnapshot>("read_pipeline", {
    previousStamp: previousStamp ?? null,
    previousEntitiesStamp: previousEntitiesStamp ?? null,
    loadEntities,
  });
}

export function pipeState(up: boolean, liveContext: boolean): PipeState {
  if (up) return "up";
  if (liveContext) return "stale";
  return "idle";
}
