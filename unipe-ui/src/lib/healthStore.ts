import type { HealthView } from "./coverage";

type Listener = () => void;

const EMPTY: HealthView = {
  mode: "offline",
  flowsIn: 0,
  flowsScored: 0,
  flowsDropped: 0,
  flowsPerSec: 0,
  capacityPerSec: 0,
  worstBatchMs: 0,
  alerts: 0,
  replayTotal: 0,
  coverageDegraded: false,
  tapOneWay: false,
  tapMessage: "",
  helloComplete: 0,
  hellos: 0,
  ja3: 0,
  ja3s: 0,
  blindSpots: [],
  sevHigh: 0,
  sevMed: 0,
  sevLow: 0,
};

let health: HealthView = EMPTY;
const listeners = new Set<Listener>();

function sameHealth(a: HealthView, b: HealthView): boolean {
  return (
    a.mode === b.mode &&
    a.flowsIn === b.flowsIn &&
    a.flowsScored === b.flowsScored &&
    a.flowsDropped === b.flowsDropped &&
    Math.abs(a.flowsPerSec - b.flowsPerSec) < 1 &&
    a.capacityPerSec === b.capacityPerSec &&
    a.worstBatchMs === b.worstBatchMs &&
    a.alerts === b.alerts &&
    a.replayTotal === b.replayTotal &&
    a.coverageDegraded === b.coverageDegraded &&
    a.helloComplete === b.helloComplete &&
    a.hellos === b.hellos &&
    a.ja3 === b.ja3 &&
    a.ja3s === b.ja3s &&
    a.sevHigh === b.sevHigh &&
    a.sevMed === b.sevMed &&
    a.sevLow === b.sevLow &&
    a.blindSpots.length === b.blindSpots.length &&
    a.blindSpots.every((s, i) => s === b.blindSpots[i])
  );
}

export function getHealthView(): HealthView {
  return health;
}

export function setHealthView(next: HealthView): void {
  if (sameHealth(health, next)) return;
  health = next;
  listeners.forEach((l) => l());
}

export function subscribeHealthView(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
