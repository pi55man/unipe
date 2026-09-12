/** Tiny store so flows/s can update without re-rendering the alert workbench. */

type Listener = () => void;

let rate = 0;
const listeners = new Set<Listener>();

export function getFlowsPerSec(): number {
  return rate;
}

export function setFlowsPerSecStore(next: number): void {
  if (Math.abs(rate - next) < 1) return;
  rate = next;
  listeners.forEach((l) => l());
}

export function subscribeFlowsPerSec(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
