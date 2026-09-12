import type { Alert } from "./alerts";

export type SuppressKind = "dst_ip" | "src_ip" | "subtype";

export type SuppressRule = {
  id: string;
  kind: SuppressKind;
  value: string;
  reason: string;
  created_at: number;
};

export function makeSuppressRule(
  kind: SuppressKind,
  value: string,
  reason: string,
): SuppressRule {
  return {
    id: `${kind}:${value}:${Date.now()}`,
    kind,
    value,
    reason: reason.trim() || "(no reason given)",
    created_at: Date.now() / 1000,
  };
}

export function alertMatchesSuppress(alert: Alert, rule: SuppressRule): boolean {
  if (rule.kind === "dst_ip") return Boolean(alert.dst_ip) && alert.dst_ip === rule.value;
  if (rule.kind === "src_ip") return Boolean(alert.src_ip) && alert.src_ip === rule.value;
  return alert.subtype === rule.value;
}

export function filterSuppressed(
  alerts: Alert[],
  rules: SuppressRule[],
): Alert[] {
  if (!rules.length) return alerts;
  return alerts.filter(
    (a) => !rules.some((r) => alertMatchesSuppress(a, r)),
  );
}
