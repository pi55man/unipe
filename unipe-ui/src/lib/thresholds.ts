import type { Alert } from "./alerts";

/** Default detector thresholds (mirrors unipe-ai/configs/default.toml). */
const DEFAULTS = {
  udp_flood_packet_rate: 5000,
  udp_flood_min_flows: 25,
  udp_flood_max_avg_packets: 3,
  syn_flood_min_syn_ratio: 5,
  syn_flood_min_flows: 20,
  icmp_flood_packet_rate: 1000,
  icmp_flood_min_flows: 25,
  dst_packet_rate: 5000,
  min_unique_sources: 30,
  min_ports_per_dst: 20,
  min_dsts_per_port: 20,
  dga_model_threshold: 0.55,
  max_jitter_ratio: 0.15,
  min_intervals: 5,
  tunnel_min_qname_len: 60,
  min_outbound_bytes: 5_000_000,
  min_ratio: 10,
  flow_packet_rate: 5000,
} as const;

export type ThresholdCrumb = {
  label: string;
  text: string;
};

function num(evidence: Record<string, unknown>, key: string): number | null {
  const v = evidence[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function fmtRate(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return `${Math.round(n)}`;
}

/** Human breadcrumb: rule · threshold · observed. */
export function thresholdBreadcrumbs(alert: Alert): ThresholdCrumb[] {
  const e = alert.evidence ?? {};
  const crumbs: ThresholdCrumb[] = [];
  const subtype = alert.subtype;

  const push = (label: string, threshold: string, observed: string) => {
    crumbs.push({
      label,
      text: `${subtype} · threshold ${threshold} · observed ${observed}`,
    });
  };

  if (subtype === "udp_flood") {
    const pps = num(e, "packet_rate");
    const flows = num(e, "udp_flows");
    const avg = num(e, "avg_packets");
    if (pps != null) {
      push("packet rate", `${fmtRate(DEFAULTS.udp_flood_packet_rate)} pps`, `${fmtRate(pps)} pps`);
    }
    if (flows != null) {
      push("udp flows", `≥${DEFAULTS.udp_flood_min_flows}`, `${Math.round(flows)}`);
    }
    if (avg != null && e.spoofed_short_flows) {
      push(
        "avg packets/flow",
        `≤${DEFAULTS.udp_flood_max_avg_packets} (spoofed)`,
        avg.toFixed(1),
      );
    }
  } else if (subtype === "syn_flood") {
    const ratio = num(e, "syn_only_fraction") ?? num(e, "syn_count");
    const flows = num(e, "tcp_flows");
    // message often has syn/ack — evidence has syn_count/ack_count
    const syn = num(e, "syn_count");
    const ack = num(e, "ack_count");
    if (syn != null && ack != null) {
      const observed = ack > 0 ? (syn / ack).toFixed(1) : `${fmtRate(syn)} SYN`;
      push("syn/ack", `≥${DEFAULTS.syn_flood_min_syn_ratio}`, observed);
    }
    if (flows != null) {
      push("tcp flows", `≥${DEFAULTS.syn_flood_min_flows}`, `${Math.round(flows)}`);
    }
    if (ratio != null && ratio <= 1) {
      push("syn-only fraction", "≥0.70", `${(ratio * 100).toFixed(0)}%`);
    }
  } else if (subtype === "icmp_flood") {
    const pps = num(e, "packet_rate");
    if (pps != null) {
      push("packet rate", `${fmtRate(DEFAULTS.icmp_flood_packet_rate)} pps`, `${fmtRate(pps)} pps`);
    }
  } else if (subtype === "fan_in_flood") {
    const pps = num(e, "packet_rate");
    const sources = num(e, "unique_sources");
    if (pps != null) {
      push("packet rate", `${fmtRate(DEFAULTS.dst_packet_rate)} pps`, `${fmtRate(pps)} pps`);
    }
    if (sources != null) {
      push("sources", `≥${DEFAULTS.min_unique_sources}`, `${Math.round(sources)}`);
    }
  } else if (subtype === "vertical_port_scan") {
    const ports = num(e, "unique_ports");
    if (ports != null) {
      push("ports", `≥${DEFAULTS.min_ports_per_dst}`, `${Math.round(ports)}`);
    }
  } else if (subtype === "horizontal_sweep") {
    const hosts = num(e, "unique_hosts");
    if (hosts != null) {
      push("hosts", `≥${DEFAULTS.min_dsts_per_port}`, `${Math.round(hosts)}`);
    }
  } else if (subtype === "dga_domain") {
    const p = num(e, "dns_ml_probability");
    if (p != null) {
      push(
        "dns model",
        `p≥${DEFAULTS.dga_model_threshold}`,
        `p=${p.toFixed(2)}`,
      );
    }
  } else if (subtype === "periodic_beacon") {
    const jitter = num(e, "jitter_ratio");
    const intervals = num(e, "interval_count");
    if (jitter != null) {
      push(
        "jitter",
        `≤${(DEFAULTS.max_jitter_ratio * 100).toFixed(0)}%`,
        `${(jitter * 100).toFixed(0)}%`,
      );
    }
    if (intervals != null) {
      push("intervals", `≥${DEFAULTS.min_intervals}`, `${Math.round(intervals)}`);
    }
  } else if (subtype === "dns_tunnel") {
    const len = num(e, "qname_len");
    if (len != null) {
      push("qname length", `≥${DEFAULTS.tunnel_min_qname_len}`, `${Math.round(len)}`);
    }
  } else if (
    subtype === "asymmetric_outbound_volume" ||
    subtype === "bulk_exfiltration"
  ) {
    const out = num(e, "outbound_bytes");
    const ratio = num(e, "byte_ratio") ?? num(e, "ratio");
    if (out != null) {
      push(
        "outbound",
        `≥${fmtRate(DEFAULTS.min_outbound_bytes)} B`,
        `${fmtRate(out)} B`,
      );
    }
    if (ratio != null) {
      push("out/in ratio", `≥${DEFAULTS.min_ratio}`, ratio.toFixed(1));
    }
  } else if (
    subtype === "high_rate_flow" ||
    subtype === "udp_high_rate_flow" ||
    subtype === "syn_high_rate_flow" ||
    subtype === "icmp_high_rate_flow"
  ) {
    const pps = num(e, "packet_rate");
    if (pps != null) {
      push("packet rate", `${fmtRate(DEFAULTS.flow_packet_rate)} pps`, `${fmtRate(pps)} pps`);
    }
  }

  // always show confidence vs reporting gate
  crumbs.push({
    label: "confidence",
    text: `reporting gate · threshold 0.50 · observed ${alert.confidence.toFixed(2)}`,
  });

  return crumbs;
}
