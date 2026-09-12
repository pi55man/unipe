/** Human-readable evidence labels and value formatting. */

export type EvidenceRow = {
  key: string;
  label: string;
  value: string;
};

const LABELS: Record<string, { label: string; format?: (v: unknown) => string }> = {
  unique_sources: { label: "distinct source IPs" },
  unique_ports: { label: "distinct destination ports" },
  ephemeral_ports_ignored: { label: "ephemeral ports ignored" },
  unique_hosts: { label: "distinct hosts" },
  flow_count: { label: "flows in window" },
  udp_flows: { label: "UDP flows" },
  tcp_flows: { label: "TCP flows" },
  packet_rate: {
    label: "packet rate",
    format: (v) => `${Number(v).toFixed(0)} pkt/s`,
  },
  byte_rate: {
    label: "byte rate",
    format: (v) => formatBytes(Number(v)) + "/s",
  },
  avg_packets: { label: "avg packets per flow" },
  spoofed_short_flows: {
    label: "looks like spoofed short flows",
    format: (v) => (v ? "yes" : "no"),
  },
  syn_count: { label: "SYN flags seen" },
  ack_count: { label: "ACK flags seen" },
  syn_only_fraction: {
    label: "SYN-only fraction",
    format: (v) => pct(Number(v)),
  },
  mean_interval_s: {
    label: "mean check-in interval",
    format: (v) => `${Number(v).toFixed(1)} s`,
  },
  jitter_ratio: {
    label: "interval jitter",
    format: (v) => pct(Number(v)),
  },
  interval_count: { label: "intervals observed" },
  dns_ml_probability: {
    label: "DGA model score",
    format: (v) => pct(Number(v)),
  },
  bigram_familiarity: {
    label: "letter-pair familiarity",
    format: (v) => pct(Number(v)),
  },
  normalized_entropy: {
    label: "name entropy",
    format: (v) => Number(v).toFixed(3),
  },
  qname: { label: "DNS query name" },
  qname_len: { label: "query name length" },
  label_count: { label: "DNS labels" },
  parent_domain: { label: "parent domain" },
  port_sample: {
    label: "sample ports",
    format: (v) => (Array.isArray(v) ? v.join(", ") : String(v)),
  },
  host_sample: {
    label: "sample hosts",
    format: (v) => (Array.isArray(v) ? v.join(", ") : String(v)),
  },
  ttl: { label: "IP TTL" },
  protocol: {
    label: "IP protocol",
    format: (v) => protoName(Number(v)),
  },
  signals: {
    label: "fallback signals",
    format: (v) => (Array.isArray(v) ? v.join(", ") : String(v)),
  },
  outbound_bytes: {
    label: "outbound bytes",
    format: (v) => formatBytes(Number(v)),
  },
  inbound_bytes: {
    label: "inbound bytes",
    format: (v) => formatBytes(Number(v)),
  },
  dst_port: { label: "destination port" },
  packets: { label: "packets" },
  bytes: { label: "bytes", format: (v) => formatBytes(Number(v)) },
};

export function formatEvidence(
  evidence: Record<string, unknown> | undefined | null,
): EvidenceRow[] {
  if (!evidence) return [];
  return Object.entries(evidence).map(([key, raw]) => {
    const meta = LABELS[key];
    const value = meta?.format
      ? meta.format(raw)
      : typeof raw === "object"
        ? JSON.stringify(raw)
        : String(raw);
    return {
      key,
      label: meta?.label ?? humanizeKey(key),
      value,
    };
  });
}

function humanizeKey(key: string): string {
  return key.replace(/_/g, " ");
}

function pct(n: number): string {
  if (!Number.isFinite(n)) return String(n);
  if (n <= 1) return `${(n * 100).toFixed(0)}%`;
  return `${n.toFixed(0)}%`;
}

function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return String(n);
  if (n < 1024) return `${n.toFixed(0)} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

function protoName(n: number): string {
  if (n === 6) return "TCP (6)";
  if (n === 17) return "UDP (17)";
  if (n === 1) return "ICMP (1)";
  return String(n);
}
