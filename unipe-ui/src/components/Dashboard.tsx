"use client";

import {
  memo,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
  startTransition,
} from "react";

import { AlertDetail } from "@/components/AlertDetail";
import { AlertStream, type StreamView } from "@/components/AlertStream";
import { ContextStrip } from "@/components/ContextStrip";
import { EntityDossierPanel } from "@/components/EntityDossier";
import { ReplayBar, type ReplayMode } from "@/components/ReplayBar";
import { StatusBar } from "@/components/StatusBar";
import { TopBar } from "@/components/TopBar";
import { parseJsonl } from "@/lib/aggregates";
import type { Alert } from "@/lib/alerts";
import {
  dedupeAlerts,
  rowKey,
  sortAlerts,
  THREAT_CLASSES,
} from "@/lib/alerts";
import { healthFromFileReplay, healthFromStatus } from "@/lib/coverage";
import {
  dossierForIp,
  parseEntities,
  type EntityDossier,
} from "@/lib/entities";
import { setFlowsPerSecStore, getFlowsPerSec } from "@/lib/flowRateStore";
import { setHealthView } from "@/lib/healthStore";
import {
  alertsToCsv,
  buildIncidents,
  downloadText,
  incidentsToCsv,
  suppressionsToCsv,
} from "@/lib/incidents";
import { latencyStats } from "@/lib/latency";
import { MOCK_ALERTS } from "@/lib/mock-alerts";
import {
  isTauri,
  pipeState,
  readPipeline,
  type PipeState,
} from "@/lib/pipeline";
import {
  filterSuppressed,
  makeSuppressRule,
  type SuppressKind,
  type SuppressRule,
} from "@/lib/suppress";

const POLL_MS = 2000;
const DISPLAY_CAP = 40;
/** wall-clock mapping for replay; React only commits when alert count changes */
const REPLAY_TICK_MS = 50;

function upperBoundIndex(sortedAsc: Alert[], t: number): number {
  let lo = 0;
  let hi = sortedAsc.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (sortedAsc[mid]!.timestamp <= t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function alertsFingerprint(list: Alert[]): string {
  if (!list.length) return "0";
  const a = list[0]!;
  const b = list[list.length - 1]!;
  return `${list.length}|${rowKey(a)}|${rowKey(b)}`;
}

export function Dashboard() {
  const [alerts, setAlerts] = useState<Alert[]>(MOCK_ALERTS);
  const [sourceLabel, setSourceLabel] = useState("mock schema samples");
  const [selected, setSelected] = useState<Alert | null>(MOCK_ALERTS[0] ?? null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [classFilter, setClassFilter] = useState("all");
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [destFilter, setDestFilter] = useState("");
  const [pinnedIds, setPinnedIds] = useState<string[]>([]);
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(() => new Set());
  const dismissedRef = useRef(dismissedIds);
  dismissedRef.current = dismissedIds;
  const alertsStampRef = useRef("");
  const entitiesStampRef = useRef("");
  const alertsFpRef = useRef("");
  const entityIpRef = useRef<string | null>(null);
  const rateSampleRef = useRef<{ flows: number; at: number } | null>(null);
  const [live, setLive] = useState(false);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(false);
  pausedRef.current = paused;
  const [exporter, setExporter] = useState<PipeState>("idle");
  const [engine, setEngine] = useState<PipeState>("idle");
  const [manualOverride, setManualOverride] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const [view, setView] = useState<StreamView>("alerts");
  const [suppressions, setSuppressions] = useState<SuppressRule[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(
    null,
  );
  const [engineReplay, setEngineReplay] = useState(false);
  const [replayActive, setReplayActive] = useState(false);
  /** exclusive end index into alertsAsc — how many alerts are revealed */
  const [replayCount, setReplayCount] = useState(0);
  const replayCountRef = useRef(0);
  replayCountRef.current = replayCount;
  /** exact scrubber time — play resumes from here after seek */
  const replaySeekTRef = useRef<number | null>(null);
  const [replayPlaying, setReplayPlaying] = useState(false);
  const [replaySpeed, setReplaySpeed] = useState(1);
  /** status stays off the React tree — SensorHealth reads healthStore */
  const pipelineStatusRef = useRef<Record<string, unknown> | null>(null);
  const healthOptsRef = useRef({
    replayActive: false,
    engineReplay: false,
    live: false,
  });
  const [entities, setEntities] = useState<Record<string, EntityDossier>>({});
  const [entityIp, setEntityIp] = useState<string | null>(null);
  entityIpRef.current = entityIp;

  const publishHealth = useCallback(() => {
    setHealthView(
      healthFromStatus(pipelineStatusRef.current, healthOptsRef.current),
    );
  }, []);

  const noteFlowsIn = useCallback((flowsIn: number) => {
    const now = performance.now();
    const prev = rateSampleRef.current;
    if (!prev || flowsIn < prev.flows) {
      rateSampleRef.current = { flows: flowsIn, at: now };
      setFlowsPerSecStore(0);
      return;
    }
    const dt = (now - prev.at) / 1000;
    if (dt < 0.4) return;
    const rate = (flowsIn - prev.flows) / dt;
    rateSampleRef.current = { flows: flowsIn, at: now };
    setFlowsPerSecStore(rate);
  }, []);

  const applyAlerts = useCallback((next: Alert[], label: string) => {
    const gone = dismissedRef.current;
    const sorted = dedupeAlerts(sortAlerts(next)).filter(
      (a) => !gone.has(rowKey(a)),
    );
    const fp = alertsFingerprint(sorted);
    if (fp === alertsFpRef.current) {
      setSourceLabel((prev) => (prev === label ? prev : label));
      return;
    }
    alertsFpRef.current = fp;
    startTransition(() => {
      setAlerts(sorted);
      setSourceLabel(label);
      setSelected((prev) => {
        if (!prev) return sorted[0] ?? null;
        const prevId = rowKey(prev);
        const still = sorted.find((a) => rowKey(a) === prevId);
        return still ?? sorted[0] ?? null;
      });
      setPinnedIds((prev) => {
        if (!prev.length) return prev;
        const keep = prev.filter((id) => sorted.some((a) => rowKey(a) === id));
        return keep.length === prev.length ? prev : keep;
      });
    });
  }, []);

  useEffect(() => {
    if (isTauri()) return;
    let cancelled = false;
    fetch("/alerts.jsonl")
      .then(async (res) => {
        if (!res.ok) return;
        const text = await res.text();
        const parsed = parseJsonl(text);
        if (!cancelled && parsed.length) {
          applyAlerts(parsed, "public/alerts.jsonl");
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [applyAlerts]);

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    let timer = 0;
    let inFlight = false;

    const tick = async () => {
      if (cancelled || manualOverride || pausedRef.current) return;
      if (typeof document !== "undefined" && document.hidden) return;
      if (inFlight) return;
      inFlight = true;
      try {
        const snap = await readPipeline(
          alertsStampRef.current || undefined,
          entitiesStampRef.current || undefined,
          Boolean(entityIpRef.current),
        );
        if (cancelled || !snap) return;

        const nextLive = snap.live;
        const nextExporter = pipeState(snap.exporter_up, snap.live);
        const nextEngine = pipeState(snap.engine_up, snap.live);

        setLive((prev) => (prev === nextLive ? prev : nextLive));
        setExporter((prev) => (prev === nextExporter ? prev : nextExporter));
        setEngine((prev) => (prev === nextEngine ? prev : nextEngine));
        if (snap.status) {
          pipelineStatusRef.current = snap.status;
          publishHealth();
        }
        const flowsIn = Number(snap.status?.flows_in ?? 0);
        if (Number.isFinite(flowsIn) && flowsIn >= 0) {
          noteFlowsIn(flowsIn);
        } else {
          // fallback if status has no counter yet
          setFlowsPerSecStore(snap.flows_per_sec);
        }
        setEngineReplay(Boolean(snap.status?.replay));

        entitiesStampRef.current = snap.entities_stamp;
        if (
          entityIpRef.current &&
          !snap.entities_unchanged &&
          snap.entities
        ) {
          setEntities(parseEntities(snap.entities));
        }

        alertsStampRef.current = snap.alerts_stamp;
        if (snap.alerts_unchanged) return;

        if (snap.alerts.length) {
          applyAlerts(snap.alerts, snap.alerts_path);
        } else if (snap.engine_up || snap.exporter_up) {
          setSourceLabel(snap.alerts_path);
          setAlerts([]);
          setSelected(null);
          alertsFpRef.current = "";
        }
      } catch {
        if (!cancelled) {
          setLive(false);
          setExporter("idle");
          setEngine("stale");
        }
      } finally {
        inFlight = false;
      }
    };

    tick();
    timer = window.setInterval(tick, POLL_MS);

    const onVis = () => {
      if (!document.hidden) void tick();
    };
    document.addEventListener("visibilitychange", onVis);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [applyAlerts, manualOverride, noteFlowsIn, publishHealth]);

  // live/engine health from status poll; file replay publishes its own view below
  useEffect(() => {
    healthOptsRef.current = {
      replayActive: false,
      engineReplay,
      live: live && !manualOverride,
    };
    if (!replayActive) publishHealth();
  }, [replayActive, engineReplay, live, manualOverride, publishHealth]);

  const onLoadFile = useCallback(
    (file: File) => {
      const reader = new FileReader();
      reader.onload = () => {
        const text = String(reader.result ?? "");
        const parsed = parseJsonl(text);
        if (!parsed.length) {
          window.alert(
            "no alert records found — expected alerts JSONL (one alert object per line)",
          );
          return;
        }
        let tMin = parsed[0]!.timestamp;
        let tMax = parsed[0]!.timestamp;
        for (const a of parsed) {
          if (a.timestamp < tMin) tMin = a.timestamp;
          if (a.timestamp > tMax) tMax = a.timestamp;
        }
        setManualOverride(true);
        setLive(false);
        setDismissedIds(new Set());
        setPinnedIds([]);
        setSuppressions([]);
        alertsStampRef.current = "";
        setReplayActive(true);
        setReplayCount(1);
        setReplayPlaying(true);
        setReplaySpeed(1);
        applyAlerts(parsed, `replay: ${file.name}`);
        setStatusMessage(`replay loaded · ${parsed.length} alerts`);
      };
      reader.readAsText(file);
    },
    [applyAlerts],
  );

  const onResetAlerts = useCallback(() => {
    const n = alerts.length;
    if (!n && getFlowsPerSec() === 0) {
      setStatusMessage("nothing to reset");
      return;
    }
    const ok = window.confirm(
      `Clear the console session?\n\n• ${n} alert${n === 1 ? "" : "s"} will be dismissed\n• flows/s counter resets to 0\n\nNew live alerts can still appear afterward.`,
    );
    if (!ok) return;

    setDismissedIds((prev) => {
      const next = new Set(prev);
      for (const a of alerts) next.add(rowKey(a));
      return next;
    });
    setPinnedIds([]);
    setAlerts([]);
    setSelected(null);
    setSelectedIncidentId(null);
    setSuppressions([]);
    setFlowsPerSecStore(0);
    rateSampleRef.current = null;
    alertsFpRef.current = "";
    if (replayActive) {
      setReplayActive(false);
      setReplayPlaying(false);
      setManualOverride(false);
      alertsStampRef.current = "";
    }
    setStatusMessage("session reset");
  }, [alerts, replayActive]);

  const classOptions = useMemo(() => {
    const present = new Set(alerts.map((a) => a.threat_class));
    return THREAT_CLASSES.filter((c) => present.has(c));
  }, [alerts]);

  const pinnedSet = useMemo(() => new Set(pinnedIds), [pinnedIds]);

  const alertsAsc = useMemo(() => {
    if (!replayActive) return null;
    return [...alerts].sort((a, b) => a.timestamp - b.timestamp);
  }, [alerts, replayActive]);

  const replayBounds = useMemo(() => {
    if (!replayActive || !alertsAsc?.length) return { min: 0, max: 0 };
    return {
      min: alertsAsc[0]!.timestamp,
      max: alertsAsc[alertsAsc.length - 1]!.timestamp,
    };
  }, [alertsAsc, replayActive]);

  const sessionAlerts = useMemo(() => {
    if (!replayActive || !alertsAsc) return alerts;
    return alertsAsc.slice(0, replayCount);
  }, [alerts, alertsAsc, replayActive, replayCount]);

  // sensor tab tracks the scrubber during file replay
  useEffect(() => {
    if (!replayActive) return;
    setHealthView(healthFromFileReplay(sessionAlerts, alerts.length));
  }, [replayActive, sessionAlerts, alerts.length]);

  const replayCursor = useMemo(() => {
    if (!replayActive || !alertsAsc?.length) return 0;
    if (replayCount <= 0) return alertsAsc[0]!.timestamp;
    const idx = Math.min(replayCount, alertsAsc.length) - 1;
    return alertsAsc[idx]!.timestamp;
  }, [alertsAsc, replayActive, replayCount]);

  const activeAlerts = useMemo(
    () => filterSuppressed(sessionAlerts, suppressions),
    [sessionAlerts, suppressions],
  );

  // charts / latency can lag a frame behind during scrub — keeps list responsive
  const deferredActive = useDeferredValue(activeAlerts);
  const latStats = useMemo(
    () => latencyStats(deferredActive),
    [deferredActive],
  );

  const mode: ReplayMode = replayActive
    ? "replay"
    : live && !manualOverride
      ? "live"
      : sourceLabel.includes("mock")
        ? "mock"
        : "offline";

  // advance by alert timestamps — React only updates when a new alert appears
  useEffect(() => {
    if (!replayActive || !replayPlaying || !alertsAsc?.length) return;
    const tMin = alertsAsc[0]!.timestamp;
    const tMax = alertsAsc[alertsAsc.length - 1]!.timestamp;
    const span = Math.max(tMax - tMin, 0.001);
    const durationAt1x = Math.min(Math.max(span, 8), 45);

    // Prefer the last scrub position; if already at/past the end, loop from start.
    let pendingT =
      replaySeekTRef.current ??
      (replayCountRef.current > 0
        ? alertsAsc[
            Math.min(replayCountRef.current, alertsAsc.length) - 1
          ]!.timestamp
        : tMin);
    replaySeekTRef.current = null;
    if (
      replayCountRef.current >= alertsAsc.length ||
      pendingT >= tMax
    ) {
      pendingT = tMin;
      setReplayCount(alertsAsc.length ? 1 : 0);
    }

    let cancelled = false;
    let last = performance.now();
    let lastUi = 0;
    let raf = 0;
    const step = (now: number) => {
      if (cancelled) return;
      const dt = (now - last) / 1000;
      last = now;
      pendingT += (span / durationAt1x) * replaySpeed * dt;
      if (pendingT >= tMax) {
        setReplayCount(alertsAsc.length);
        setReplayPlaying(false);
        return;
      }
      if (now - lastUi >= REPLAY_TICK_MS) {
        lastUi = now;
        const nextCount = upperBoundIndex(alertsAsc, pendingT);
        if (nextCount !== replayCountRef.current) {
          setReplayCount(nextCount);
        }
      }
      raf = window.requestAnimationFrame(step);
    };
    raf = window.requestAnimationFrame(step);
    return () => {
      cancelled = true;
      window.cancelAnimationFrame(raf);
    };
  }, [replayActive, replayPlaying, replaySpeed, alertsAsc]);

  // when opening a dossier, force one entities.json fetch on the next poll
  useEffect(() => {
    if (entityIp) entitiesStampRef.current = "";
    else setEntities({});
  }, [entityIp]);

  const filtered = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase();
    const list = activeAlerts.filter((a) => {
      if (severityFilter !== "all" && a.severity !== severityFilter) return false;
      if (classFilter !== "all" && a.threat_class !== classFilter) return false;
      if (destFilter === "(aggregate)") {
        if (a.dst_ip) return false;
      } else if (destFilter && a.dst_ip !== destFilter) {
        return false;
      }
      if (!q) return true;
      return (
        a.message.toLowerCase().includes(q) ||
        a.flow_id.toLowerCase().includes(q) ||
        a.src_ip.toLowerCase().includes(q) ||
        a.dst_ip.toLowerCase().includes(q) ||
        a.subtype.toLowerCase().includes(q)
      );
    });

    if (!pinnedIds.length) return list;
    const byId = new Map(list.map((a) => [rowKey(a), a]));
    const top: Alert[] = [];
    for (const id of pinnedIds) {
      const hit = byId.get(id);
      if (hit) {
        top.push(hit);
        byId.delete(id);
      }
    }
    return [...top, ...byId.values()];
  }, [
    activeAlerts,
    severityFilter,
    classFilter,
    deferredQuery,
    destFilter,
    pinnedIds,
  ]);

  // always build so the incidents tab badge stays live
  const incidents = useMemo(() => buildIncidents(filtered), [filtered]);

  const selectedIncident = useMemo(
    () => incidents.find((i) => i.id === selectedIncidentId) ?? null,
    [incidents, selectedIncidentId],
  );

  const visible = useMemo(
    () => filtered.slice(0, DISPLAY_CAP),
    [filtered],
  );

  const selectedId = selected ? rowKey(selected) : null;

  const onDelete = useCallback((alert: Alert) => {
    const id = rowKey(alert);
    setDismissedIds((prev) => {
      const next = new Set(prev);
      next.add(id);
      return next;
    });
    setPinnedIds((prev) => prev.filter((p) => p !== id));
    setAlerts((prev) => {
      const next = prev.filter((a) => rowKey(a) !== id);
      setSelected((cur) => {
        if (!cur || rowKey(cur) !== id) return cur;
        const idx = prev.findIndex((a) => rowKey(a) === id);
        return next[Math.min(idx, next.length - 1)] ?? next[0] ?? null;
      });
      return next;
    });
    setStatusMessage("alert deleted");
  }, []);

  const onTogglePin = useCallback((alert: Alert) => {
    const id = rowKey(alert);
    setPinnedIds((prev) => {
      if (prev.includes(id)) return prev.filter((p) => p !== id);
      return [id, ...prev];
    });
  }, []);

  const onSelect = useCallback((alert: Alert) => {
    setSelected(alert);
    setSelectedIncidentId(null);
  }, []);

  const onSelectIncident = useCallback((incident: { id: string; alerts: Alert[] }) => {
    setSelectedIncidentId(incident.id);
    setSelected(incident.alerts[0] ?? null);
  }, []);

  const onSuppress = useCallback((alert: Alert, kind: SuppressKind) => {
    const value =
      kind === "dst_ip"
        ? alert.dst_ip
        : kind === "src_ip"
          ? alert.src_ip
          : alert.subtype;
    if (!value) {
      setStatusMessage("nothing to suppress");
      return;
    }
    const reason = window.prompt(
      `Suppress ${kind} “${value}” for this session.\nReason (shown in CSV audit):`,
      "benign / lab noise",
    );
    if (reason === null) return;
    const rule = makeSuppressRule(kind, value, reason);
    setSuppressions((prev) => [...prev, rule]);
    setStatusMessage(`suppressed ${kind} ${value}`);
  }, []);

  const onRemoveSuppress = useCallback((id: string) => {
    setSuppressions((prev) => prev.filter((r) => r.id !== id));
    setStatusMessage("suppression removed");
  }, []);

  const onSelectRelative = useCallback(
    (delta: number) => {
      if (!visible.length) return;
      const idx = selectedId
        ? visible.findIndex((a) => rowKey(a) === selectedId)
        : -1;
      const nextIdx = Math.max(
        0,
        Math.min(visible.length - 1, (idx < 0 ? 0 : idx) + delta),
      );
      setSelected(visible[nextIdx] ?? null);
      setSelectedIncidentId(null);
    },
    [visible, selectedId],
  );

  const onClearFilters = useCallback(() => {
    setSeverityFilter("all");
    setClassFilter("all");
    setDestFilter("");
    setQuery("");
  }, []);

  const onToggleDestFilter = useCallback((dstIp: string) => {
    setDestFilter((prev) => (prev === dstIp ? "" : dstIp));
  }, []);

  const onChartDestFilter = useCallback((dstIp: string) => {
    setDestFilter((prev) => (prev === dstIp ? "" : dstIp));
    setQuery("");
  }, []);

  const onPlayPause = useCallback(() => {
    setReplayPlaying((p) => {
      if (p) return false;
      // At the end, play means restart from the beginning.
      if (
        alertsAsc?.length &&
        replayCountRef.current >= alertsAsc.length
      ) {
        replaySeekTRef.current = alertsAsc[0]!.timestamp;
        setReplayCount(1);
      }
      return true;
    });
  }, [alertsAsc]);

  const onSeek = useCallback(
    (t: number) => {
      setReplayPlaying(false);
      replaySeekTRef.current = t;
      if (!alertsAsc?.length) {
        setReplayCount(0);
        return;
      }
      setReplayCount(upperBoundIndex(alertsAsc, t));
    },
    [alertsAsc],
  );

  const onSkipEnd = useCallback(() => {
    setReplayPlaying(false);
    replaySeekTRef.current = null;
    setReplayCount(alertsAsc?.length ?? 0);
  }, [alertsAsc]);

  const onRestart = useCallback(() => {
    if (!alertsAsc?.length) {
      setReplayCount(0);
      setReplayPlaying(false);
      return;
    }
    replaySeekTRef.current = alertsAsc[0]!.timestamp;
    setReplayCount(1);
    setReplayPlaying(true);
  }, [alertsAsc]);

  const onTogglePause = useCallback(() => {
    setPaused((p) => !p);
  }, []);

  const onResumeLive = useCallback(() => {
    setManualOverride(false);
    setReplayActive(false);
    setReplayPlaying(false);
    alertsStampRef.current = "";
    entitiesStampRef.current = "";
    setStatusMessage("resumed live");
  }, []);

  const onSelectIp = useCallback((ip: string) => {
    if (!ip || ip === "*" || ip === "(aggregate)") return;
    setEntityIp(ip);
    entitiesStampRef.current = "";
    setStatusMessage(`entity ${ip}`);
  }, []);

  const selectedEntity = useMemo(() => {
    if (!entityIp) return null;
    const fromEngine = entities[entityIp];
    if (fromEngine && fromEngine.alert_count > 0) return fromEngine;
    const fromAlerts = dossierForIp(entityIp, alerts);
    if (fromEngine && fromAlerts) {
      return {
        ...fromEngine,
        ...fromAlerts,
        partners: { ...fromAlerts.partners, ...fromEngine.partners },
        ports: { ...fromAlerts.ports, ...fromEngine.ports },
        domains: { ...fromAlerts.domains, ...fromEngine.domains },
        alerts: fromAlerts.alerts.length
          ? fromAlerts.alerts
          : fromEngine.alerts,
        alert_count: Math.max(fromEngine.alert_count, fromAlerts.alert_count),
      };
    }
    return fromEngine ?? fromAlerts;
  }, [entityIp, entities, alerts]);

  const onExportJsonl = useCallback(() => {
    if (!filtered.length) {
      setStatusMessage("nothing to export");
      return;
    }
    const body = filtered.map((a) => JSON.stringify(a)).join("\n") + "\n";
    downloadText(
      `unipe-alerts-${Date.now()}.jsonl`,
      body,
      "application/x-ndjson",
    );
    setStatusMessage(`exported ${filtered.length} alerts (jsonl)`);
  }, [filtered]);

  const onExportCsv = useCallback(() => {
    if (!filtered.length && !suppressions.length) {
      setStatusMessage("nothing to export");
      return;
    }
    const stamp = Date.now();
    const incs = buildIncidents(filtered);
    downloadText(
      `unipe-incidents-${stamp}.csv`,
      incidentsToCsv(incs),
      "text/csv;charset=utf-8",
    );
    downloadText(
      `unipe-alerts-${stamp}.csv`,
      alertsToCsv(filtered, incs),
      "text/csv;charset=utf-8",
    );
    if (suppressions.length) {
      downloadText(
        `unipe-suppressions-${stamp}.csv`,
        suppressionsToCsv(suppressions),
        "text/csv;charset=utf-8",
      );
    }
    setStatusMessage(
      `exported ${incs.length} incidents + ${filtered.length} alerts as csv`,
    );
  }, [filtered, suppressions]);

  return (
    <div className="flex h-screen min-h-[720px] flex-col overflow-hidden">
      <TopBar
        alertCount={activeAlerts.length}
        onResetAlerts={onResetAlerts}
      />
      <ReplayBar
        mode={mode}
        playing={replayPlaying}
        speed={replaySpeed}
        cursor={replayCursor}
        tMin={replayBounds.min}
        tMax={replayBounds.max}
        shown={sessionAlerts.length}
        total={alerts.length}
        onPlayPause={onPlayPause}
        onSpeed={setReplaySpeed}
        onSeek={onSeek}
        onSkipEnd={onSkipEnd}
        onRestart={onRestart}
      />

      <div className="flex min-h-0 flex-1">
        <AlertStream
          view={view}
          onView={setView}
          alerts={visible}
          incidents={incidents}
          totalMatching={filtered.length}
          selectedId={selectedId}
          selectedIncidentId={selectedIncidentId}
          pinnedIds={pinnedSet}
          suppressions={suppressions}
          onSelect={onSelect}
          onSelectIncident={onSelectIncident}
          onSelectRelative={onSelectRelative}
          onDelete={onDelete}
          onTogglePin={onTogglePin}
          onSuppress={onSuppress}
          onRemoveSuppress={onRemoveSuppress}
          onFilterSeverity={setSeverityFilter}
          onFilterClass={setClassFilter}
          onFilterDest={setDestFilter}
          severityFilter={severityFilter}
          classFilter={classFilter}
          destFilter={destFilter}
          query={query}
          onSeverityFilter={setSeverityFilter}
          onClassFilter={setClassFilter}
          onDestFilter={onToggleDestFilter}
          onQuery={setQuery}
          onClearFilters={onClearFilters}
          onExportJsonl={onExportJsonl}
          onExportCsv={onExportCsv}
          classOptions={classOptions}
          statusMessage={statusMessage}
        />
        {entityIp ? (
          <EntityDossierPanel
            ip={entityIp}
            entity={selectedEntity}
            onSelectIp={onSelectIp}
            onClose={() => setEntityIp(null)}
          />
        ) : (
          <AlertDetail
            alert={view === "incidents" ? null : selected}
            incident={view === "incidents" ? selectedIncident : null}
            pinned={selectedId ? pinnedSet.has(selectedId) : false}
            onSelectIp={onSelectIp}
          />
        )}
      </div>

      <ContextStrip
        alerts={deferredActive}
        classFilter={classFilter}
        destFilter={destFilter}
        onClassFilter={setClassFilter}
        onDestFilter={onChartDestFilter}
      />

      <StatusBar
        exporter={exporter}
        engine={engine}
        ui="up"
        mode={mode}
        paused={paused}
        sourceLabel={sourceLabel}
        engineReplay={engineReplay && !replayActive}
        latency={latStats}
        onLoadFile={onLoadFile}
        onTogglePause={onTogglePause}
        onResumeLive={
          manualOverride || replayActive ? onResumeLive : undefined
        }
      />
    </div>
  );
}
