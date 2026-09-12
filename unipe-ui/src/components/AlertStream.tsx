"use client";

import {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

import type { Alert } from "@/lib/alerts";
import {
  alertDomId,
  formatTime,
  rowKey,
  severityColorVar,
  shortClass,
  threatColorVar,
} from "@/lib/alerts";
import type { Incident } from "@/lib/incidents";
import type { SuppressRule } from "@/lib/suppress";
import { ContextMenu, type MenuAction } from "@/components/ContextMenu";

export type StreamView = "alerts" | "incidents";

type Props = {
  view: StreamView;
  onView: (v: StreamView) => void;
  alerts: Alert[];
  incidents: Incident[];
  totalMatching: number;
  selectedId: string | null;
  selectedIncidentId: string | null;
  pinnedIds: Set<string>;
  suppressions: SuppressRule[];
  onSelect: (alert: Alert) => void;
  onSelectIncident: (incident: Incident) => void;
  onSelectRelative: (delta: number) => void;
  onDelete: (alert: Alert) => void;
  onTogglePin: (alert: Alert) => void;
  onSuppress: (alert: Alert, kind: "dst_ip" | "src_ip" | "subtype") => void;
  onRemoveSuppress: (id: string) => void;
  onFilterSeverity: (severity: string) => void;
  onFilterClass: (threatClass: string) => void;
  onFilterDest: (dstIp: string) => void;
  severityFilter: string;
  classFilter: string;
  destFilter: string;
  query: string;
  onSeverityFilter: (v: string) => void;
  onClassFilter: (v: string) => void;
  onDestFilter: (v: string) => void;
  onQuery: (v: string) => void;
  onClearFilters: () => void;
  onExportJsonl: () => void;
  onExportCsv: () => void;
  classOptions: string[];
  statusMessage: string;
};

type MenuState = {
  x: number;
  y: number;
  alert: Alert;
};

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, ((value - 0.5) / 0.5) * 100));
  return (
    <div className="h-1.5 w-20 overflow-hidden bg-line" aria-hidden>
      <div className="h-full bg-foreground/70" style={{ width: `${pct}%` }} />
    </div>
  );
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

const AlertRow = memo(function AlertRow({
  alert,
  selected,
  pinned,
  onSelect,
  onContextMenu,
}: {
  alert: Alert;
  selected: boolean;
  pinned: boolean;
  onSelect: (alert: Alert) => void;
  onContextMenu: (alert: Alert, x: number, y: number) => void;
}) {
  const id = rowKey(alert);
  const domId = alertDomId(id);
  return (
    <li role="none">
      <button
        type="button"
        id={domId}
        data-alert-id={id}
        role="option"
        aria-selected={selected}
        aria-label={`${alert.severity} ${shortClass(alert.threat_class)} ${alert.subtype}`}
        onClick={() => onSelect(alert)}
        onContextMenu={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onContextMenu(alert, e.clientX, e.clientY);
        }}
        className={`flex w-full items-stretch gap-0 border-b border-line text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-accent ${
          selected ? "bg-accent-soft/60" : "hover:bg-background-wash"
        }`}
        style={{ minHeight: 40 }}
      >
        <span
          className="w-[3px] shrink-0"
          style={{ background: severityColorVar(alert.severity) }}
          aria-hidden
        />
        <span
          className="ml-2.5 mt-[16px] h-2 w-2 shrink-0 rounded-full"
          style={{ background: threatColorVar(alert.threat_class) }}
          aria-hidden
        />
        <span className="grid min-w-0 flex-1 grid-cols-[5rem_8.5rem_1fr_auto] items-center gap-2.5 px-2.5 py-2.5">
          <span className="font-mono text-xs text-muted">
            {formatTime(alert.timestamp)}
          </span>
          <span className="truncate font-mono text-xs text-muted">
            {shortClass(alert.threat_class)}
          </span>
          <span className="truncate text-sm text-foreground">
            {pinned ? (
              <span
                className="mr-1.5 inline-block font-mono text-[10px] text-accent"
                title="pinned"
                aria-hidden
              >
                ◆
              </span>
            ) : null}
            <span className="font-mono text-xs text-muted">{alert.subtype}</span>{" "}
            {alert.message}
          </span>
          <span className="flex items-center gap-2">
            <span className="font-mono text-xs text-muted">
              {alert.confidence.toFixed(2)}
            </span>
            <ConfidenceBar value={alert.confidence} />
          </span>
        </span>
      </button>
    </li>
  );
});

const IncidentRow = memo(function IncidentRow({
  incident,
  selected,
  onSelect,
}: {
  incident: Incident;
  selected: boolean;
  onSelect: (incident: Incident) => void;
}) {
  return (
    <li role="none">
      <button
        type="button"
        role="option"
        aria-selected={selected}
        onClick={() => onSelect(incident)}
        className={`flex w-full items-stretch gap-0 border-b border-line text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-accent ${
          selected ? "bg-accent-soft/60" : "hover:bg-background-wash"
        }`}
        style={{ minHeight: 48 }}
      >
        <span
          className="w-[3px] shrink-0"
          style={{ background: severityColorVar(incident.severity) }}
          aria-hidden
        />
        <span className="grid min-w-0 flex-1 grid-cols-[5rem_7rem_1fr_auto] items-center gap-2.5 px-3 py-2.5">
          <span className="font-mono text-xs text-muted">
            {formatTime(incident.end)}
          </span>
          <span className="truncate font-mono text-xs text-muted">
            {incident.victim}
          </span>
          <span className="min-w-0 truncate text-sm text-foreground">
            <span className="font-mono text-xs text-muted">
              {incident.alert_count} alerts · {incident.subtypes.join(", ")}
            </span>{" "}
            {incident.sample_message}
          </span>
          <span className="flex flex-col items-end gap-0.5 font-mono text-[11px] text-muted">
            <span>{incident.severity}</span>
            {incident.peak_packet_rate != null ? (
              <span>~{Math.round(incident.peak_packet_rate)} pps</span>
            ) : (
              <span>conf {incident.peak_confidence.toFixed(2)}</span>
            )}
          </span>
        </span>
      </button>
    </li>
  );
});

function AlertStreamInner({
  view,
  onView,
  alerts,
  incidents,
  totalMatching,
  selectedId,
  selectedIncidentId,
  pinnedIds,
  suppressions,
  onSelect,
  onSelectIncident,
  onSelectRelative,
  onDelete,
  onTogglePin,
  onSuppress,
  onRemoveSuppress,
  onFilterSeverity,
  onFilterClass,
  onFilterDest,
  severityFilter,
  classFilter,
  destFilter,
  query,
  onSeverityFilter,
  onClassFilter,
  onDestFilter,
  onQuery,
  onClearFilters,
  onExportJsonl,
  onExportCsv,
  classOptions,
  statusMessage,
}: Props) {
  const listRef = useRef<HTMLUListElement>(null);
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [announce, setAnnounce] = useState("");

  const hasFilters =
    severityFilter !== "all" ||
    classFilter !== "all" ||
    Boolean(destFilter) ||
    Boolean(query.trim());

  const openMenu = useCallback(
    (alert: Alert, x: number, y: number) => {
      onSelect(alert);
      setMenu({ alert, x, y });
    },
    [onSelect],
  );

  const say = useCallback((msg: string) => {
    setAnnounce(msg);
  }, []);

  const menuActions: MenuAction[] = useMemo(() => {
    if (!menu) return [];
    const a = menu.alert;
    const id = rowKey(a);
    const pinned = pinnedIds.has(id);
    const endpoint = a.dst_ip
      ? `${a.dst_ip}${a.dst_port ? `:${a.dst_port}` : ""}`
      : a.src_ip
        ? `${a.src_ip}${a.src_port ? `:${a.src_port}` : ""}`
        : "";

    return [
      {
        id: "pin",
        label: pinned ? "unpin" : "pin to top",
        shortcut: "P",
        onSelect: () => {
          onTogglePin(a);
          say(pinned ? "alert unpinned" : "alert pinned to top");
        },
      },
      {
        id: "suppress-dst",
        label: a.dst_ip ? `suppress destination ${a.dst_ip}` : "suppress destination",
        disabled: !a.dst_ip,
        onSelect: () => onSuppress(a, "dst_ip"),
      },
      {
        id: "suppress-src",
        label: a.src_ip ? `suppress source ${a.src_ip}` : "suppress source",
        disabled: !a.src_ip,
        onSelect: () => onSuppress(a, "src_ip"),
      },
      {
        id: "suppress-subtype",
        label: `suppress subtype ${a.subtype}`,
        onSelect: () => onSuppress(a, "subtype"),
      },
      {
        id: "copy-msg",
        label: "copy message",
        onSelect: async () => {
          say((await copyText(a.message)) ? "message copied" : "copy failed");
        },
      },
      {
        id: "copy-flow",
        label: "copy flow id",
        onSelect: async () => {
          say((await copyText(a.flow_id)) ? "flow id copied" : "copy failed");
        },
      },
      {
        id: "copy-endpoint",
        label: "copy endpoint",
        disabled: !endpoint,
        onSelect: async () => {
          say((await copyText(endpoint)) ? "endpoint copied" : "copy failed");
        },
      },
      {
        id: "filter-class",
        label: `filter class: ${shortClass(a.threat_class)}`,
        onSelect: () => {
          onFilterClass(a.threat_class);
          say(`filtered to ${shortClass(a.threat_class)}`);
        },
      },
      {
        id: "filter-sev",
        label: `filter severity: ${a.severity}`,
        onSelect: () => {
          onFilterSeverity(a.severity);
          say(`filtered to ${a.severity} severity`);
        },
      },
      {
        id: "filter-dst",
        label: a.dst_ip ? `filter destination: ${a.dst_ip}` : "filter destination",
        disabled: !a.dst_ip,
        onSelect: () => {
          if (!a.dst_ip) return;
          onFilterDest(a.dst_ip);
          say(`filtered to ${a.dst_ip}`);
        },
      },
      {
        id: "delete",
        label: "delete alert",
        shortcut: "Del",
        danger: true,
        onSelect: () => {
          onDelete(a);
          say("alert deleted");
        },
      },
    ];
  }, [
    menu,
    pinnedIds,
    onTogglePin,
    onDelete,
    onSuppress,
    onFilterClass,
    onFilterSeverity,
    onFilterDest,
    say,
  ]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (menu || view !== "alerts") return;
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable)
      ) {
        return;
      }

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        onSelectRelative(1);
        return;
      }
      if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        onSelectRelative(-1);
        return;
      }
      if (e.key === "/" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        const input = document.querySelector<HTMLInputElement>(
          'input[aria-label="filter alerts by text"]',
        );
        input?.focus();
        input?.select();
        return;
      }

      const selected = alerts.find((a) => rowKey(a) === selectedId);
      if (!selected) return;

      if (e.key === "Delete" || e.key === "Backspace") {
        e.preventDefault();
        onDelete(selected);
        say("alert deleted");
        return;
      }
      if (e.key === "p" || e.key === "P") {
        e.preventDefault();
        const was = pinnedIds.has(rowKey(selected));
        onTogglePin(selected);
        say(was ? "alert unpinned" : "alert pinned to top");
        return;
      }
      if (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) {
        e.preventDefault();
        const row = listRef.current?.querySelector<HTMLElement>(
          `[data-alert-id="${CSS.escape(rowKey(selected))}"]`,
        );
        const rect = row?.getBoundingClientRect();
        openMenu(
          selected,
          rect ? rect.left + 24 : 80,
          rect ? rect.bottom - 4 : 80,
        );
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [
    menu,
    view,
    alerts,
    selectedId,
    pinnedIds,
    onDelete,
    onTogglePin,
    onSelectRelative,
    openMenu,
    say,
  ]);

  useEffect(() => {
    if (view !== "alerts" || !selectedId) return;
    const row = listRef.current?.querySelector<HTMLElement>(
      `#${CSS.escape(alertDomId(selectedId))}`,
    );
    row?.scrollIntoView({ block: "nearest" });
  }, [selectedId, view]);

  const onListKeyDown = (e: ReactKeyboardEvent) => {
    if (view !== "alerts") return;
    if (e.key === "Home") {
      e.preventDefault();
      if (alerts[0]) onSelect(alerts[0]);
    } else if (e.key === "End") {
      e.preventDefault();
      const last = alerts[alerts.length - 1];
      if (last) onSelect(last);
    }
  };

  return (
    <section
      className="flex min-h-0 flex-[0.55] flex-col border-r border-line bg-panel"
      aria-label="alert stream"
    >
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
        <div className="mr-1 flex items-center gap-1 rounded-sm border border-line p-0.5">
          <button
            type="button"
            onClick={() => onView("alerts")}
            className={`px-2 py-1 font-mono text-[11px] ${
              view === "alerts"
                ? "bg-accent-soft text-foreground"
                : "text-muted hover:text-foreground"
            }`}
          >
            alerts
          </button>
          <button
            type="button"
            onClick={() => onView("incidents")}
            className={`px-2 py-1 font-mono text-[11px] ${
              view === "incidents"
                ? "bg-accent-soft text-foreground"
                : "text-muted hover:text-foreground"
            }`}
          >
            incidents ({incidents.length})
          </button>
        </div>
        <select
          value={severityFilter}
          onChange={(e) => onSeverityFilter(e.target.value)}
          aria-label="filter by severity"
          className="border border-line bg-background px-2 py-1.5 font-mono text-xs text-muted outline-none"
        >
          <option value="all">all severity</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select
          value={classFilter}
          onChange={(e) => onClassFilter(e.target.value)}
          aria-label="filter by threat class"
          className="max-w-[11rem] border border-line bg-background px-2 py-1.5 font-mono text-xs text-muted outline-none"
        >
          <option value="all">all classes</option>
          {classOptions.map((c) => (
            <option key={c} value={c}>
              {shortClass(c)}
            </option>
          ))}
        </select>
        <input
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          placeholder="filter (/ to focus)"
          aria-label="filter alerts by text"
          className="min-w-0 flex-1 border border-line bg-background px-2 py-1.5 font-mono text-xs text-foreground outline-none placeholder:text-muted/70"
        />
        <button
          type="button"
          onClick={onExportCsv}
          className="font-mono text-[11px] text-muted underline-offset-2 hover:text-foreground hover:underline"
          title="download incident report as csv"
        >
          export csv
        </button>
        <button
          type="button"
          onClick={onExportJsonl}
          className="font-mono text-[11px] text-muted underline-offset-2 hover:text-foreground hover:underline"
          title="download filtered alerts as jsonl"
        >
          jsonl
        </button>
      </div>

      {hasFilters ? (
        <div
          className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line bg-background-wash/60 px-4 py-2"
          aria-label="active filters"
        >
          <span className="font-mono text-[11px] text-muted">
            showing {totalMatching}
          </span>
          {severityFilter !== "all" ? (
            <Chip
              label={`severity: ${severityFilter}`}
              onClear={() => onSeverityFilter("all")}
            />
          ) : null}
          {classFilter !== "all" ? (
            <Chip
              label={`class: ${shortClass(classFilter)}`}
              onClear={() => onClassFilter("all")}
            />
          ) : null}
          {destFilter ? (
            <Chip
              label={`dst: ${destFilter}`}
              onClear={() => onDestFilter(destFilter)}
            />
          ) : null}
          {query.trim() ? (
            <Chip label={`text: ${query.trim()}`} onClear={() => onQuery("")} />
          ) : null}
          <button
            type="button"
            onClick={onClearFilters}
            className="ml-auto font-mono text-[11px] text-accent underline-offset-2 hover:underline"
          >
            clear all
          </button>
        </div>
      ) : null}

      {suppressions.length ? (
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-4 py-1.5">
          <span className="font-mono text-[11px] text-muted">suppressed</span>
          {suppressions.map((r) => (
            <Chip
              key={r.id}
              label={`${r.kind}:${r.value}`}
              title={r.reason}
              onClear={() => onRemoveSuppress(r.id)}
            />
          ))}
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-y-auto">
        {view === "incidents" ? (
          incidents.length === 0 ? (
            <p className="px-5 py-10 font-mono text-sm text-muted" role="status">
              no incidents
            </p>
          ) : (
            <ul role="listbox" aria-label="incidents">
              {incidents.map((inc) => (
                <IncidentRow
                  key={inc.id}
                  incident={inc}
                  selected={selectedIncidentId === inc.id}
                  onSelect={onSelectIncident}
                />
              ))}
            </ul>
          )
        ) : alerts.length === 0 ? (
          <p className="px-5 py-10 font-mono text-sm text-muted" role="status">
            no alerts match
          </p>
        ) : (
          <ul
            ref={listRef}
            role="listbox"
            aria-labelledby="alerts-heading"
            aria-activedescendant={
              selectedId ? alertDomId(selectedId) : undefined
            }
            tabIndex={0}
            onKeyDown={onListKeyDown}
          >
            {alerts.map((alert, index) => {
              const id = rowKey(alert);
              return (
                <AlertRow
                  key={`${id}#${index}`}
                  alert={alert}
                  selected={selectedId === id}
                  pinned={pinnedIds.has(id)}
                  onSelect={onSelect}
                  onContextMenu={openMenu}
                />
              );
            })}
          </ul>
        )}
      </div>

      {menu ? (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          title={menu.alert.subtype}
          actions={menuActions}
          onClose={() => setMenu(null)}
        />
      ) : null}

      <div className="sr-only" role="status" aria-live="polite" aria-atomic>
        {announce || statusMessage}
      </div>
    </section>
  );
}

export const AlertStream = memo(AlertStreamInner);

function Chip({
  label,
  onClear,
  title,
}: {
  label: string;
  onClear: () => void;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClear}
      title={title ?? "remove"}
      aria-label={`remove ${label}`}
      className="inline-flex items-center gap-1.5 rounded-sm border border-accent/30 bg-accent-soft px-2 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:border-accent"
    >
      <span className="max-w-[14rem] truncate">{label}</span>
      <span className="text-muted" aria-hidden>
        ×
      </span>
    </button>
  );
}
