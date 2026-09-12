"use client";

import { useEffect, useId, useRef } from "react";

export type MenuAction = {
  id: string;
  label: string;
  shortcut?: string;
  danger?: boolean;
  disabled?: boolean;
  onSelect: () => void;
};

type Props = {
  x: number;
  y: number;
  title?: string;
  actions: MenuAction[];
  onClose: () => void;
};

export function ContextMenu({ x, y, title, actions, onClose }: Props) {
  const menuRef = useRef<HTMLDivElement>(null);
  const labelId = useId();

  useEffect(() => {
    const el = menuRef.current;
    if (!el) return;

    // keep on-screen
    const pad = 8;
    const rect = el.getBoundingClientRect();
    let left = x;
    let top = y;
    if (left + rect.width > window.innerWidth - pad) {
      left = Math.max(pad, window.innerWidth - rect.width - pad);
    }
    if (top + rect.height > window.innerHeight - pad) {
      top = Math.max(pad, window.innerHeight - rect.height - pad);
    }
    el.style.left = `${left}px`;
    el.style.top = `${top}px`;

    const first = el.querySelector<HTMLButtonElement>(
      '[role="menuitem"]:not(:disabled)',
    );
    first?.focus();
  }, [x, y]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Home" && e.key !== "End") {
        return;
      }
      const items = Array.from(
        menuRef.current?.querySelectorAll<HTMLButtonElement>(
          '[role="menuitem"]:not(:disabled)',
        ) ?? [],
      );
      if (!items.length) return;
      e.preventDefault();
      const i = items.indexOf(document.activeElement as HTMLButtonElement);
      if (e.key === "Home") {
        items[0]?.focus();
        return;
      }
      if (e.key === "End") {
        items[items.length - 1]?.focus();
        return;
      }
      const next =
        e.key === "ArrowDown"
          ? items[(i + 1 + items.length) % items.length]
          : items[(i - 1 + items.length) % items.length];
      next?.focus();
    };
    const onPointer = (e: MouseEvent) => {
      // ignore the right-click that opened us; it can race the mount listener
      if (e.button === 2) return;
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    // defer so the opening gesture cannot immediately dismiss the menu
    const t = window.setTimeout(() => {
      window.addEventListener("mousedown", onPointer);
    }, 0);
    return () => {
      window.clearTimeout(t);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onPointer);
    };
  }, [onClose]);

  return (
    <div
      ref={menuRef}
      role="menu"
      aria-labelledby={title ? labelId : undefined}
      className="fixed z-[200] min-w-[13rem] border border-line bg-panel py-1 shadow-md"
      style={{ left: x, top: y }}
    >
      {title ? (
        <p
          id={labelId}
          className="truncate border-b border-line px-3 py-1.5 font-mono text-[10px] text-muted"
        >
          {title}
        </p>
      ) : null}
      {actions.map((action) => (
        <button
          key={action.id}
          type="button"
          role="menuitem"
          disabled={action.disabled}
          onClick={() => {
            if (action.disabled) return;
            action.onSelect();
            onClose();
          }}
          className={`flex w-full items-center justify-between gap-4 px-3 py-1.5 text-left font-mono text-xs outline-none transition-colors focus:bg-accent-soft disabled:opacity-40 ${
            action.danger
              ? "text-sev-high hover:bg-sev-high/10"
              : "text-foreground hover:bg-background-wash"
          }`}
        >
          <span>{action.label}</span>
          {action.shortcut ? (
            <span className="text-[10px] text-muted">{action.shortcut}</span>
          ) : null}
        </button>
      ))}
    </div>
  );
}
