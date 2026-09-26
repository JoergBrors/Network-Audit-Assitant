import { useCallback, useEffect, useRef, useState } from "react";

export interface OverlayRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

const DEFAULT_RECT: OverlayRect = { x: 0, y: 0, width: 480, height: 620 };
const MIN_WIDTH = 340;
const MIN_HEIGHT = 320;
const STORAGE_KEY = "ai-overlay-rect";

function loadRect(key: string, size: { width: number; height: number }): OverlayRect {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return centered(size);
    const parsed = JSON.parse(raw) as Partial<OverlayRect>;
    if (
      typeof parsed.x === "number" &&
      typeof parsed.y === "number" &&
      typeof parsed.width === "number" &&
      typeof parsed.height === "number"
    ) {
      return parsed as OverlayRect;
    }
  } catch {
    // ignore, fall through to default
  }
  return centered(size);
}

function centered(size: { width: number; height: number }): OverlayRect {
  const width = Math.min(size.width, window.innerWidth - 32);
  const height = Math.min(size.height, window.innerHeight - 32);
  return {
    width,
    height,
    x: Math.max(16, Math.round((window.innerWidth - width) / 2)),
    y: Math.max(16, Math.round((window.innerHeight - height) / 3)),
  };
}

function saveRect(key: string, rect: OverlayRect): void {
  try {
    localStorage.setItem(key, JSON.stringify(rect));
  } catch {
    // best effort: a private window or full storage just means position isn't remembered
  }
}

function clampToViewport(rect: OverlayRect): OverlayRect {
  const maxX = Math.max(0, window.innerWidth - Math.min(rect.width, window.innerWidth) - 8);
  const maxY = Math.max(0, window.innerHeight - 40); // keep at least the title bar reachable
  return {
    ...rect,
    x: Math.min(Math.max(0, rect.x), maxX),
    y: Math.min(Math.max(0, rect.y), maxY),
  };
}

type DragState =
  | { kind: "move"; startX: number; startY: number; origX: number; origY: number }
  | {
      kind: "resize";
      edge: "se" | "e" | "s";
      startX: number;
      startY: number;
      origWidth: number;
      origHeight: number;
    };

/**
 * A floating, draggable, resizable window (title bar drag, corner/edge resize handles), positioned
 * and sized in `localStorage` across sessions. Used for the AI chat panel so it behaves like a
 * normal desktop chat window instead of a fixed in-page section — movable out of the way of the
 * graph, resizable to read longer answers, and remembers where the user left it.
 */
export function FloatingOverlay({
  title,
  onClose,
  children,
  headerExtra,
  storageKey = STORAGE_KEY,
  defaultSize = DEFAULT_RECT,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  headerExtra?: React.ReactNode;
  /** localStorage key for position/size (one per kind of window). */
  storageKey?: string;
  defaultSize?: { width: number; height: number };
}) {
  const [rect, setRect] = useState<OverlayRect>(() => clampToViewport(loadRect(storageKey, defaultSize)));
  const dragRef = useRef<DragState | null>(null);
  const rectRef = useRef(rect);
  rectRef.current = rect;

  useEffect(() => {
    const onResize = () => setRect((r) => clampToViewport(r));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const commit = useCallback(
    (next: OverlayRect) => {
      setRect(next);
      saveRect(storageKey, next);
    },
    [storageKey],
  );

  const onPointerMove = useCallback((e: PointerEvent) => {
    const drag = dragRef.current;
    if (!drag) return;
    if (drag.kind === "move") {
      const dx = e.clientX - drag.startX;
      const dy = e.clientY - drag.startY;
      setRect((r) => ({ ...r, x: drag.origX + dx, y: drag.origY + dy }));
    } else {
      const dx = e.clientX - drag.startX;
      const dy = e.clientY - drag.startY;
      setRect((r) => ({
        ...r,
        width: drag.edge !== "s" ? Math.max(MIN_WIDTH, drag.origWidth + dx) : r.width,
        height: drag.edge !== "e" ? Math.max(MIN_HEIGHT, drag.origHeight + dy) : r.height,
      }));
    }
  }, []);

  const endDrag = useCallback(() => {
    if (!dragRef.current) return;
    dragRef.current = null;
    commit(clampToViewport(rectRef.current));
    window.removeEventListener("pointermove", onPointerMove);
    window.removeEventListener("pointerup", endDrag);
  }, [commit, onPointerMove]);

  const startMove = useCallback(
    (e: React.PointerEvent) => {
      if ((e.target as HTMLElement).closest("button")) return; // don't drag when clicking a header button
      dragRef.current = { kind: "move", startX: e.clientX, startY: e.clientY, origX: rect.x, origY: rect.y };
      window.addEventListener("pointermove", onPointerMove);
      window.addEventListener("pointerup", endDrag);
    },
    [rect.x, rect.y, onPointerMove, endDrag],
  );

  const startResize = useCallback(
    (edge: "se" | "e" | "s") => (e: React.PointerEvent) => {
      e.stopPropagation();
      dragRef.current = {
        kind: "resize",
        edge,
        startX: e.clientX,
        startY: e.clientY,
        origWidth: rect.width,
        origHeight: rect.height,
      };
      window.addEventListener("pointermove", onPointerMove);
      window.addEventListener("pointerup", endDrag);
    },
    [rect.width, rect.height, onPointerMove, endDrag],
  );

  useEffect(() => () => endDrag(), [endDrag]);

  return (
    <div
      className="floating-overlay"
      style={{ left: rect.x, top: rect.y, width: rect.width, height: rect.height }}
      role="dialog"
      aria-label={title}
    >
      <div className="floating-overlay-header" onPointerDown={startMove}>
        <span className="floating-overlay-title">{title}</span>
        <div className="floating-overlay-header-extra">{headerExtra}</div>
        <button className="secondary" onClick={onClose} aria-label="Schließen">
          ✕
        </button>
      </div>
      <div className="floating-overlay-body">{children}</div>
      <div className="floating-overlay-resize floating-overlay-resize-e" onPointerDown={startResize("e")} />
      <div className="floating-overlay-resize floating-overlay-resize-s" onPointerDown={startResize("s")} />
      <div className="floating-overlay-resize floating-overlay-resize-se" onPointerDown={startResize("se")} />
    </div>
  );
}
