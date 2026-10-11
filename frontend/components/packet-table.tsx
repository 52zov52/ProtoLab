"use client";

import { useEffect, useRef, useState } from "react";

import { Badge } from "@/components/ui";
import { cn, formatTimestamp } from "@/lib/format";

export const PACKET_ROW_HEIGHT = 30;

export interface PacketTableRow {
  packet_index: number;
  timestamp: number;
  captured_length: number;
  original_length: number;
  source_address: string;
  destination_address: string;
  source_port: number | null;
  destination_port: number | null;
  transport_protocol: string | null;
  tcp_sequence: number | null;
  tcp_acknowledgment: number | null;
  tcp_flags: number | null;
  tcp_window: number | null;
  payload_length: number;
  truncated: boolean;
  session_id: string | null;
}

/**
 * Pure windowing: which rows of `items` are visible inside a scroll viewport.
 * Split out so the virtualisation logic is assertable without a DOM.
 */
export function visibleStart(
  items: unknown[],
  scrollTop: number,
  rowHeight = PACKET_ROW_HEIGHT,
  overscan = 2,
): number {
  if (items.length === 0) return 0;
  // Clamp to the last row so a stale scroll position (after the capture
  // changed under us) renders the tail instead of an empty window.
  const maxStart = Math.max(0, items.length - 1);
  return Math.min(maxStart, Math.max(0, Math.floor(scrollTop / rowHeight) - overscan));
}

export function visibleSlice<T>(
  items: T[],
  scrollTop: number,
  viewHeight: number,
  rowHeight = PACKET_ROW_HEIGHT,
  overscan = 2,
): T[] {
  if (viewHeight <= 0 || items.length === 0) return [];
  const start = visibleStart(items, scrollTop, rowHeight, overscan);
  const end = Math.min(items.length, Math.ceil((scrollTop + viewHeight) / rowHeight) + overscan);
  return items.slice(start, Math.max(start + 1, end));
}

export function PacketTable({
  items,
  selectedIndex,
  onSelect,
}: {
  items: PacketTableRow[];
  selectedIndex: number | null;
  onSelect: (packetIndex: number) => void;
}) {
  const [scrollTop, setScrollTop] = useState(0);
  const [viewHeight, setViewHeight] = useState(0);
  const viewportRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const measure = () => setViewHeight(el.clientHeight);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [items]);

  const rows = visibleSlice(items, scrollTop, viewHeight || 360);
  const start = visibleStart(items, scrollTop);
  const topPad = start * PACKET_ROW_HEIGHT;
  const bottomPad =
    (items.length - start - rows.length) * PACKET_ROW_HEIGHT;

  if (items.length === 0) {
    return (
      <p className="px-3 py-6 text-center text-2xs text-text-faint">
        No packets match the current filters.
      </p>
    );
  }

  return (
    <div
      ref={viewportRef}
      role="table"
      aria-label="Packets"
      className="overflow-auto"
      style={{ height: "100%", minHeight: 220 }}
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
    >
      <table className="data-table w-full border-separate border-spacing-0">
        <thead className="sticky top-0 z-10">
          <tr>
            <th className="w-14">#</th>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th className="w-14">Proto</th>
            <th className="w-16">Flags</th>
            <th className="w-14">Len</th>
            <th className="w-14">Payload</th>
            <th className="w-14">State</th>
          </tr>
        </thead>
        <tbody>
          {topPad > 0 ? (
            <tr aria-hidden="true" style={{ height: topPad }}>
              <td colSpan={9} />
            </tr>
          ) : null}
          {rows.map((row) => {
            const selected = selectedIndex === row.packet_index;
            const truncated =
              row.truncated && row.original_length > row.captured_length;
            return (
              <tr
                key={row.packet_index}
                style={{ height: PACKET_ROW_HEIGHT }}
                className={cn(
                  "cursor-pointer align-middle",
                  selected && "bg-accent-faint",
                )}
                onClick={() => onSelect(row.packet_index)}
                title={`Packet #${row.packet_index}`}
              >
                <td className="text-accent">{row.packet_index}</td>
                <td className="whitespace-nowrap text-text-muted">
                  {formatTimestamp(row.timestamp)}
                </td>
                <td className="whitespace-nowrap font-mono text-2xs text-text">
                  {row.source_address}
                  {row.source_port != null ? (
                    <span className="text-text-faint">:{row.source_port}</span>
                  ) : null}
                </td>
                <td className="whitespace-nowrap font-mono text-2xs text-text">
                  {row.destination_address}
                  {row.destination_port != null ? (
                    <span className="text-text-faint">:{row.destination_port}</span>
                  ) : null}
                </td>
                <td className="text-2xs text-text-muted">
                  {row.transport_protocol ?? "—"}
                </td>
                <td className="font-mono text-2xs text-text-faint">
                  {row.tcp_flags != null
                    ? `0x${row.tcp_flags.toString(16).padStart(2, "0")}`
                    : "—"}
                </td>
                <td className="text-2xs text-text-muted">{row.captured_length}</td>
                <td className="text-2xs text-text-muted">{row.payload_length}</td>
                <td>
                  {truncated ? (
                    <Badge tone="warn">truncated</Badge>
                  ) : (
                    <span className="text-2xs text-text-faint">ok</span>
                  )}
                </td>
              </tr>
            );
          })}
          {bottomPad > 0 ? (
            <tr aria-hidden="true" style={{ height: bottomPad }}>
              <td colSpan={9} />
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}