"use client";

import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useMemo, useRef, useState } from "react";

import { Badge } from "@/components/ui";
import { cn } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

export const MESSAGE_ROW_HEIGHT = 28;
const OVERSCAN = 4;

/**
 * The height assumed until the scroll element reports one. jsdom, print
 * layouts and the first paint have no measurable box, and a windowing table
 * that renders zero rows there is indistinguishable from an empty result.
 */
const FALLBACK_VIEW_HEIGHT = 320;

export interface MessageTableRow {
  id: string;
  index_in_stream: number;
  start_offset: number;
  end_offset: number;
  present_length: number;
  complete: boolean;
  features: Record<string, number>;
}

/**
 * Framed messages of one direction, windowed the same way the packet table is:
 * a stream can carry thousands of messages, and rendering all of them blocks
 * the main thread for the whole panel.
 *
 * Selection is owned by the caller (2–6 messages at a time, oldest dropped)
 * rather than by the table, because the comparison limit is a product rule and
 * not a table state.
 */
export function MessageTable({
  items,
  selected,
  onToggle,
  onCompare,
}: {
  items: MessageTableRow[];
  selected: string[];
  onToggle: (id: string) => void;
  /** Number of messages the comparison supports; shown per row as a hint. */
  onCompare?: (id: string) => void;
}) {
  const { t } = useI18n();
  const [sorting, setSorting] = useState<SortingState>([]);
  const viewportRef = useRef<HTMLDivElement | null>(null);

  const columns = useMemo<ColumnDef<MessageTableRow>[]>(
    () => [
      {
        id: "select",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <input
            type="checkbox"
            checked={selected.includes(row.original.id)}
            readOnly
            aria-label={t("message {index}", { index: row.original.index_in_stream })}
          />
        ),
      },
      {
        id: "index_in_stream",
        accessorKey: "index_in_stream",
        header: "#",
        cell: ({ row }) => (
          <span className="text-text-faint">{row.original.index_in_stream}</span>
        ),
      },
      {
        id: "range",
        header: t("Range"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-2xs text-text-muted">
            {row.original.start_offset}…{row.original.end_offset}
          </span>
        ),
      },
      {
        id: "present_length",
        accessorKey: "present_length",
        header: t("Len"),
        cell: ({ row }) => <span className="text-2xs">{row.original.present_length}</span>,
      },
      {
        id: "entropy",
        header: t("Entropy"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-2xs text-text-muted">
            {(row.original.features.entropy ?? 0).toFixed(2)}
          </span>
        ),
      },
      {
        id: "unique",
        header: t("Unique"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-2xs text-text-muted">
            {row.original.features.unique_bytes ?? "-"}
          </span>
        ),
      },
      {
        id: "state",
        header: t("State"),
        enableSorting: false,
        cell: ({ row }) => (
          <Badge tone={row.original.complete ? "ok" : "warn"}>
            {row.original.complete ? t("complete") : t("partial")}
          </Badge>
        ),
      },
    ],
    [t, selected],
  );

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: items,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const rows = table.getRowModel().rows;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => viewportRef.current,
    estimateSize: () => MESSAGE_ROW_HEIGHT,
    overscan: OVERSCAN,
    initialRect: { width: 0, height: FALLBACK_VIEW_HEIGHT },
    // jsdom, print layouts and the first paint report a 0×0 box, and the default
    // observer would overwrite `initialRect` with it — a windowing table that
    // renders no rows there is indistinguishable from an empty result.
    observeElementRect: (instance, onRect) => {
      const element = instance.options.getScrollElement();
      if (!element) return;
      const measure = () => {
        const height = element.clientHeight;
        if (height > 0) onRect({ width: element.clientWidth, height });
      };
      measure();
      const observer = new ResizeObserver(measure);
      observer.observe(element);
      return () => observer.disconnect();
    },
  });

  const virtualRows = virtualizer.getVirtualItems();
  const topPad = virtualRows.length > 0 ? virtualRows[0].start : 0;
  const bottomPad =
    virtualRows.length > 0
      ? virtualizer.getTotalSize() - virtualRows[virtualRows.length - 1].end
      : 0;

  return (
    <div
      ref={viewportRef}
      role="table"
      aria-label={t("Messages")}
      className="overflow-auto"
      style={{ height: "100%", minHeight: 200 }}
    >
      <table className="data-table w-full border-separate border-spacing-0">
        <thead className="sticky top-0 z-10">
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                const label = String(header.column.columnDef.header ?? "");
                if (!header.column.getCanSort()) {
                  return (
                    <th key={header.id} aria-label={label || undefined}>
                      {label}
                    </th>
                  );
                }
                const direction = header.column.getIsSorted();
                return (
                  <th key={header.id}>
                    <button
                      type="button"
                      onClick={() => header.column.toggleSorting()}
                      className={cn(
                        "flex items-center gap-1 uppercase tracking-wider transition-colors",
                        direction ? "text-accent" : "hover:text-text",
                      )}
                      title={label}
                    >
                      {label}
                      <span aria-hidden className="text-3xs">
                        {direction === "asc" ? "▲" : direction === "desc" ? "▼" : "↕"}
                      </span>
                    </button>
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {topPad > 0 ? (
            <tr aria-hidden="true" style={{ height: topPad }}>
              <td colSpan={columns.length} />
            </tr>
          ) : null}
          {virtualRows.map((virtualRow) => {
            const row = rows[virtualRow.index];
            const active = selected.includes(row.original.id);
            return (
              <tr
                key={row.id}
                data-index={virtualRow.index}
                style={{ height: virtualRow.size }}
                className={cn("cursor-pointer align-middle", active && "bg-accent-faint")}
                onClick={() => (onCompare ? onCompare(row.original.id) : onToggle(row.original.id))}
                onDoubleClick={() => onToggle(row.original.id)}
                title={t("message {index}", { index: row.original.index_in_stream })}
              >
                {row.getVisibleCells().map((cell) => (
                  <td
                    key={cell.id}
                    onClick={
                      cell.column.id === "select"
                        ? (event) => {
                            event.stopPropagation();
                            onToggle(row.original.id);
                          }
                        : undefined
                    }
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            );
          })}
          {bottomPad > 0 ? (
            <tr aria-hidden="true" style={{ height: bottomPad }}>
              <td colSpan={columns.length} />
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}
