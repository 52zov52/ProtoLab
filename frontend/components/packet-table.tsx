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
import { cn, formatTimestamp } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

export const PACKET_ROW_HEIGHT = 30;

/** Rows rendered above and below the viewport; small enough to stay cheap. */
const OVERSCAN = 4;

/**
 * The height assumed until the scroll element reports one. jsdom, print
 * layouts and the first paint have no measurable box, and a windowing table that
 * renders zero rows there is indistinguishable from an empty result.
 */
const FALLBACK_VIEW_HEIGHT = 360;

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
 * Sortable columns: the ones an analyst compares numerically while triaging.
 * Sorting is over the page that is loaded, never over the capture as a whole —
 * paging stays the server's job.
 */
const SORTABLE = new Set(["timestamp", "captured_length", "payload_length", "packet_index"]);

function HeaderButton({
  label,
  direction,
  onClick,
}: {
  label: string;
  direction: false | "asc" | "desc";
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
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
  );
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
  const { t } = useI18n();
  const [sorting, setSorting] = useState<SortingState>([]);
  const viewportRef = useRef<HTMLDivElement | null>(null);

  // Built inside the component because the headers and cells are translated.
  const columns = useMemo<ColumnDef<PacketTableRow>[]>(
    () => [
      {
        id: "packet_index",
        accessorKey: "packet_index",
        header: "#",
        cell: ({ row }) => <span className="text-accent">{row.original.packet_index}</span>,
      },
      {
        id: "timestamp",
        accessorKey: "timestamp",
        header: t("Time"),
        cell: ({ row }) => (
          <span className="whitespace-nowrap text-text-muted">
            {formatTimestamp(row.original.timestamp)}
          </span>
        ),
      },
      {
        id: "source_address",
        accessorKey: "source_address",
        header: t("Source"),
        cell: ({ row }) => (
          <span className="whitespace-nowrap font-mono text-2xs text-text">
            {row.original.source_address}
            {row.original.source_port != null ? (
              <span className="text-text-faint">:{row.original.source_port}</span>
            ) : null}
          </span>
        ),
      },
      {
        id: "destination_address",
        accessorKey: "destination_address",
        header: t("Destination"),
        cell: ({ row }) => (
          <span className="whitespace-nowrap font-mono text-2xs text-text">
            {row.original.destination_address}
            {row.original.destination_port != null ? (
              <span className="text-text-faint">:{row.original.destination_port}</span>
            ) : null}
          </span>
        ),
      },
      {
        id: "transport_protocol",
        accessorKey: "transport_protocol",
        header: t("Proto"),
        cell: ({ row }) => (
          <span className="text-2xs text-text-muted">
            {row.original.transport_protocol ?? "—"}
          </span>
        ),
      },
      {
        id: "tcp_flags",
        accessorKey: "tcp_flags",
        header: t("Flags"),
        cell: ({ row }) => (
          <span className="font-mono text-2xs text-text-faint">
            {row.original.tcp_flags != null
              ? `0x${row.original.tcp_flags.toString(16).padStart(2, "0")}`
              : "—"}
          </span>
        ),
      },
      {
        id: "captured_length",
        accessorKey: "captured_length",
        header: t("Len"),
        cell: ({ row }) => (
          <span className="text-2xs text-text-muted">{row.original.captured_length}</span>
        ),
      },
      {
        id: "payload_length",
        accessorKey: "payload_length",
        header: t("Payload"),
        cell: ({ row }) => (
          <span className="text-2xs text-text-muted">{row.original.payload_length}</span>
        ),
      },
      {
        id: "state",
        header: t("State"),
        // A row is only marked truncated when the capture actually dropped
        // bytes: a short original length on an offloaded packet is normal.
        cell: ({ row }) =>
          row.original.truncated && row.original.original_length > row.original.captured_length ? (
            <Badge tone="warn">{t("truncated")}</Badge>
          ) : (
            <span className="text-2xs text-text-faint">{t("ok")}</span>
          ),
      },
    ],
    [t],
  );

  // The sorting state is plain React state wrapped by TanStack's own reducer,
  // which the React Compiler lint cannot see through; the table is not a source
  // of renders outside its own state.
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
    estimateSize: () => PACKET_ROW_HEIGHT,
    overscan: OVERSCAN,
    initialRect: { width: 0, height: FALLBACK_VIEW_HEIGHT },
    // jsdom, print layouts and the first paint report a 0×0 box, and the default
    // observer would overwrite `initialRect` with it — a windowing table that
    // renders no rows there is indistinguishable from an empty result. Keep the
    // assumed height until there is a real box to measure.
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

  if (rows.length === 0) {
    return (
      <p className="px-3 py-6 text-center text-2xs text-text-faint">
        {t("No packets match the current filters.")}
      </p>
    );
  }

  return (
    <div
      ref={viewportRef}
      role="table"
      aria-label={t("Packets")}
      className="overflow-auto"
      style={{ height: "100%", minHeight: 220 }}
    >
      <table className="data-table w-full border-separate border-spacing-0">
        <thead className="sticky top-0 z-10">
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                const label = String(header.column.columnDef.header ?? "");
                const sortable = SORTABLE.has(header.column.id);
                const direction = header.column.getIsSorted();
                return (
                  <th key={header.id}>
                    {sortable ? (
                      <HeaderButton
                        label={label}
                        direction={direction}
                        onClick={() => header.column.toggleSorting()}
                      />
                    ) : (
                      label
                    )}
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
            const selected = selectedIndex === row.original.packet_index;
            return (
              <tr
                key={row.id}
                data-index={virtualRow.index}
                style={{ height: virtualRow.size }}
                className={cn("cursor-pointer align-middle", selected && "bg-accent-faint")}
                onClick={() => onSelect(row.original.packet_index)}
                title={t("Packet #{index}", { index: row.original.packet_index })}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id}>
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
