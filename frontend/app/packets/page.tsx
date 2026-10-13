"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

import { HexViewer } from "@/components/hex-viewer";
import { PacketTable, type PacketTableRow } from "@/components/packet-table";
import {
  Badge,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { formatNumber } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

const PAGE_SIZE = 250;
const TRANSPORTS = ["TCP", "UDP", "ICMP", "IGMP", "other"];

function bytesToLines(bytes: Uint8Array): {
  offset: number;
  hex: string[];
  ascii: string[];
  length: number;
}[] {
  const lines: { offset: number; hex: string[]; ascii: string[]; length: number }[] = [];
  for (let start = 0; start < bytes.length; start += 16) {
    const chunk = bytes.slice(start, Math.min(start + 16, bytes.length));
    const hex: string[] = [];
    const ascii: string[] = [];
    for (const byte of chunk) {
      hex.push(byte.toString(16).padStart(2, "0"));
      ascii.push(byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".");
    }
    lines.push({ offset: start, hex, ascii: [ascii.join("")], length: chunk.length });
  }
  return lines;
}

export default function PacketsPage() {
  const workspace = useWorkspace();
  const { t } = useI18n();
  const captureId = workspace.captureId;

  const [search, setSearch] = useState("");
  const [transport, setTransport] = useState("");
  const [minPayload, setMinPayload] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [rawBytes, setRawBytes] = useState<Uint8Array | null>(null);
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);

  const query = useMemo(() => {
    const parts = [`offset=${offset}`, `limit=${PAGE_SIZE}`];
    if (transport) parts.push(`transport=${encodeURIComponent(transport)}`);
    if (search.trim()) parts.push(`search=${encodeURIComponent(search.trim())}`);
    const min = Number.parseInt(minPayload, 10);
    if (Number.isFinite(min) && min > 0) parts.push(`min_payload=${min}`);
    return `?${parts.join("&")}`;
  }, [offset, transport, search, minPayload]);

  const packets = useAsync(
    () => (captureId ? api.listPackets(captureId, query) : Promise.resolve(null)),
    [captureId, query, workspace.revision],
  );

  const items: PacketTableRow[] = useMemo(() => {
    const rows = (packets.data?.items ?? []) as Record<string, unknown>[];
    return rows.map((row) => ({
      packet_index: Number(row.packet_index),
      timestamp: Number(row.timestamp ?? 0),
      captured_length: Number(row.captured_length ?? 0),
      original_length: Number(row.original_length ?? 0),
      source_address: String(row.source_address ?? ""),
      destination_address: String(row.destination_address ?? ""),
      source_port: row.source_port == null ? null : Number(row.source_port),
      destination_port: row.destination_port == null ? null : Number(row.destination_port),
      transport_protocol: row.transport_protocol == null ? null : String(row.transport_protocol),
      tcp_sequence: row.tcp_sequence == null ? null : Number(row.tcp_sequence),
      tcp_acknowledgment: row.tcp_acknowledgment == null ? null : Number(row.tcp_acknowledgment),
      tcp_flags: row.tcp_flags == null ? null : Number(row.tcp_flags),
      tcp_window: row.tcp_window == null ? null : Number(row.tcp_window),
      payload_length: Number(row.payload_length ?? 0),
      truncated: Boolean(row.truncated),
      session_id: row.session_id == null ? null : String(row.session_id),
    }));
  }, [packets.data]);

  const total = Number(packets.data?.total ?? 0);
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.floor(offset / PAGE_SIZE);

  const selectPacket = useCallback(
    async (packetIndex: number) => {
      setSelectedIndex(packetIndex);
      if (!captureId) return;
      setRawLoading(true);
      setRawError(null);
      try {
        setRawBytes(await api.packetBytes(captureId, packetIndex));
      } catch (error) {
        setRawBytes(null);
        setRawError(error instanceof Error ? error.message : String(error));
      } finally {
        setRawLoading(false);
      }
    },
    [captureId],
  );

  // Keep the selection page-local: when filters/page change, drop the hex view.
  useEffect(() => {
    setSelectedIndex(null);
    setRawBytes(null);
    setRawError(null);
  }, [query]);

  if (!captureId) {
    return (
      <div className="p-4">
        <EmptyState
          title={t("No capture selected")}
          description={t("The packet table lists the packets of one capture. Pick a capture first.")}
          action={
            <Link href="/captures" className="btn btn-primary">
              {t("Go to Captures")}
            </Link>
          }
        />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">{t("Packets")}</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "The packets of this capture as imported (offsets, flags, lengths). Rows are only rendered while visible; click a packet to see its original bytes.",
          )}
        </p>
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        <input
          className="input h-7 w-44 font-mono text-2xs"
          placeholder={t("search address…")}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
        <select
          className="input h-7 text-2xs"
          value={transport}
          onChange={(event) => {
            setTransport(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">{t("any transport")}</option>
          {TRANSPORTS.map((item) => (
            <option key={item} value={item}>
              {t(item)}
            </option>
          ))}
        </select>
        <input
          className="input h-7 w-24 font-mono text-2xs"
          placeholder={t("min payload")}
          inputMode="numeric"
          value={minPayload}
          onChange={(event) => {
            setMinPayload(event.target.value);
            setOffset(0);
          }}
        />
        <span className="text-2xs text-text-faint">
          {t("{count} packet(s) · page {page}/{pageCount}", {
            count: formatNumber(total),
            page: page + 1,
            pageCount,
          })}
        </span>
        <div className="ml-auto flex gap-1.5">
          <button
            type="button"
            className="btn"
            disabled={offset === 0 || packets.state === "loading"}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            {t("Prev")}
          </button>
          <button
            type="button"
            className="btn"
            disabled={offset + PAGE_SIZE >= total || packets.state === "loading"}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            {t("Next")}
          </button>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-hidden p-3 lg:grid-cols-[1fr_420px]">
        <Panel
          title={t("Packet table")}
          actions={<Badge tone="neutral">{t("{count} rendered", { count: formatNumber(items.length) })}</Badge>}
        >
          <div className="h-full">
            {packets.state === "error" ? (
              <ErrorState message={packets.error ?? ""} onRetry={packets.reload} />
            ) : packets.state === "loading" ? (
              <Skeleton rows={9} />
            ) : (
              <PacketTable
                items={items}
                selectedIndex={selectedIndex}
                onSelect={selectPacket}
              />
            )}
          </div>
        </Panel>

        <Panel title={t("Packet bytes")}>
          {selectedIndex == null ? (
            <EmptyState
              title={t("No packet selected")}
              description={t(
                "Click a row to fetch the original on-disk bytes of that packet from the immutable capture file.",
              )}
            />
          ) : rawLoading ? (
            <Skeleton rows={10} />
          ) : rawError ? (
            <ErrorState message={rawError} />
          ) : rawBytes ? (
            <div className="overflow-auto p-2">
              <p className="pb-2 text-2xs text-text-faint">
                {t("Packet #{index} · {count} byte(s)", {
                  index: selectedIndex,
                  count: formatNumber(rawBytes.length),
                })}
              </p>
              <HexViewer lines={bytesToLines(rawBytes)} dense />
            </div>
          ) : null}
        </Panel>
      </div>
    </div>
  );
}
