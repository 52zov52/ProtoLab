"use client";

import { useMemo } from "react";

import { useI18n } from "@/lib/i18n";

/**
 * A visual timeline of the TCP events the capture actually observed.
 *
 * It is deliberately *not* a reconstruction of either peer's state machine: the
 * diagram draws only packets that are present, marks the retransmissions, the
 * out-of-order arrivals and the zero-window advertisements the reconstructor
 * recorded, and leaves absent packets absent. This is the "living picture" of
 * the session that a packet list cannot give.
 */

export interface TcpTimelineEvent {
  packet_index: number;
  timestamp: number;
  direction: string;
  source: string;
  destination?: string;
  flags_text: string;
  sequence: number | null;
  acknowledgment: number | null;
  window: number | null;
  payload_length: number;
}

export interface TcpAnomalyIndex {
  retransmissions: number[];
  out_of_order: number[];
  duplicates: number[];
  zero_windows: number[];
}

const C = {
  syn: "#4ea87a",
  ack: "#5d6772",
  data: "#3fb6c8",
  fin: "#c9a227",
  rst: "#c9584f",
  retrans: "#c9584f",
  ooo: "#c9a227",
  zero: "#5b8fd6",
  dup: "#7b8794",
  grid: "#23282f",
  lane: "#313842",
  text: "#8d97a3",
  faint: "#5d6772",
} as const;

type Kind = "syn" | "ack" | "data" | "fin" | "rst";

function classify(event: TcpTimelineEvent): Kind {
  const flags = event.flags_text.toUpperCase();
  if (flags.includes("RST")) return "rst";
  if (flags.includes("SYN")) return "syn";
  if (flags.includes("FIN")) return "fin";
  if (event.payload_length > 0) return "data";
  return "ack";
}

const KIND_COLOR: Record<Kind, string> = {
  syn: C.syn,
  ack: C.ack,
  data: C.data,
  fin: C.fin,
  rst: C.rst,
};

const KIND_LABEL: Record<Kind, string> = {
  syn: "SYN / SYN-ACK",
  ack: "ACK",
  data: "DATA",
  fin: "FIN",
  rst: "RST",
};

const WIDTH = 940;
const HEIGHT = 208;
const PAD_LEFT = 60;
const PAD_RIGHT = 18;
const LANE_TOP = 56;
const LANE_BOTTOM = 108;
const AXIS_Y = 164;

function fmtTime(value: number): string {
  return value.toFixed(6);
}

export function TcpStateDiagram({
  events,
  anomalies,
  onSelectPacket,
  selectedPacket,
}: {
  events: TcpTimelineEvent[];
  anomalies?: Partial<TcpAnomalyIndex>;
  onSelectPacket?: (packetIndex: number) => void;
  selectedPacket?: number | null;
}) {
  const { t } = useI18n();
  const model = useMemo(() => {
    const ordered = [...events].sort((a, b) => a.packet_index - b.packet_index);
    const usable = WIDTH - PAD_LEFT - PAD_RIGHT;
    const t0 = ordered.length ? ordered[0].timestamp : 0;
    const t1 = ordered.length ? ordered[ordered.length - 1].timestamp : 0;
    const span = t1 - t0;
    const byIndex = span <= 0;
    const x = (event: TcpTimelineEvent, index: number) =>
      byIndex
        ? PAD_LEFT + (ordered.length <= 1 ? usable / 2 : (index / (ordered.length - 1)) * usable)
        : PAD_LEFT + ((event.timestamp - t0) / span) * usable;

    const placed = ordered.map((event, index) => ({
      event,
      kind: classify(event),
      x: x(event, index),
      y: event.direction === "a2b" ? LANE_TOP : LANE_BOTTOM,
    }));
    const byPacket = new Map(placed.map((p) => [p.event.packet_index, p]));

    const firstData = placed.find((p) => p.kind === "data");
    const firstClose = placed.find((p) => p.kind === "fin" || p.kind === "rst");
    return { placed, byPacket, t0, t1, usable, firstData, firstClose };
  }, [events]);

  if (events.length === 0) {
    return (
      <p className="p-3 text-2xs text-text-faint">
        {t(
          "No TCP packets were observed for this session, so there is no state diagram to draw.",
        )}
      </p>
    );
  }

  const { placed, byPacket, t0, t1, firstData, firstClose } = model;

  const anomalyMarkers: Array<{
    packetIndex: number;
    color: string;
    glyph: string;
    label: string;
  }> = [];
  const push = (indices: number[] | undefined, color: string, glyph: string, label: string) => {
    for (const packetIndex of indices ?? []) {
      if (byPacket.has(packetIndex)) anomalyMarkers.push({ packetIndex, color, glyph, label });
    }
  };
  push(anomalies?.retransmissions, C.retrans, "R", t("retransmission"));
  push(anomalies?.duplicates, C.dup, "D", t("exact duplicate"));
  push(anomalies?.out_of_order, C.ooo, "O", t("out of order"));
  push(anomalies?.zero_windows, C.zero, "Z", t("zero window"));

  const phaseSegments = buildPhases(t0, t1, firstData?.event.timestamp, firstClose?.event.timestamp);

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        width="100%"
        role="img"
        aria-label={t("Observed TCP state timeline")}
        className="min-w-[720px]"
      >
        {/* Lane guides. */}
        <line x1={PAD_LEFT} y1={LANE_TOP} x2={WIDTH - PAD_RIGHT} y2={LANE_TOP} stroke={C.lane} strokeWidth={1} />
        <line x1={PAD_LEFT} y1={LANE_BOTTOM} x2={WIDTH - PAD_RIGHT} y2={LANE_BOTTOM} stroke={C.lane} strokeWidth={1} />
        <text x={8} y={LANE_TOP + 3} fill={C.text} fontSize={10} fontFamily="monospace">A→B</text>
        <text x={8} y={LANE_BOTTOM + 3} fill={C.text} fontSize={10} fontFamily="monospace">B→A</text>

        {/* Per-event markers. */}
        {placed.map(({ event, kind, x, y }) => {
          const radius = kind === "data" ? Math.min(7, 3 + event.payload_length / 120) : 3.6;
          const selected = selectedPacket != null && selectedPacket === event.packet_index;
          const title = t(
            "#{index} {time} {flags} seq={seq} ack={ack} win={win} payload={payload}",
            {
              index: event.packet_index,
              time: fmtTime(event.timestamp),
              flags: event.flags_text,
              seq: event.sequence ?? "-",
              ack: event.acknowledgment ?? "-",
              win: event.window ?? "-",
              payload: event.payload_length,
            },
          );
          return (
            <g
              key={event.packet_index}
              onClick={onSelectPacket ? () => onSelectPacket(event.packet_index) : undefined}
              style={onSelectPacket ? { cursor: "pointer" } : undefined}
            >
              <title>{title}</title>
              {kind === "data" && (
                <line
                  x1={x}
                  y1={LANE_TOP}
                  x2={x}
                  y2={LANE_BOTTOM}
                  stroke={C.data}
                  strokeOpacity={selected ? 0.7 : 0.28}
                  strokeWidth={selected ? 2 : 1}
                />
              )}
              <circle
                cx={x}
                cy={y}
                r={selected ? radius + 2 : radius}
                fill={KIND_COLOR[kind]}
                stroke={selected ? "#d6dbe1" : "transparent"}
                strokeWidth={1}
              />
            </g>
          );
        })}

        {/* Anomaly glyphs sit just off the lane they belong to. */}
        {anomalyMarkers.map((marker, index) => {
          const point = byPacket.get(marker.packetIndex);
          if (!point) return null;
          const above = point.event.direction === "a2b";
          const gy = above ? point.y - 15 : point.y + 15;
          return (
            <g key={`${marker.glyph}-${marker.packetIndex}-${index}`}>
              <title>{t("Packet #{index}: {reason}", { index: marker.packetIndex, reason: marker.label })}</title>
              <rect
                x={point.x - 5}
                y={gy - 5}
                width={10}
                height={10}
                rx={2}
                fill={marker.color}
                fillOpacity={0.85}
              />
              <text x={point.x} y={gy + 3.2} fill="#0b0d10" fontSize={8} fontFamily="monospace" textAnchor="middle">
                {marker.glyph}
              </text>
            </g>
          );
        })}

        {/* Time axis. */}
        <line x1={PAD_LEFT} y1={AXIS_Y} x2={WIDTH - PAD_RIGHT} y2={AXIS_Y} stroke={C.grid} strokeWidth={1} />
        <text x={PAD_LEFT} y={AXIS_Y + 14} fill={C.faint} fontSize={9} fontFamily="monospace">
          {fmtTime(t0)}
        </text>
        <text x={WIDTH - PAD_RIGHT} y={AXIS_Y + 14} fill={C.faint} fontSize={9} fontFamily="monospace" textAnchor="end">
          {fmtTime(t1)}
        </text>
        <text
          x={(PAD_LEFT + (WIDTH - PAD_RIGHT)) / 2}
          y={AXIS_Y + 14}
          fill={C.faint}
          fontSize={9}
          textAnchor="middle"
        >
          {t("time (s, capture order left → right)")}
        </text>

        {/* Phase strip. */}
        <g transform={`translate(${PAD_LEFT}, ${AXIS_Y + 22})`}>
          {phaseSegments.map((segment) => (
            <g key={segment.label}>
              <rect
                x={segment.x0}
                y={0}
                width={Math.max(1, segment.x1 - segment.x0)}
                height={10}
                fill={segment.color}
                fillOpacity={0.5}
              />
              {segment.x1 - segment.x0 > 70 && (
                <text
                  x={(segment.x0 + segment.x1) / 2}
                  y={26}
                  fill={C.text}
                  fontSize={9}
                  textAnchor="middle"
                >
                  {t(segment.label)}
                </text>
              )}
            </g>
          ))}
        </g>
      </svg>

      <div className="flex flex-wrap items-center gap-3 px-3 pb-1 pt-1 text-2xs text-text-muted">
        {(Object.keys(KIND_LABEL) as Kind[]).map((kind) => (
          <span key={kind} className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: KIND_COLOR[kind] }} />
            {t(KIND_LABEL[kind])}
          </span>
        ))}
        <span className="text-text-faint">·</span>
        <span className="inline-flex items-center gap-1">
          <span className="inline-flex h-3 w-3 items-center justify-center rounded-sm text-[7px]" style={{ background: C.retrans, color: "#0b0d10" }}>R</span>
          {t("retransmission")}
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="inline-flex h-3 w-3 items-center justify-center rounded-sm text-[7px]" style={{ background: C.ooo, color: "#0b0d10" }}>O</span>
          {t("out of order")}
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="inline-flex h-3 w-3 items-center justify-center rounded-sm text-[7px]" style={{ background: C.zero, color: "#0b0d10" }}>Z</span>
          {t("zero window")}
        </span>
      </div>
    </div>
  );
}

function buildPhases(
  t0: number,
  t1: number,
  firstData: number | undefined,
  firstClose: number | undefined,
): Array<{ label: string; x0: number; x1: number; color: string }> {
  const usable = WIDTH - PAD_LEFT - PAD_RIGHT;
  const span = t1 - t0;
  const pos = (t: number) => (span <= 0 ? 0 : ((t - t0) / span) * usable);
  const dataStart = firstData != null ? pos(firstData) : undefined;
  const closeStart = firstClose != null ? pos(firstClose) : undefined;

  const segments: Array<{ label: string; x0: number; x1: number; color: string }> = [];
  const handshakeEnd = dataStart ?? closeStart ?? usable;
  segments.push({ label: "handshake", x0: 0, x1: handshakeEnd, color: C.syn });
  if (dataStart != null) {
    segments.push({ label: "data", x0: dataStart, x1: closeStart ?? usable, color: C.data });
  }
  if (closeStart != null) {
    segments.push({ label: "teardown", x0: closeStart, x1: usable, color: C.fin });
  }
  return segments;
}
