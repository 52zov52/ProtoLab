"use client";

import { useMemo, useState } from "react";

import { cn, toHexRows } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

export interface Hole {
  start: number;
  end: number;
  length: number;
  reason: string;
}

interface HexViewerProps {
  lines: {
    offset: number;
    hex: string[];
    ascii: string[];
    length: number;
  }[];
  /** Absolute stream offsets to highlight (e.g. the selected message). */
  highlightRange?: { start: number; end: number } | null;
  holes?: Hole[];
  onOffsetClick?: (offset: number) => void;
  dense?: boolean;
}

/**
 * Hex + ASCII view.
 *
 * Missing bytes are rendered as an explicit `GAP` marker rather than as zeros:
 * the viewer must never imply that bytes exist where the capture lost them.
 */
export function HexViewer({
  lines,
  highlightRange,
  holes = [],
  onOffsetClick,
  dense = false,
}: HexViewerProps) {
  const { t } = useI18n();
  const rows = useMemo(() => toHexRows(lines), [lines]);
  const [selected, setSelected] = useState<number | null>(null);

  const inHighlight = (offset: number): boolean => {
    if (!highlightRange) return false;
    return offset >= highlightRange.start && offset < highlightRange.end;
  };

  const isGap = (offset: number): boolean =>
    holes.some((hole) => offset >= hole.start && offset < hole.end);

  if (rows.length === 0) {
    return (
      <p className="p-3 text-2xs text-text-faint">
        {t("No bytes to display at this offset.")}
      </p>
    );
  }

  return (
    <div className={cn("hexdump overflow-x-auto", dense && "text-[10px] leading-4")}>
      <table className="w-full border-collapse">
        <tbody>
          {rows.map((row) => (
            <tr key={row.offset} className="align-top">
              <td className="hex-offset whitespace-nowrap pr-3">
                <button
                  type="button"
                  className="hover:text-accent"
                  onClick={() => {
                    setSelected(row.offset);
                    onOffsetClick?.(row.offset);
                  }}
                  title={
                    selected === row.offset
                      ? t("Copied offset shown in the toolbar")
                      : t("Select this row")
                  }
                >
                  {row.offset.toString(16).padStart(8, "0")}
                </button>
              </td>
              <td className="whitespace-pre">
                {row.cells.map((cell, index) => {
                  const absolute = row.offset + index;
                  if (cell === "GAP") {
                    return (
                      <span key={index} className="hex-byte hex-byte-gap" title={t("Bytes missing from the capture")}>
                        GAP
                      </span>
                    );
                  }
                  const gapped = isGap(absolute);
                  return (
                    <span
                      key={index}
                      className={cn(
                        "hex-byte",
                        inHighlight(absolute) && "hex-byte-highlight",
                        gapped && "hex-byte-gap",
                      )}
                      title={t("offset {offset} (0x{hex})", { offset: absolute, hex: cell })}
                    >
                      {cell}
                    </span>
                  );
                })}
              </td>
              <td className="whitespace-pre pl-3 text-text-muted">{row.ascii}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Side-by-side comparison with per-offset change highlighting. */
export function HexComparison({
  rows,
  labels,
}: {
  rows: {
    offset: number;
    values: (number | null)[];
    changed: boolean;
    present_count: number;
  }[];
  labels: string[];
}) {
  const { t } = useI18n();
  const [onlyDifferences, setOnlyDifferences] = useState(false);
  const visible = onlyDifferences ? rows.filter((row) => row.changed) : rows;
  const changedCount = rows.filter((row) => row.changed).length;

  return (
    <div className="flex min-h-0 flex-col">
      <div className="flex items-center justify-between border-b border-line px-3 py-1.5">
        <span className="text-2xs text-text-muted">
          {t("{changed} of {total} offsets differ", { changed: changedCount, total: rows.length })}
        </span>
        <label className="flex items-center gap-1.5 text-2xs text-text-muted">
          <input
            type="checkbox"
            checked={onlyDifferences}
            onChange={(event) => setOnlyDifferences(event.target.checked)}
          />
          {t("only differing offsets")}
        </label>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t("Offset")}</th>
              {labels.map((label, index) => (
                <th key={index} className="text-right">
                  {label}
                </th>
              ))}
              <th>{t("State")}</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <tr key={row.offset} className={row.changed ? "bg-status-warn/5" : undefined}>
                <td className="text-text-faint">{row.offset}</td>
                {row.values.map((value, index) => (
                  <td
                    key={index}
                    className={cn(
                      "text-right",
                      value === null
                        ? "text-text-faint italic"
                        : row.changed
                          ? "text-status-warn"
                          : "text-text",
                    )}
                    title={
                      value === null
                        ? t("absent: this message is shorter than this offset (not zero)")
                        : undefined
                    }
                  >
                    {value === null ? t("— absent —") : `0x${value.toString(16).padStart(2, "0")}`}
                  </td>
                ))}
                <td>
                  {row.changed ? (
                    <span className="text-status-warn">
                      {row.present_count < row.values.length
                        ? t("differs / absent")
                        : t("differs")}
                    </span>
                  ) : (
                    <span className="text-text-faint">{t("identical")}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}