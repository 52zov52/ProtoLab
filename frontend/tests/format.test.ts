/**
 * Formatting and hex helpers.
 *
 * These carry product claims, so they are asserted rather than assumed: an
 * absent byte must render as "absent", and a missing value must never be
 * silently coerced into zero.
 */
import { describe, expect, it } from "vitest";

import {
  asciiPreview,
  bytesToHex,
  checkTone,
  completenessTone,
  formatBytes,
  formatDuration,
  hexToBytes,
  toHexRows,
  verdictTone,
} from "@/lib/format";

describe("formatBytes", () => {
  it("renders sub-kilobyte values exactly", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("scales into binary units", () => {
    expect(formatBytes(1024)).toBe("1.0 KiB");
    expect(formatBytes(1024 * 1024)).toBe("1.0 MiB");
  });

  it("degrades to a dash instead of printing NaN", () => {
    expect(formatBytes(Number.NaN)).toBe("-");
  });
});

describe("formatDuration", () => {
  it("uses milliseconds below one second", () => {
    expect(formatDuration(0.25)).toBe("250.0 ms");
  });

  it("uses seconds below a minute", () => {
    expect(formatDuration(2)).toBe("2.000 s");
  });

  it("rejects negative and non-finite input", () => {
    expect(formatDuration(-1)).toBe("-");
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe("-");
  });
});

describe("hex conversion", () => {
  it("round-trips bytes through hex", () => {
    const bytes = new Uint8Array([0x00, 0x0a, 0xff, 0x7f]);
    expect(bytesToHex(bytes)).toBe("000aff7f");
    expect(Array.from(hexToBytes("000aff7f"))).toEqual([0x00, 0x0a, 0xff, 0x7f]);
  });

  it("ignores separators when parsing hex", () => {
    expect(Array.from(hexToBytes("00 0a ff"))).toEqual([0x00, 0x0a, 0xff]);
  });

  it("prints non-printable bytes as dots in the ASCII column", () => {
    expect(asciiPreview(new Uint8Array([0x41, 0x00, 0x7f, 0x42]))).toBe("A..B");
  });
});

describe("toHexRows", () => {
  it("flags rows that contain a gap rather than inventing zeros", () => {
    const rows = toHexRows([
      { offset: 0, hex: ["00", "01"], ascii: [".."], length: 2 },
      { offset: 2, hex: ["GAP", "GAP"], ascii: ["  "], length: 2 },
    ]);
    expect(rows[0].isGap).toBe(false);
    expect(rows[1].isGap).toBe(true);
    expect(rows[1].cells).toEqual(["GAP", "GAP"]);
  });
});

describe("status tones", () => {
  it("never reports an unrecognised status as good", () => {
    expect(completenessTone("complete")).toBe("ok");
    expect(completenessTone("something_new")).toBe("unknown");
    expect(verdictTone("consistent_with_corpus")).toBe("ok");
    expect(verdictTone("contradicted")).toBe("bad");
    expect(verdictTone("totally_made_up")).toBe("neutral");
  });

  it("distinguishes an unverified security check from a failure", () => {
    expect(checkTone("pass")).toBe("ok");
    expect(checkTone("fail")).toBe("bad");
    expect(checkTone("unknown")).toBe("warn");
  });
});