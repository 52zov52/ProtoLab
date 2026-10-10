/**
 * Hex viewer and message comparison.
 *
 * The assertions here encode two product promises that are easy to break:
 *
 *  1. A lost segment renders as an explicit GAP, never as `00` bytes.
 *  2. A byte absent from a shorter message renders as "absent", never as zero,
 *     so the analyst cannot mistake padding for data.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { HexComparison, HexViewer } from "@/components/hex-viewer";

const LINES = [
  { offset: 0, hex: ["00", "07", "01", "00"], ascii: ["...."], length: 4 },
  { offset: 4, hex: ["GAP", "GAP", "02"], ascii: ["   "], length: 3 },
];

describe("HexViewer", () => {
  it("renders an explicit GAP marker for bytes missing from the capture", () => {
    render(<HexViewer lines={LINES} />);
    const gaps = screen.getAllByText("GAP");
    expect(gaps).toHaveLength(2);
    // The lost bytes must not be rendered as zeros.
    expect(screen.queryByTitle("offset 4 (0x00)")).not.toBeInTheDocument();
  });

  it("highlights exactly the requested byte range", () => {
    render(<HexViewer lines={LINES} highlightRange={{ start: 1, end: 3 }} />);
    expect(screen.getByTitle("offset 1 (0x07)").className).toContain(
      "hex-byte-highlight",
    );
    // The range is half-open: offset 3 is outside it.
    expect(screen.getByTitle("offset 3 (0x00)").className).not.toContain(
      "hex-byte-highlight",
    );
  });

  it("reports the clicked stream offset to the parent", async () => {
    const onOffsetClick = vi.fn();
    render(<HexViewer lines={LINES} onOffsetClick={onOffsetClick} />);
    await userEvent.click(screen.getByRole("button", { name: "00000004" }));
    expect(onOffsetClick).toHaveBeenCalledWith(4);
  });

  it("says so when there is nothing to show instead of rendering an empty box", () => {
    render(<HexViewer lines={[]} />);
    expect(screen.getByText(/No bytes to display/i)).toBeInTheDocument();
  });
});

describe("HexComparison", () => {
  const rows = [
    {
      offset: 0,
      values: [0x00, 0x07],
      changed: false,
      present_count: 2,
    },
    {
      offset: 2,
      // The second message is shorter: the byte is absent, not zero.
      values: [0x01, null],
      changed: true,
      present_count: 1,
    },
  ];

  it("renders an absent byte as absent rather than as 0x00", () => {
    render(<HexComparison rows={rows} labels={["A", "B"]} />);
    expect(screen.getByText("— absent —")).toBeInTheDocument();
    expect(screen.getAllByText("0x00").length).toBe(1);
  });

  it("explains that the differing row is partly absent", () => {
    render(<HexComparison rows={rows} labels={["A", "B"]} />);
    expect(screen.getByText("differs / absent")).toBeInTheDocument();
  });

  it("can filter down to only the differing offsets", async () => {
    render(<HexComparison rows={rows} labels={["A", "B"]} />);
    expect(screen.getByText((_, el) => el?.textContent === "1 of 2 offsets differ")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("checkbox"));
    // The identical row is filtered away; the differing one remains.
    expect(screen.getByText("differs / absent")).toBeInTheDocument();
    expect(screen.queryByText("identical")).not.toBeInTheDocument();
  });
});