/**
 * Packet table windowing and sorting.
 *
 * The table renders a page of up to 250 packets out of a capture that can hold
 * 250 000, and it now windows with TanStack Virtual rather than hand-rolled
 * arithmetic. A windowing bug either drops rows or renders all of them, and both
 * are silently invisible to an analyst, so the behaviour is pinned on the
 * rendered DOM instead of on a helper function:
 *
 *  - only a small window of rows is mounted, and it starts at the top;
 *  - scrolling mounts the tail of the list, clamped to it;
 *  - a sortable header reorders the rows that are shown.
 */
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { PACKET_ROW_HEIGHT, PacketTable, type PacketTableRow } from "@/components/packet-table";

function makeRow(index: number, captured = 64 + index): PacketTableRow {
  return {
    packet_index: index,
    timestamp: 1700000000 + index,
    captured_length: captured,
    original_length: captured,
    source_address: "10.0.0.1",
    destination_address: "10.0.0.2",
    source_port: 49152,
    destination_port: 80,
    transport_protocol: "TCP",
    tcp_sequence: 1000 + index,
    tcp_acknowledgment: 500,
    tcp_flags: 0x18,
    tcp_window: 64240,
    payload_length: index % 7,
    truncated: false,
    session_id: "sess1",
  };
}

function renderedRows(container: HTMLElement): HTMLElement[] {
  return Array.from(
    container.querySelectorAll("tbody tr[data-index]"),
  ) as HTMLElement[];
}

function viewport(container: HTMLElement): HTMLElement {
  const element = container.querySelector('[role="table"]');
  if (!element) throw new Error("no table viewport");
  return element as HTMLElement;
}

describe("PacketTable", () => {
  it("renders a window of rows, not all of them", () => {
    const items = Array.from({ length: 500 }, (_, index) => makeRow(index));
    const { container } = render(
      <PacketTable items={items} selectedIndex={null} onSelect={() => {}} />,
    );
    const rows = renderedRows(container);
    expect(rows.length).toBeGreaterThan(4);
    expect(rows.length).toBeLessThan(60);
    expect(rows[0].dataset.index).toBe("0");
    // The spacer rows keep the scrollbar honest about the hidden rows: what is
    // rendered plus what is padded must be the whole list.
    const dataRows = renderedRows(container);
    const spacerHeight = Array.from(
      container.querySelectorAll("tbody tr[aria-hidden]"),
    ).reduce(
      (sum, row) => sum + Number((row as HTMLElement).style.height.replace("px", "")),
      0,
    );
    expect(spacerHeight + dataRows.length * PACKET_ROW_HEIGHT).toBe(
      items.length * PACKET_ROW_HEIGHT,
    );
  });

  it("mounts the tail of the list when the viewport is scrolled to the end", () => {
    const items = Array.from({ length: 500 }, (_, index) => makeRow(index));
    const { container } = render(
      <PacketTable items={items} selectedIndex={null} onSelect={() => {}} />,
    );

    fireEvent.scroll(viewport(container), { target: { scrollTop: 500 * PACKET_ROW_HEIGHT } });

    const rows = renderedRows(container);
    expect(rows.length).toBeGreaterThan(0);
    expect(Number(rows[rows.length - 1].dataset.index)).toBeGreaterThanOrEqual(490);
  });

  it("reports a click on a row by its packet index", () => {
    const picked: number[] = [];
    const items = [makeRow(0), makeRow(1)];
    const { container } = render(
      <PacketTable items={items} selectedIndex={null} onSelect={(index) => picked.push(index)} />,
    );
    fireEvent.click(renderedRows(container)[1]);
    expect(picked).toEqual([1]);
  });

  it("sorts by a sortable header over the loaded page", () => {
    // Row 0 is the largest so the default window starts with an unsorted value.
    const items = [makeRow(0, 900), makeRow(1, 10), makeRow(2, 500)];
    const { container } = render(
      <PacketTable items={items} selectedIndex={null} onSelect={() => {}} />,
    );

    // Largest first: a triage table is opened by "what is biggest", not by what
    // happens to sit at the bottom.
    fireEvent.click(screen.getByRole("button", { name: "Len" }));

    const rows = renderedRows(container);
    expect(rows[0].querySelectorAll("td")[6]?.textContent).toBe("900");

    // A second click flips the direction, which is what the arrow indicates.
    fireEvent.click(screen.getByRole("button", { name: "Len" }));
    expect(renderedRows(container)[0].querySelectorAll("td")[6]?.textContent).toBe("10");
  });

  it("says why it is empty instead of rendering a blank table", () => {
    render(<PacketTable items={[]} selectedIndex={null} onSelect={() => {}} />);
    expect(screen.getByText("No packets match the current filters.")).toBeInTheDocument();
  });
});
