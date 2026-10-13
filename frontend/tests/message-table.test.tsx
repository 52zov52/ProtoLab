/**
 * Message table windowing and selection (§4 stack: TanStack Table + Virtual).
 *
 * A direction of a reconstructed stream can carry thousands of messages, so the
 * table must render a window rather than all of them, and the 2–6 selection
 * limit belongs to the product (a comparison has a bounded width), not to the
 * table. These assertions are on the rendered DOM, so a windowing regression is
 * visible rather than silent.
 */
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import {
  MESSAGE_ROW_HEIGHT,
  MessageTable,
  type MessageTableRow,
} from "@/components/message-table";

function makeMessage(index: number): MessageTableRow {
  return {
    id: `msg${index}`,
    index_in_stream: index,
    start_offset: index * 32,
    end_offset: index * 32 + 32,
    present_length: 32,
    complete: index % 5 !== 0,
    features: { entropy: 3.25, unique_bytes: 12 },
  };
}

function renderedRows(container: HTMLElement): HTMLElement[] {
  return Array.from(
    container.querySelectorAll("tbody tr[data-index]"),
  ) as HTMLElement[];
}

describe("MessageTable", () => {
  it("renders a window of the messages, not all of them", () => {
    const items = Array.from({ length: 800 }, (_, index) => makeMessage(index));
    const { container } = render(
      <MessageTable items={items} selected={[]} onToggle={() => {}} />,
    );
    const rows = renderedRows(container);
    expect(rows.length).toBeGreaterThan(4);
    expect(rows.length).toBeLessThan(60);
    expect(rows[0].dataset.index).toBe("0");

    const dataRows = rows.length;
    const spacerHeight = Array.from(
      container.querySelectorAll("tbody tr[aria-hidden]"),
    ).reduce(
      (sum, row) => sum + Number((row as HTMLElement).style.height.replace("px", "")),
      0,
    );
    expect(spacerHeight + dataRows * MESSAGE_ROW_HEIGHT).toBe(
      items.length * MESSAGE_ROW_HEIGHT,
    );
  });

  it("mounts the tail of the list when scrolled to the end", () => {
    const items = Array.from({ length: 800 }, (_, index) => makeMessage(index));
    const { container } = render(
      <MessageTable items={items} selected={[]} onToggle={() => {}} />,
    );
    const viewport = container.querySelector('[role="table"]') as HTMLElement;

    fireEvent.scroll(viewport, { target: { scrollTop: 800 * MESSAGE_ROW_HEIGHT } });

    const rows = renderedRows(container);
    expect(rows.length).toBeGreaterThan(0);
    expect(Number(rows[rows.length - 1].dataset.index)).toBeGreaterThanOrEqual(790);
  });

  it("toggles a message by its id when the checkbox is clicked", () => {
    const toggled: string[] = [];
    const items = [makeMessage(0), makeMessage(1)];
    const { container } = render(
      <MessageTable
        items={items}
        selected={["msg0"]}
        onToggle={(id) => toggled.push(id)}
      />,
    );

    fireEvent.click(renderedRows(container)[0].querySelector("input[type=checkbox]")!);
    expect(toggled).toEqual(["msg0"]);
  });

  it("shows the entropy and the completeness state of each message", async () => {
    const items = [makeMessage(0), makeMessage(1)];
    render(<MessageTable items={items} selected={[]} onToggle={() => {}} />);

    expect(await screen.findAllByText("3.25")).toHaveLength(2);
    // Index 0 is a multiple of 5, which the fixture marks partial.
    expect(screen.getByText("partial")).toBeInTheDocument();
    expect(screen.getByText("complete")).toBeInTheDocument();
  });
});
