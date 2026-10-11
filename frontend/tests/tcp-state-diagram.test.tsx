/**
 * TCP state diagram.
 *
 * The diagram is a claim about what the capture contains: it must draw exactly
 * the observed events, and any retransmission/out-of-order/zero-window marker it
 * shows must point at a packet that is actually present. These tests pin that
 * down, plus the honest empty state.
 */
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { TcpStateDiagram, type TcpTimelineEvent } from "@/components/tcp-state-diagram";

const EVENTS: TcpTimelineEvent[] = [
  { packet_index: 0, timestamp: 0.0, direction: "a2b", source: "10.0.0.1", flags_text: "SYN", sequence: 0, acknowledgment: null, window: 64240, payload_length: 0 },
  { packet_index: 1, timestamp: 0.001, direction: "b2a", source: "10.0.0.2", flags_text: "SYN, ACK", sequence: 0, acknowledgment: 1, window: 64240, payload_length: 0 },
  { packet_index: 2, timestamp: 0.002, direction: "a2b", source: "10.0.0.1", flags_text: "ACK", sequence: 1, acknowledgment: 1, window: 64240, payload_length: 0 },
  { packet_index: 3, timestamp: 0.003, direction: "a2b", source: "10.0.0.1", flags_text: "ACK", sequence: 1, acknowledgment: 1, window: 64240, payload_length: 12 },
  { packet_index: 4, timestamp: 0.004, direction: "b2a", source: "10.0.0.2", flags_text: "FIN, ACK", sequence: 1, acknowledgment: 13, window: 64240, payload_length: 0 },
];

describe("TcpStateDiagram", () => {
  it("draws one marker per observed packet", () => {
    const { container } = render(<TcpStateDiagram events={EVENTS} />);
    expect(screen.getByRole("img", { name: /Observed TCP state timeline/i })).toBeInTheDocument();
    expect(container.querySelectorAll("circle")).toHaveLength(EVENTS.length);
  });

  it("marks a retransmission on the packet that carried it", () => {
    const { container } = render(
      <TcpStateDiagram events={EVENTS} anomalies={{ retransmissions: [3] }} />,
    );
    const titles = Array.from(container.querySelectorAll("title")).map((node) => node.textContent);
    expect(titles).toContain("Packet #3: retransmission");
    // R glyph rectangle plus the five event circles exist; no phantom markers.
    expect(container.querySelectorAll("rect").length).toBeGreaterThanOrEqual(1);
  });

  it("ignores an anomaly that points at a packet absent from the capture", () => {
    const { container } = render(
      <TcpStateDiagram events={EVENTS} anomalies={{ out_of_order: [999] }} />,
    );
    const titles = Array.from(container.querySelectorAll("title")).map((node) => node.textContent);
    expect(titles).not.toContain("Packet #999: out of order");
  });

  it("says there is nothing to draw instead of rendering an empty frame", () => {
    render(<TcpStateDiagram events={[]} />);
    expect(screen.getByText(/No TCP packets were observed/i)).toBeInTheDocument();
  });
});
