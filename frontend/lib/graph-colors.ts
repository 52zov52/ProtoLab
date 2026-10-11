/**
 * Protocol colours for the network graph.
 *
 * Colour is a label taken from the detected protocol, never from a port: two
 * services on the same port must not be painted the same colour by assumption.
 * An unrecognised protocol is grey so it is visibly unclassified.
 */
export interface ProtocolEdgeLike {
  protocols: string[];
}

export const PROTOCOL_META: Record<string, { label: string; color: string }> = {
  http1: { label: "HTTP/1.x", color: "#5b8fd6" },
  http2: { label: "HTTP/2", color: "#3fb6c8" },
  grpc: { label: "gRPC", color: "#4ea87a" },
  websocket: { label: "WebSocket", color: "#9b7fd6" },
  mqtt: { label: "MQTT", color: "#c9a227" },
  dns_tcp: { label: "DNS/TCP", color: "#5bc9c0" },
  tls: { label: "TLS", color: "#6fae8f" },
  length_prefixed_unknown: { label: "unknown (length-prefixed)", color: "#5d6772" },
  unknown_binary: { label: "unknown / binary", color: "#5d6772" },
  unknown: { label: "unknown", color: "#5d6772" },
};

export const UNKNOWN_PROTOCOL_COLOR = "#5d6772";

//: Labels that mean "we could not classify this", so a classified protocol on
//: the same edge must win even if it appears later in the list.
const UNCLASSIFIED = new Set([
  "unknown",
  "unknown_binary",
  "length_prefixed_unknown",
]);

export function protocolMeta(name: string): { label: string; color: string } {
  return PROTOCOL_META[name] ?? { label: name, color: UNKNOWN_PROTOCOL_COLOR };
}

/**
 * The colour of an edge: a classified protocol if the edge carries one,
 * otherwise the first label we have a colour for, otherwise grey. An
 * unclassified label never masks a classified one.
 */
export function edgeColor(edge: ProtocolEdgeLike): string {
  const classified = edge.protocols.find(
    (protocol) => PROTOCOL_META[protocol] && !UNCLASSIFIED.has(protocol),
  );
  const name =
    classified ??
    edge.protocols.find((protocol) => PROTOCOL_META[protocol]) ??
    edge.protocols[0] ??
    "unknown";
  return protocolMeta(name).color;
}