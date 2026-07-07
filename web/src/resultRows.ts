import type {
  Alert,
  DlqEvent,
  EndpointRisk,
  EventRow,
  Incident,
  ProcessTreeRow,
  QueryFinding,
  ResponseAction,
  TimelineItem,
  TopologyEdge,
  TopologyNode
} from "./dashboardTypes";
import {
  arrayOfRecords,
  arrayOfText,
  hostLabel,
  normalizeSeverity,
  normalizeTopologyState,
  numberValue,
  text
} from "./resultPrimitives";

const KNOWN_ENDPOINTS: readonly Pick<EndpointRisk, "host" | "hostId">[] = [
  { host: "이주호-Desktop", hostId: "endpoint-04" }
] as const;

export function toAlert(item: Readonly<Record<string, unknown>>): Alert {
  const hostId = text(item.host_id, "unknown");
  return {
    alertId: text(item.alert_id, text(item.rule_id, "unknown")),
    ruleId: text(item.rule_id, "unknown"),
    title: text(item.title, text(item.rule_id, "Unknown alert")),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    eventTime: text(item.event_time, ""),
    severity: normalizeSeverity(text(item.severity, "info")),
    riskScore: numberValue(item.risk_score),
    mitre: arrayOfText(item.mitre_mapping),
    evidence: arrayOfText(item.evidence)
  };
}

export function toEndpointRisk(item: Readonly<Record<string, unknown>>): EndpointRisk {
  const hostId = text(item.host_id, "unknown");
  return {
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    severity: normalizeSeverity(text(item.severity, "info")),
    riskScore: numberValue(item.risk_score),
    alerts: numberValue(item.alert_count),
    incidents: numberValue(item.incident_count),
    topRules: arrayOfText(item.top_rules),
    lastEventTime: text(item.last_event_time, "")
  };
}

export function toTopologyNode(item: Readonly<Record<string, unknown>>): TopologyNode {
  const id = text(item.id, "unknown");
  const rawLabel = text(item.label, id);
  const layer = text(item.layer, "unknown");
  return {
    id,
    label: layer.toLowerCase().includes("endpoint") ? hostLabel(id, rawLabel) : rawLabel,
    layer,
    state: normalizeTopologyState(text(item.state, "observed")),
    riskScore: numberValue(item.risk_score),
    alertCount: numberValue(item.alert_count)
  };
}

export function toTopologyEdge(item: Readonly<Record<string, unknown>>): TopologyEdge {
  const source = text(item.source, "unknown");
  return {
    source,
    sourceLabel: hostLabel(source, text(item.source_label, source)),
    target: text(item.target, "unknown"),
    protocol: text(item.protocol, "tcp"),
    state: normalizeTopologyState(text(item.state, "observed")),
    eventCount: numberValue(item.event_count),
    alertCount: numberValue(item.alert_count),
    bytesOut: numberValue(item.bytes_out)
  };
}

export function toEventRow(item: Readonly<Record<string, unknown>>): EventRow {
  const hostId = text(item.host_id, "unknown");
  return {
    eventId: text(item.event_id, "unknown"),
    eventTime: text(item.event_time, ""),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    eventType: text(item.event_type, "unknown"),
    processName: text(item.process_name, "-"),
    destination: text(item.domain, text(item.dst_ip, "-")),
    bytesOut: numberValue(item.bytes_out)
  };
}

export function toDlqEvent(item: Readonly<Record<string, unknown>>): DlqEvent {
  return {
    eventId: text(item.event_id, `index-${numberValue(item.index)}`),
    index: numberValue(item.index),
    code: text(item.code, "UNKNOWN_SCHEMA_ERROR"),
    errors: arrayOfText(item.errors)
  };
}

export function toProcessTreeRow(item: Readonly<Record<string, unknown>>): ProcessTreeRow {
  const hostId = text(item.host_id, "unknown");
  return {
    eventId: text(item.event_id, "unknown"),
    eventTime: text(item.event_time, ""),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    parentProcess: text(item.parent_process, "-"),
    processName: text(item.process_name, "-"),
    processPath: text(item.process_path, ""),
    signed: Boolean(item.signed)
  };
}

export function toIncident(item: Readonly<Record<string, unknown>>): Incident {
  const hostId = text(item.host_id, "unknown");
  return {
    incidentId: text(item.incident_id, "unknown"),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    severity: normalizeSeverity(text(item.severity, "critical")),
    riskScore: numberValue(item.risk_score),
    category: text(item.primary_category, "incident"),
    stages: arrayOfRecords(item.detected_sequence).map((stage) => ({
      stage: text(stage.stage, "unknown"),
      summary: text(stage.summary, "")
    })),
    evidence: arrayOfText(item.evidence)
  };
}

export function toTimelineItem(item: Readonly<Record<string, unknown>>): TimelineItem {
  const hostId = text(item.host_id, "unknown");
  return {
    time: text(item.time, ""),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    stage: text(item.stage, "unknown"),
    summary: text(item.summary, ""),
    severity: normalizeSeverity(text(item.severity, "info"))
  };
}

export function toQueryFinding(item: Readonly<Record<string, unknown>>): QueryFinding {
  const hostId = text(item.host_id, "unknown");
  return {
    queryId: text(item.query_id, "SIEM-Q"),
    title: text(item.title, "SIEM query finding"),
    ruleId: text(item.rule_id, "-"),
    severity: normalizeSeverity(text(item.severity, "info")),
    host: hostLabel(hostId, text(item.host_display_name, "")),
    hostId,
    summary: text(item.summary, ""),
    evidenceCount: numberValue(item.evidence_count),
    alertCount: numberValue(item.alert_count),
    lastEventTime: text(item.last_event_time, "")
  };
}

export function toResponseAction(item: Readonly<Record<string, unknown>>): ResponseAction {
  const hostId = text(item.host_id, "unknown");
  return {
    actionType: text(item.action_type, "analyst_review"),
    host: hostLabel(hostId, ""),
    ruleId: text(item.rule_id, "-"),
    mode: text(item.mode, "dry-run"),
    status: text(item.status, "planned"),
    description: text(item.description, "")
  };
}

export function includeKnownEndpointRisk(rows: readonly EndpointRisk[]): readonly EndpointRisk[] {
  const knownHostIds = new Set(rows.map((row) => row.hostId));
  const missingRows = KNOWN_ENDPOINTS
    .filter((endpoint) => !knownHostIds.has(endpoint.hostId))
    .map((endpoint) => ({
      host: endpoint.host,
      hostId: endpoint.hostId,
      severity: "info",
      riskScore: 0,
      alerts: 0,
      incidents: 0,
      topRules: [],
      lastEventTime: ""
    } satisfies EndpointRisk));
  return [...rows, ...missingRows];
}

export function includeKnownTopologyNodes(nodes: readonly TopologyNode[]): readonly TopologyNode[] {
  const knownNodeIds = new Set(nodes.map((node) => node.id));
  const missingNodes = KNOWN_ENDPOINTS
    .filter((endpoint) => !knownNodeIds.has(endpoint.hostId))
    .map((endpoint) => ({
      id: endpoint.hostId,
      label: endpoint.host,
      layer: "endpoint",
      state: "not-detected",
      riskScore: 0,
      alertCount: 0
    } satisfies TopologyNode));
  return [...nodes, ...missingNodes];
}
