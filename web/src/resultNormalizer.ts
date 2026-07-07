import type { DashboardResult } from "./dashboardTypes";
import {
  arrayOfRecords,
  normalizeEdrState,
  numberValue,
  recordOrEmpty,
  sourceLabel,
  text
} from "./resultPrimitives";
import {
  includeKnownEndpointRisk,
  includeKnownTopologyNodes,
  toAlert,
  toDlqEvent,
  toEndpointRisk,
  toEventRow,
  toIncident,
  toProcessTreeRow,
  toQueryFinding,
  toResponseAction,
  toTimelineItem,
  toTopologyEdge,
  toTopologyNode
} from "./resultRows";

export type AdaptResultOptions = {
  readonly includeDemoFallbackAssets?: boolean;
  readonly sourceOverride?: string;
};

export function adaptResult(raw: unknown, options: AdaptResultOptions = {}): DashboardResult {
  const result = recordOrEmpty(raw);
  const summary = recordOrEmpty(result.summary);
  const siem = recordOrEmpty(result.siem_analysis);
  const topology = recordOrEmpty(siem.egress_topology);
  const report = recordOrEmpty(result.report);
  const input = recordOrEmpty(result.input);
  const edrState = recordOrEmpty(result.edr_state);
  const responsePlan = recordOrEmpty(result.response_plan);
  const pipeline = recordOrEmpty(result.pipeline_delivery);
  const ai = recordOrEmpty(result.ai_predictions);
  const telemetry = {
    ...recordOrEmpty(input),
    ...recordOrEmpty(result.telemetry_metadata),
    ...recordOrEmpty(siem.telemetry_metadata)
  };
  const topologySummary = recordOrEmpty(topology.summary);
  const endpointRiskRows = arrayOfRecords(result.endpoint_risk).map(toEndpointRisk);
  const topologyNodeRows = arrayOfRecords(topology.nodes).map(toTopologyNode);
  const endpointRisk = options.includeDemoFallbackAssets ? includeKnownEndpointRisk(endpointRiskRows) : endpointRiskRows;
  const topologyNodes = options.includeDemoFallbackAssets ? includeKnownTopologyNodes(topologyNodeRows) : topologyNodeRows;

  return {
    status: text(result.status, "empty"),
    decision: text(result.decision, "not_available"),
    generatedAt: text(result.generated_at, "not generated"),
    edrState: normalizeEdrState(text(edrState.state, "unknown")),
    summary: {
      inputEvents: numberValue(summary.input_event_count),
      events: numberValue(summary.valid_event_count),
      alerts: numberValue(summary.alert_count),
      incidents: numberValue(summary.incident_count),
      highestRisk: numberValue(summary.highest_risk_score),
      dlq: numberValue(summary.dlq_event_count),
      privacyMasks: numberValue(summary.privacy_mask_action_count),
      flowEvents: numberValue(summary.flow_event_count),
      l7Events: numberValue(summary.l7_event_count),
      decryptionEvents: numberValue(summary.decryption_event_count),
      responseActions: numberValue(summary.response_action_count),
      aiPredictions: numberValue(summary.ai_prediction_count),
      predictedHighOrCritical: numberValue(summary.predicted_high_or_critical_count)
    },
    alerts: arrayOfRecords(result.alerts).map(toAlert),
    endpointRisk,
    events: arrayOfRecords(result.events).map(toEventRow),
    dlqEvents: arrayOfRecords(result.dlq_events).map(toDlqEvent),
    processTrees: arrayOfRecords(result.process_trees).map(toProcessTreeRow),
    incidents: arrayOfRecords(result.incidents).map(toIncident),
    timeline: arrayOfRecords(siem.correlation_timeline).map(toTimelineItem),
    queryFindings: arrayOfRecords(siem.query_findings).map(toQueryFinding),
    mitreDistribution: arrayOfRecords(result.mitre_distribution).map((item) => ({
      label: text(item.tactic, "unknown tactic"),
      count: numberValue(item.count)
    })),
    topDomains: arrayOfRecords(result.top_suspicious_domains).map((item) => ({
      label: text(item.domain, "unknown domain"),
      count: numberValue(item.count)
    })),
    topIps: arrayOfRecords(result.top_suspicious_ips).map((item) => ({
      label: text(item.ip, "unknown ip"),
      count: numberValue(item.count)
    })),
    responseActions: arrayOfRecords(responsePlan.actions).map(toResponseAction),
    topology: {
      nodes: topologyNodes,
      edges: arrayOfRecords(topology.edges).map(toTopologyEdge),
      summary: {
        endpointCount: numberValue(topologySummary.endpoint_count),
        externalDestinationCount: numberValue(topologySummary.external_destination_count),
        alertEdgeCount: numberValue(topologySummary.alert_edge_count)
      }
    },
    pipeline: {
      compression: text(pipeline.compression, "none"),
      rawBytes: numberValue(pipeline.raw_bytes),
      compressedBytes: numberValue(pipeline.compressed_bytes),
      compressionRatio: numberValue(pipeline.compression_ratio),
      shipStatus: text(pipeline.ship_status, "not_requested")
    },
    telemetry: {
      customerId: text(telemetry.customer_id, "-"),
      tenantId: text(telemetry.tenant_id, "-"),
      agentVersion: text(telemetry.agent_version, "-"),
      payloadVersion: text(telemetry.payload_version, "-"),
      schemaVersion: text(telemetry.schema_version, "-")
    },
    aiSummary: {
      model: text(ai.model, "not_available"),
      predictionCount: numberValue(ai.prediction_count),
      highOrCriticalCount: numberValue(ai.high_or_critical_count),
      note: text(ai.note, "")
    },
    report: {
      htmlPath: text(report.latest_html_path, "-"),
      markdownPath: text(report.latest_markdown_path, "-")
    },
    source: options.sourceOverride ?? sourceLabel(input)
  };
}
