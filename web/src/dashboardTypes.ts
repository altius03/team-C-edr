export type Severity = "critical" | "warning" | "suspicious" | "info";
export type EdrState = "red" | "yellow" | "green" | "unknown";

export type Alert = {
  readonly alertId: string;
  readonly ruleId: string;
  readonly title: string;
  readonly host: string;
  readonly hostId: string;
  readonly eventTime: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly mitre: readonly string[];
  readonly evidence: readonly string[];
};

export type EndpointRisk = {
  readonly host: string;
  readonly hostId: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly alerts: number;
  readonly incidents: number;
  readonly topRules: readonly string[];
  readonly lastEventTime: string;
};

export type TopologyNode = {
  readonly id: string;
  readonly label: string;
  readonly layer: string;
  readonly state: string;
  readonly riskScore: number;
  readonly alertCount: number;
};

export type TopologyEdge = {
  readonly source: string;
  readonly sourceLabel: string;
  readonly target: string;
  readonly protocol: string;
  readonly state: string;
  readonly eventCount: number;
  readonly alertCount: number;
  readonly bytesOut: number;
};

export type EventRow = {
  readonly eventId: string;
  readonly eventTime: string;
  readonly host: string;
  readonly hostId: string;
  readonly eventType: string;
  readonly processName: string;
  readonly destination: string;
  readonly bytesOut: number;
};

export type DlqEvent = {
  readonly eventId: string;
  readonly index: number;
  readonly code: string;
  readonly errors: readonly string[];
};

export type ProcessTreeRow = {
  readonly eventId: string;
  readonly eventTime: string;
  readonly host: string;
  readonly hostId: string;
  readonly parentProcess: string;
  readonly processName: string;
  readonly processPath: string;
  readonly signed: boolean;
};

export type IncidentStage = {
  readonly stage: string;
  readonly summary: string;
};

export type Incident = {
  readonly incidentId: string;
  readonly host: string;
  readonly hostId: string;
  readonly severity: Severity;
  readonly riskScore: number;
  readonly category: string;
  readonly stages: readonly IncidentStage[];
  readonly evidence: readonly string[];
};

export type TimelineItem = {
  readonly time: string;
  readonly host: string;
  readonly stage: string;
  readonly summary: string;
  readonly severity: Severity;
};

export type CountRow = {
  readonly label: string;
  readonly count: number;
};

export type ResponseAction = {
  readonly actionType: string;
  readonly host: string;
  readonly ruleId: string;
  readonly mode: string;
  readonly status: string;
  readonly description: string;
};

export type PipelineDelivery = {
  readonly compression: string;
  readonly rawBytes: number;
  readonly compressedBytes: number;
  readonly compressionRatio: number;
  readonly shipStatus: string;
};

export type TelemetryMetadata = {
  readonly customerId: string;
  readonly tenantId: string;
  readonly agentVersion: string;
  readonly payloadVersion: string;
  readonly schemaVersion: string;
};

export type AiSummary = {
  readonly model: string;
  readonly predictionCount: number;
  readonly highOrCriticalCount: number;
  readonly note: string;
};

export type QueryFinding = {
  readonly queryId: string;
  readonly title: string;
  readonly ruleId: string;
  readonly severity: Severity;
  readonly host: string;
  readonly hostId: string;
  readonly summary: string;
  readonly evidenceCount: number;
  readonly alertCount: number;
  readonly lastEventTime: string;
};

export type TopologySummary = {
  readonly endpointCount: number;
  readonly externalDestinationCount: number;
  readonly alertEdgeCount: number;
};

export type DashboardResult = {
  readonly status: string;
  readonly decision: string;
  readonly generatedAt: string;
  readonly edrState: EdrState;
  readonly summary: {
    readonly inputEvents: number;
    readonly events: number;
    readonly alerts: number;
    readonly incidents: number;
    readonly highestRisk: number;
    readonly dlq: number;
    readonly privacyMasks: number;
    readonly flowEvents: number;
    readonly l7Events: number;
    readonly decryptionEvents: number;
    readonly responseActions: number;
    readonly aiPredictions: number;
    readonly predictedHighOrCritical: number;
  };
  readonly alerts: readonly Alert[];
  readonly endpointRisk: readonly EndpointRisk[];
  readonly events: readonly EventRow[];
  readonly dlqEvents: readonly DlqEvent[];
  readonly processTrees: readonly ProcessTreeRow[];
  readonly incidents: readonly Incident[];
  readonly timeline: readonly TimelineItem[];
  readonly queryFindings: readonly QueryFinding[];
  readonly mitreDistribution: readonly CountRow[];
  readonly topDomains: readonly CountRow[];
  readonly topIps: readonly CountRow[];
  readonly responseActions: readonly ResponseAction[];
  readonly topology: {
    readonly nodes: readonly TopologyNode[];
    readonly edges: readonly TopologyEdge[];
    readonly summary: TopologySummary;
  };
  readonly pipeline: PipelineDelivery;
  readonly telemetry: TelemetryMetadata;
  readonly aiSummary: AiSummary;
  readonly report: {
    readonly htmlPath: string;
    readonly markdownPath: string;
  };
  readonly source: string;
};
