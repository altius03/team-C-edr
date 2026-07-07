import type { EdrState, Severity } from "./dashboardTypes";

export function recordOrEmpty(value: unknown): Readonly<Record<string, unknown>> {
  return isRecord(value) ? value : {};
}

export function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function arrayOfRecords(value: unknown): readonly Readonly<Record<string, unknown>>[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

export function arrayOfText(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function text(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

export function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export function normalizeSeverity(value: string): Severity {
  const normalized = value.toLowerCase();
  switch (normalized) {
    case "critical":
    case "warning":
    case "suspicious":
    case "info":
      return normalized;
    default:
      return "info";
  }
}

export function normalizeEdrState(value: string): EdrState {
  const normalized = value.toLowerCase();
  switch (normalized) {
    case "red":
    case "yellow":
    case "green":
      return normalized;
    default:
      return "unknown";
  }
}

export function normalizeTopologyState(value: string): string {
  const normalized = value.toLowerCase().replace(/_/g, "-");
  if (normalized === "red") return "alert";
  return normalized;
}

export function sourceLabel(input: Readonly<Record<string, unknown>>): string {
  const source = text(input.source, "latest CLI run");
  if (source === "event_file") return `${numberValue(input.raw_event_count)} events / offline sample`;
  if (source === "local_windows") return "local Windows telemetry";
  if (source === "pcap_file") return "PCAP file telemetry";
  if (source === "l7_file") return "decrypted L7 records";
  return source;
}

export function hostLabel(hostId: string, displayName: string): string {
  const fallback: Readonly<Record<string, string>> = {
    "endpoint-01": "황건하 PC",
    "endpoint-02": "박소연 Laptop",
    "endpoint-03": "이혜령 Workstation",
    "endpoint-04": "이주호-Desktop"
  };
  if (isReadableLabel(displayName)) {
    return displayName;
  }
  return fallback[hostId.toLowerCase()] ?? hostId;
}

function isReadableLabel(value: string): boolean {
  if (!value) return false;
  if (value.includes("\uFFFD")) return false;
  if (/[\u3130-\u318f\uac00-\ud7af]/.test(value)) return true;
  const noisyCharacters = [...value].filter((character) => character === "?");
  return noisyCharacters.length <= Math.max(1, Math.floor(value.length / 3));
}
