export function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  const minute = String(date.getMinutes()).padStart(2, "0");
  return `${month}-${day} ${hour}:${minute}`;
}

export function formatBytes(value: number): string {
  if (!value) return "-";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB`;
  return `${value} B`;
}

export function clamp(value: number): number {
  return Math.min(100, Math.max(0, value));
}

export function fileName(value: string): string {
  return value.split(/[\/]/).pop() || value;
}

export function stateLabel(state: string): string {
  if (state === "alert") return "alert";
  if (state === "observed") return "observed";
  return "not detected";
}
