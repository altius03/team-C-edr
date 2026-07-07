import type { DashboardResult } from "./dashboardTypes";
import { adaptResult, type AdaptResultOptions } from "./resultNormalizer";

export type * from "./dashboardTypes";
export { adaptResult };

type DashboardFetchResponse = {
  readonly ok: boolean;
  json(): Promise<unknown>;
};

export type DashboardFetch = (input: string, init: { readonly signal: AbortSignal }) => Promise<DashboardFetchResponse>;

export type DashboardRuntime = {
  readonly apiBaseUrl: string;
  readonly allowDemoFallback: boolean;
};

const DEMO_FALLBACK_SOURCE = "demo-fallback";
const API_ERROR_SOURCE = "api_error";
const TRUTHY_ENV_VALUES = new Set(["1", "true", "yes", "on", "demo", "local"]);

export function emptyDashboardResult(options: AdaptResultOptions = {}): DashboardResult {
  return adaptResult({}, options);
}

export async function loadDashboardResult(signal: AbortSignal): Promise<DashboardResult> {
  return loadDashboardResultWithRuntime(signal, dashboardRuntimeFromEnv(), fetch);
}

export async function loadDashboardResultWithRuntime(
  signal: AbortSignal,
  runtime: DashboardRuntime,
  fetcher: DashboardFetch
): Promise<DashboardResult> {
  const apiResult = await fetchDashboardApi(signal, runtime, fetcher);
  if (apiResult) return apiResult;

  if (!runtime.allowDemoFallback) {
    return adaptResult({
      status: API_ERROR_SOURCE,
      decision: "api_unavailable",
      input: { source: API_ERROR_SOURCE }
    }, { sourceOverride: API_ERROR_SOURCE });
  }

  const fallbackResult = await fetchDemoFallback(signal, fetcher);
  return fallbackResult ?? emptyDashboardResult({
    includeDemoFallbackAssets: true,
    sourceOverride: DEMO_FALLBACK_SOURCE
  });
}

export function dashboardRuntimeFromEnv(): DashboardRuntime {
  return {
    apiBaseUrl: String(import.meta.env.VITE_LAYERTRACE_API_BASE_URL ?? import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, ""),
    allowDemoFallback: demoFallbackAllowed()
  };
}

async function fetchDashboardApi(signal: AbortSignal, runtime: DashboardRuntime, fetcher: DashboardFetch): Promise<DashboardResult | null> {
  try {
    const response = await fetcher(`${runtime.apiBaseUrl}/v1/dashboard/latest`, { signal });
    if (!response.ok) return null;
    return adaptResult(await response.json());
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    return null;
  }
}

async function fetchDemoFallback(signal: AbortSignal, fetcher: DashboardFetch): Promise<DashboardResult | null> {
  try {
    const response = await fetcher("/latest-result.json", { signal });
    if (!response.ok) return null;
    return adaptResult(await response.json(), {
      includeDemoFallbackAssets: true,
      sourceOverride: DEMO_FALLBACK_SOURCE
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    return null;
  }
}

function demoFallbackAllowed(): boolean {
  return TRUTHY_ENV_VALUES.has(String(import.meta.env.VITE_LAYERTRACE_ALLOW_DEMO_FALLBACK ?? "").trim().toLowerCase());
}
