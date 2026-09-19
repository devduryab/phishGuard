import type {
  AiStatus,
  AssessmentResult,
  DatasetInfo,
  ScanRecord,
  ScanResult,
  ScanSummary,
  Weights,
} from "./types";

async function parse<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => null);

  if (!response.ok) {
    const message =
      body && typeof body === "object" && "error" in body
        ? String((body as { error: unknown }).error)
        : `Request failed (${response.status})`;
    throw new Error(message);
  }

  return body as T;
}

export async function scanUrl(url: string): Promise<ScanResult> {
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  return parse<ScanResult>(response);
}

export async function fetchHistory(): Promise<ScanRecord[]> {
  const response = await fetch("/api/history", { cache: "no-store" });
  return parse<ScanRecord[]>(response);
}

export async function summarizeScan(scanId: number): Promise<ScanSummary> {
  const response = await fetch("/api/summarize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_id: scanId }),
  });
  return parse<ScanSummary>(response);
}

export async function runAssessment(options?: {
  threshold?: number;
  phishingLimit?: number;
  legitLimit?: number;
}): Promise<AssessmentResult> {
  const response = await fetch("/api/assessment/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      threshold: options?.threshold,
      phishing_limit: options?.phishingLimit,
      legit_limit: options?.legitLimit,
    }),
  });
  return parse<AssessmentResult>(response);
}

export async function fetchDatasetInfo(): Promise<DatasetInfo> {
  const response = await fetch("/api/assessment/dataset", { cache: "no-store" });
  return parse<DatasetInfo>(response);
}

export async function fetchAiStatus(): Promise<AiStatus> {
  const response = await fetch("/api/ai-status", { cache: "no-store" });
  return parse<AiStatus>(response);
}

export async function fetchWeights(): Promise<Weights> {
  const response = await fetch("/api/weights", { cache: "no-store" });
  return parse<Weights>(response);
}
