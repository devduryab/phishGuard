import type { RiskLevel, Severity } from "./types";

export const RISK_THRESHOLDS = { medium: 40, high: 70 } as const;

export const riskCopy: Record<RiskLevel, { label: string; blurb: string }> = {
  LOW: {
    label: "Low risk",
    blurb: "No strong phishing indicators were found in this URL.",
  },
  MEDIUM: {
    label: "Medium risk",
    blurb: "Some indicators are present. Treat this address with caution.",
  },
  HIGH: {
    label: "High risk",
    blurb: "Multiple strong phishing indicators were found. Avoid this address.",
  },
};

export function riskTextClass(level: RiskLevel) {
  return {
    LOW: "text-risk-low",
    MEDIUM: "text-risk-medium",
    HIGH: "text-risk-high",
  }[level];
}

export function riskBadgeClass(level: RiskLevel) {
  return {
    LOW: "border-risk-low/30 bg-risk-low-surface text-risk-low",
    MEDIUM: "border-risk-medium/30 bg-risk-medium-surface text-risk-medium",
    HIGH: "border-risk-high/30 bg-risk-high-surface text-risk-high",
  }[level];
}

export function riskStroke(level: RiskLevel) {
  return {
    LOW: "var(--risk-low)",
    MEDIUM: "var(--risk-medium)",
    HIGH: "var(--risk-high)",
  }[level];
}

export function severityDotClass(severity: Severity) {
  return {
    INFO: "bg-muted-foreground/40",
    LOW: "bg-muted-foreground/70",
    MEDIUM: "bg-risk-medium",
    HIGH: "bg-risk-high",
  }[severity];
}

export function severityRank(severity: Severity) {
  return { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 }[severity];
}

export function formatScore(value: number) {
  return Number.isInteger(value) ? value.toString() : value.toFixed(2);
}

export function formatTimestamp(raw: string) {
  // SQLite returns "YYYY-MM-DD HH:MM:SS" in UTC.
  const parsed = new Date(raw.replace(" ", "T") + "Z");
  if (Number.isNaN(parsed.getTime())) return raw;
  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(raw: string) {
  const parsed = new Date(raw.replace(" ", "T") + "Z");
  if (Number.isNaN(parsed.getTime())) return raw;

  const seconds = Math.round((Date.now() - parsed.getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatTimestamp(raw);
}
