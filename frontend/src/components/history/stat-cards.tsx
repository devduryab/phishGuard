import { Card } from "@/components/ui/card";
import { formatRelative } from "@/lib/risk";
import type { ScanRecord } from "@/lib/types";

function Stat({
  label,
  value,
  hint,
  accent,
  compact,
}: {
  label: string;
  value: string;
  hint?: string;
  accent?: string;
  compact?: boolean;
}) {
  return (
    <Card className="gap-0 p-4">
      <span className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
        {label}
      </span>
      <span
        className={`tnum mt-2 font-mono font-semibold leading-none tracking-tight ${
          compact ? "text-base" : "text-2xl"
        } ${accent ?? ""}`}
      >
        {value}
      </span>
      {hint ? (
        <span className="mt-1.5 block truncate text-xs text-muted-foreground" title={hint}>
          {hint}
        </span>
      ) : null}
    </Card>
  );
}

export function StatCards({ scans }: { scans: ScanRecord[] }) {
  const total = scans.length;
  const high = scans.filter((scan) => scan.risk_level === "HIGH").length;
  const medium = scans.filter((scan) => scan.risk_level === "MEDIUM").length;
  const average =
    total === 0 ? 0 : scans.reduce((sum, scan) => sum + scan.final_score, 0) / total;
  const latest = scans[0];

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Stat label="Total scans" value={String(total)} hint="Stored locally in SQLite" />
      <Stat
        label="High risk"
        value={String(high)}
        hint={`${medium} medium risk`}
        accent={high > 0 ? "text-risk-high" : undefined}
      />
      <Stat
        label="Average score"
        value={average.toFixed(1)}
        hint="Across all scans"
      />
      <Stat
        label="Last scan"
        compact
        value={latest ? formatRelative(latest.created_at) : "—"}
        hint={latest ? latest.url.replace(/^https?:\/\//, "") : "No scans yet"}
      />
    </div>
  );
}
