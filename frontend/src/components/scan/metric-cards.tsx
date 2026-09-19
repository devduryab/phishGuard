import { Card } from "@/components/ui/card";
import type { Contribution } from "./contribution-bar";

const DESCRIPTIONS: Record<string, string> = {
  rule: "Hand-written URL heuristics",
  ml: "RandomForest on URL features",
  security: "Live HTTPS & header checks",
};

export function MetricCards({ contributions }: { contributions: Contribution[] }) {
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      {contributions.map((item) => (
        <Card key={item.key} className="gap-0 p-4">
          <div className="flex items-start justify-between gap-2">
            <span className="text-sm font-medium">{item.label}</span>
            <span className="tnum shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              ×{item.weight.toFixed(2)}
            </span>
          </div>

          <p className="mt-1 text-xs text-muted-foreground">{DESCRIPTIONS[item.key]}</p>

          <div className="mt-4 flex items-baseline gap-1.5">
            <span className="tnum font-mono text-2xl font-semibold leading-none tracking-tight">
              {item.raw}
            </span>
            <span className="font-mono text-xs text-muted-foreground">/100</span>
          </div>

          <div className="mt-3 h-1 w-full overflow-hidden rounded-full bg-muted">
            <div
              className="h-full rounded-full bg-foreground/70 transition-[width] duration-700 ease-out"
              style={{ width: `${Math.max(0, Math.min(100, item.raw))}%` }}
            />
          </div>

          <p className="tnum mt-2.5 font-mono text-[11px] text-muted-foreground">
            contributes +{(item.raw * item.weight).toFixed(2)}
          </p>
        </Card>
      ))}
    </div>
  );
}
