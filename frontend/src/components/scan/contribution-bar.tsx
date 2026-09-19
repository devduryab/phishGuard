import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Weights } from "@/lib/types";

const SEGMENT_STYLES = [
  "bg-foreground/85",
  "bg-foreground/50",
  "bg-foreground/25",
] as const;

export interface Contribution {
  key: string;
  label: string;
  raw: number;
  weight: number;
}

export function buildContributions(
  scores: { rule: number; ml: number; security: number },
  weights: Weights,
): Contribution[] {
  return [
    { key: "rule", label: "Rule engine", raw: scores.rule, weight: weights.rule },
    { key: "ml", label: "ML model", raw: scores.ml, weight: weights.ml },
    { key: "security", label: "Security checks", raw: scores.security, weight: weights.security },
  ];
}

export function ContributionBar({ contributions }: { contributions: Contribution[] }) {
  const weighted = contributions.map((item) => item.raw * item.weight);
  const total = weighted.reduce((sum, value) => sum + value, 0);

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between">
        <span className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
          Score composition
        </span>
        <span className="tnum font-mono text-xs text-muted-foreground">
          {total.toFixed(2)} / 100
        </span>
      </div>

      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted">
        {contributions.map((item, index) => (
          <Tooltip key={item.key}>
            <TooltipTrigger asChild>
              <div
                className={SEGMENT_STYLES[index]}
                style={{ width: `${Math.max(0, Math.min(100, weighted[index]))}%` }}
              />
            </TooltipTrigger>
            <TooltipContent>
              {item.label}: {item.raw} × {item.weight} = {weighted[index].toFixed(2)}
            </TooltipContent>
          </Tooltip>
        ))}
      </div>

      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-3">
        {contributions.map((item, index) => (
          <div key={item.key} className="flex items-center gap-2">
            <span className={`size-2 shrink-0 rounded-[3px] ${SEGMENT_STYLES[index]}`} />
            <dt className="text-xs text-muted-foreground">{item.label}</dt>
            <dd className="tnum ml-auto font-mono text-xs font-medium">
              +{weighted[index].toFixed(2)}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
