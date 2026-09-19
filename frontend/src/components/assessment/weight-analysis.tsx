import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { WeightOption } from "@/lib/types";

export function WeightAnalysis({ options }: { options: WeightOption[] }) {
  const current = options.find((option) => option.is_current);
  const best = options.find((option) => option.is_best);
  const recallGain =
    current && best ? Math.round((best.recall - current.recall) * 10) / 10 : 0;
  const falsePositiveCost =
    current && best ? best.counts.fp - current.counts.fp : 0;

  // Only worth surfacing as a finding if acting on it would move the needle.
  // A sub-3-point gain reads as advice when it is really noise.
  const worthChanging = recallGain >= 3;

  return (
    <Card className="gap-0 overflow-hidden pb-0">
      <CardHeader className="gap-1 pb-4">
        <CardTitle className="text-sm font-medium">Scoring weight analysis</CardTitle>
        <p className="text-xs leading-relaxed text-muted-foreground">
          The same URLs re-scored under different rule/ML weightings. This separates
          &ldquo;the detector cannot see these attacks&rdquo; from &ldquo;the detector
          sees them but the scoring formula buries the signal&rdquo;.
        </p>
      </CardHeader>

      {worthChanging ? (
        <div className="mx-6 mb-4 rounded-lg border border-risk-medium/30 bg-risk-medium-surface px-3 py-2.5">
          <p className="text-xs leading-relaxed text-risk-medium">
            <span className="font-medium">Finding:</span> rebalancing to{" "}
            <span className="font-mono">
              {best?.rule_weight.toFixed(2)}/{best?.ml_weight.toFixed(2)}
            </span>{" "}
            would raise recall by <span className="font-mono">{recallGain}</span>{" "}
            percentage points without retraining the model
            {falsePositiveCost > 0
              ? `, at a cost of ${falsePositiveCost} more false positives`
              : ""}
            .
          </p>
        </div>
      ) : current ? (
        <div className="mx-6 mb-4 rounded-lg border bg-muted/40 px-3 py-2.5">
          <p className="text-xs leading-relaxed text-muted-foreground">
            The current weighting is at or near the best available balance. No
            alternative in this table improves recall by more than{" "}
            <span className="font-mono">{Math.max(recallGain, 0)}</span> percentage
            points, so the remaining misses are a detection limitation rather than a
            scoring one.
          </p>
        </div>
      ) : null}

      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs">Rule / ML</TableHead>
              <TableHead className="text-right text-xs">Recall</TableHead>
              <TableHead className="text-right text-xs">Precision</TableHead>
              <TableHead className="text-right text-xs">F1</TableHead>
              <TableHead className="text-right text-xs">Missed</TableHead>
              <TableHead className="text-right text-xs">False pos.</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {options.map((option) => (
              <TableRow
                key={`${option.rule_weight}-${option.ml_weight}`}
                className={cn(
                  "hover:bg-transparent",
                  option.is_best && "bg-risk-low-surface/40",
                )}
              >
                <TableCell className="font-mono text-xs">
                  {option.rule_weight.toFixed(2)} / {option.ml_weight.toFixed(2)}
                  {option.is_current ? (
                    <span className="ml-2 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                      current
                    </span>
                  ) : null}
                  {option.is_best ? (
                    <span className="ml-2 rounded border border-risk-low/30 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em] text-risk-low">
                      best F1
                    </span>
                  ) : null}
                </TableCell>
                <TableCell
                  className={cn(
                    "tnum text-right font-mono text-xs",
                    option.recall < 50 && "text-risk-high",
                  )}
                >
                  {option.recall}%
                </TableCell>
                <TableCell className="tnum text-right font-mono text-xs">
                  {option.precision}%
                </TableCell>
                <TableCell className="tnum text-right font-mono text-xs font-medium">
                  {option.f1}%
                </TableCell>
                <TableCell className="tnum text-right font-mono text-xs text-muted-foreground">
                  {option.counts.fn}
                </TableCell>
                <TableCell className="tnum text-right font-mono text-xs text-muted-foreground">
                  {option.counts.fp}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
}
