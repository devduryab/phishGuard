import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { EvalCounts } from "@/lib/types";

function Cell({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: number;
  hint: string;
  tone: "good" | "bad" | "neutral";
}) {
  const toneClass = {
    good: "border-risk-low/30 bg-risk-low-surface",
    bad: "border-risk-high/30 bg-risk-high-surface",
    neutral: "bg-muted/40",
  }[tone];

  const valueClass = {
    good: "text-risk-low",
    bad: "text-risk-high",
    neutral: "",
  }[tone];

  return (
    <div className={`rounded-lg border p-3 ${toneClass}`}>
      <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted-foreground">
        {label}
      </p>
      <p className={`tnum mt-1.5 font-mono text-2xl font-semibold leading-none ${valueClass}`}>
        {value}
      </p>
      <p className="mt-1.5 text-[11px] leading-snug text-muted-foreground">{hint}</p>
    </div>
  );
}

export function ConfusionMatrix({ counts }: { counts: EvalCounts }) {
  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-sm font-medium">Confusion matrix</CardTitle>
        <p className="text-xs leading-relaxed text-muted-foreground">
          The same results as counts rather than percentages. The two green boxes are
          correct decisions, the two red boxes are mistakes, and all four add up to the
          full test set.
        </p>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-3">
        <Cell
          label="True positives"
          value={counts.tp}
          hint="Phishing, correctly flagged"
          tone="good"
        />
        <Cell
          label="False negatives"
          value={counts.fn}
          hint="Phishing the system missed"
          tone="bad"
        />
        <Cell
          label="True negatives"
          value={counts.tn}
          hint="Legitimate, correctly cleared"
          tone="good"
        />
        <Cell
          label="False positives"
          value={counts.fp}
          hint="Legitimate, wrongly flagged"
          tone={counts.fp > 0 ? "bad" : "neutral"}
        />
      </CardContent>
    </Card>
  );
}
