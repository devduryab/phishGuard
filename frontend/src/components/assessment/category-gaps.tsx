import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { CategoryResult } from "@/lib/types";

function rateColour(rate: number) {
  if (rate >= 75) return "bg-risk-low";
  if (rate >= 40) return "bg-risk-medium";
  return "bg-risk-high";
}

export function CategoryGaps({ categories }: { categories: CategoryResult[] }) {
  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-sm font-medium">Detection gaps by attack type</CardTitle>
        <p className="text-xs leading-relaxed text-muted-foreground">
          Real phishing URLs grouped by the structural trait a detector could use.
          Low bars are the attack types this system does not catch.
        </p>
      </CardHeader>
      <CardContent className="space-y-3.5">
        {categories.map((category) => (
          <div key={category.category} className="space-y-1.5">
            <div className="flex items-baseline justify-between gap-3">
              <span className="text-sm">{category.label}</span>
              <span className="tnum shrink-0 font-mono text-xs text-muted-foreground">
                {category.detected}/{category.total} · {category.detection_rate}%
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full rounded-full transition-[width] duration-700 ease-out ${rateColour(category.detection_rate)}`}
                style={{ width: `${Math.max(2, category.detection_rate)}%` }}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
