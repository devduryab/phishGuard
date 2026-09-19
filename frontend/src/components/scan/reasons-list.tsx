import { Check, TriangleAlert } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function ReasonsList({ reasons }: { reasons: string[] }) {
  const clean =
    reasons.length === 1 && reasons[0].startsWith("No strong suspicious");

  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-sm font-medium">Why this score</CardTitle>
        <p className="text-xs text-muted-foreground">
          Patterns the rule engine matched in the URL text itself.
        </p>
      </CardHeader>
      <CardContent className="px-0 pb-0">
        <ul className="divide-y border-t">
          {reasons.map((reason, index) => (
            <li key={index} className="flex items-start gap-3 px-6 py-3">
              {clean ? (
                <Check className="mt-0.5 size-4 shrink-0 text-risk-low" strokeWidth={2.25} />
              ) : (
                <TriangleAlert
                  className="mt-0.5 size-4 shrink-0 text-risk-medium"
                  strokeWidth={2.25}
                />
              )}
              <span className="text-sm leading-relaxed">{reason}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
