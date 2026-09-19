import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { FailureCase } from "@/lib/types";

export function FailureList({
  title,
  description,
  cases,
  emptyMessage,
}: {
  title: string;
  description: string;
  cases: FailureCase[];
  emptyMessage: string;
}) {
  return (
    <Card className="gap-0 overflow-hidden pb-0">
      <CardHeader className="gap-1 pb-4">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>
        {cases.length ? (
          <p className="pt-0.5 font-mono text-[11px] text-muted-foreground">
            score = final · rule = rule engine · ml = classifier
          </p>
        ) : null}
      </CardHeader>

      {cases.length === 0 ? (
        <CardContent className="border-t pt-4 text-sm text-muted-foreground">
          {emptyMessage}
        </CardContent>
      ) : (
        <ScrollArea className="h-72 border-t">
          <ul className="divide-y">
            {cases.map((item, index) => (
              <li key={`${item.url}-${index}`} className="px-6 py-3">
                <p className="break-all font-mono text-xs leading-relaxed">{item.url}</p>
                <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-muted-foreground">
                  <span>score {item.score}</span>
                  <span>rule {item.rule_score}</span>
                  <span>ml {item.ml_score}</span>
                  {item.category ? (
                    <span className="rounded border px-1.5 py-0.5">{item.category}</span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </ScrollArea>
      )}
    </Card>
  );
}
