import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { severityDotClass, severityRank } from "@/lib/risk";
import type { Finding } from "@/lib/types";

export function FindingsList({ findings }: { findings: Finding[] }) {
  const sorted = [...findings].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity),
  );

  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-sm font-medium">Security findings</CardTitle>
        <p className="text-xs text-muted-foreground">
          Passive checks performed against the live response. No intrusive testing.
        </p>
      </CardHeader>
      <CardContent className="px-0 pb-0">
        <ul className="divide-y border-t">
          {sorted.map((finding, index) => (
            <li
              key={`${finding.title}-${index}`}
              className="flex gap-3 px-6 py-3 transition-colors hover:bg-muted/40"
            >
              <span
                className={`mt-[7px] size-1.5 shrink-0 rounded-full ${severityDotClass(finding.severity)}`}
                aria-hidden
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="text-sm font-medium">{finding.title}</span>
                  <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                    {finding.severity}
                  </span>
                </div>
                <p className="mt-1 break-words font-mono text-xs leading-relaxed text-muted-foreground">
                  {finding.detail}
                </p>
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
