import { Radar } from "lucide-react";

import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

export function ScanEmptyState() {
  return (
    <Card className="items-center gap-3 border-dashed px-6 py-14 text-center shadow-none">
      <span className="flex size-11 items-center justify-center rounded-full border bg-muted/50">
        <Radar className="size-5 text-muted-foreground" strokeWidth={1.75} />
      </span>
      <div className="space-y-1">
        <p className="text-sm font-medium">No analysis yet</p>
        <p className="mx-auto max-w-sm text-xs leading-relaxed text-muted-foreground">
          Enter a URL above to run the rule engine, the machine-learning classifier and
          the passive security checks. Results are saved to your local scan history.
        </p>
      </div>
    </Card>
  );
}

export function ScanSkeleton() {
  return (
    <div className="space-y-4">
      <Card className="gap-0 p-0">
        <div className="flex flex-col items-center gap-6 p-6 sm:flex-row sm:gap-8">
          <Skeleton className="size-[132px] shrink-0 rounded-full" />
          <div className="w-full flex-1 space-y-3">
            <Skeleton className="h-6 w-40" />
            <Skeleton className="h-4 w-full max-w-md" />
            <Skeleton className="h-7 w-64" />
          </div>
        </div>
        <div className="border-t p-6">
          <Skeleton className="h-2.5 w-full rounded-full" />
        </div>
      </Card>

      <div className="grid gap-3 sm:grid-cols-3">
        {[0, 1, 2].map((index) => (
          <Skeleton key={index} className="h-[150px] rounded-xl" />
        ))}
      </div>

      <Skeleton className="h-52 rounded-xl" />
    </div>
  );
}
