"use client";

import { useEffect, useState } from "react";
import { Cpu, Sparkles } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { summarizeScan } from "@/lib/api";
import type { ScanSummary } from "@/lib/types";

export function AiSummary({ scanId }: { scanId: number }) {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    setSummary(null);
    setFailed(false);

    summarizeScan(scanId)
      .then((data) => {
        if (active) setSummary(data);
      })
      .catch(() => {
        if (active) setFailed(true);
      });

    return () => {
      active = false;
    };
  }, [scanId]);

  if (failed) return null;

  const isLlm = summary?.source === "llm";

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3 space-y-0">
        <div className="flex items-center gap-2">
          <Sparkles className="size-4 text-muted-foreground" strokeWidth={2} />
          <CardTitle className="text-sm font-medium">Plain-English summary</CardTitle>
        </div>

        {summary ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                <Cpu className="size-3" />
                {isLlm ? summary.model ?? "local model" : "rule-based"}
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-xs">
              {isLlm
                ? "Written by a language model running locally on this machine, using only the scan data above."
                : summary.reason ??
                  "The local language model was unavailable, so this summary was generated directly from the scan data."}
            </TooltipContent>
          </Tooltip>
        ) : null}
      </CardHeader>

      <CardContent>
        {summary ? (
          <p className="text-sm leading-relaxed">{summary.summary}</p>
        ) : (
          <div className="space-y-2">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-[92%]" />
            <Skeleton className="h-4 w-[64%]" />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
