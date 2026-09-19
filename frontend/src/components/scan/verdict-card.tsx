"use client";

import { Copy } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { riskBadgeClass, riskCopy, riskTextClass } from "@/lib/risk";
import type { RiskLevel, Weights } from "@/lib/types";
import { ContributionBar, buildContributions } from "./contribution-bar";
import { ScoreRing } from "./score-ring";

export function VerdictCard({
  url,
  level,
  score,
  ruleScore,
  mlScore,
  securityScore,
  weights,
}: {
  url: string;
  level: RiskLevel;
  score: number;
  ruleScore: number;
  mlScore: number;
  securityScore: number;
  weights: Weights;
}) {
  const copy = riskCopy[level];

  async function copyUrl() {
    try {
      await navigator.clipboard.writeText(url);
      toast.success("URL copied to clipboard");
    } catch {
      toast.error("Could not copy URL");
    }
  }

  return (
    <Card className="gap-0 overflow-hidden p-0">
      <div className="flex flex-col items-center gap-6 p-6 sm:flex-row sm:items-center sm:gap-8">
        <ScoreRing score={score} level={level} />

        <div className="w-full min-w-0 flex-1 space-y-3 text-center sm:text-left">
          <div className="flex flex-col items-center gap-2 sm:flex-row sm:items-center">
            <span
              className={`inline-flex items-center rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-medium uppercase tracking-[0.1em] ${riskBadgeClass(level)}`}
            >
              {level}
            </span>
            <h2 className={`text-lg font-semibold tracking-tight ${riskTextClass(level)}`}>
              {copy.label}
            </h2>
          </div>

          <p className="text-sm leading-relaxed text-muted-foreground">{copy.blurb}</p>

          <div className="flex min-w-0 items-center justify-center gap-1.5 sm:justify-start">
            <code className="min-w-0 flex-1 truncate rounded border bg-muted/50 px-2 py-1 text-left font-mono text-xs sm:max-w-md sm:flex-none">
              {url}
            </code>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-7 shrink-0 text-muted-foreground"
                  onClick={copyUrl}
                  aria-label="Copy analysed URL"
                >
                  <Copy className="size-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Copy URL</TooltipContent>
            </Tooltip>
          </div>
        </div>
      </div>

      <Separator />

      <div className="p-6">
        <ContributionBar
          contributions={buildContributions(
            { rule: ruleScore, ml: mlScore, security: securityScore },
            weights,
          )}
        />
      </div>
    </Card>
  );
}
