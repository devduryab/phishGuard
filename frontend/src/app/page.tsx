"use client";

import { useEffect, useState } from "react";
import { CircleAlert } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AiSummary } from "@/components/scan/ai-summary";
import { FindingsList } from "@/components/scan/findings-list";
import { MetricCards } from "@/components/scan/metric-cards";
import { ReasonsList } from "@/components/scan/reasons-list";
import { ScanForm } from "@/components/scan/scan-form";
import { ScanEmptyState, ScanSkeleton } from "@/components/scan/states";
import { VerdictCard } from "@/components/scan/verdict-card";
import { buildContributions } from "@/components/scan/contribution-bar";
import { fetchWeights, scanUrl } from "@/lib/api";
import type { ScanResult, Weights } from "@/lib/types";

const FALLBACK_WEIGHTS: Weights = { rule: 0.6, ml: 0.25, security: 0.15 };

export default function ScannerPage() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [weights, setWeights] = useState<Weights>(FALLBACK_WEIGHTS);

  useEffect(() => {
    fetchWeights()
      .then(setWeights)
      .catch(() => setWeights(FALLBACK_WEIGHTS));
  }, []);

  async function handleScan(url: string) {
    setPending(true);
    setError(null);

    try {
      const scan = await scanUrl(url);
      setResult(scan);
      toast.success(`Analysis complete — ${scan.level.toLowerCase()} risk`);
    } catch (exception) {
      const message =
        exception instanceof Error ? exception.message : "Something went wrong";
      setError(message);
      setResult(null);
      toast.error("Analysis failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="mx-auto w-full max-w-4xl px-4 py-8 sm:px-6 lg:px-8 lg:py-10">
      <PageHeader
        title="URL Scanner"
        description="Analyse a web address for phishing indicators. Each result combines rule-based URL heuristics, a machine-learning classifier and passive security checks into one traceable risk score."
      />

      <div className="mt-6 space-y-4">
        <ScanForm onScan={handleScan} pending={pending} />

        {error ? (
          <Alert variant="destructive">
            <CircleAlert />
            <AlertTitle>Analysis failed</AlertTitle>
            <AlertDescription className="font-mono text-xs">{error}</AlertDescription>
          </Alert>
        ) : null}

        {pending ? <ScanSkeleton /> : null}

        {!pending && result ? (
          <div className="space-y-4">
            <VerdictCard
              url={result.url}
              level={result.level}
              score={result.score}
              ruleScore={result.rule_score}
              mlScore={result.ml_score}
              securityScore={result.security_score}
              weights={weights}
            />

            <AiSummary scanId={result.id} />

            <MetricCards
              contributions={buildContributions(
                {
                  rule: result.rule_score,
                  ml: result.ml_score,
                  security: result.security_score,
                },
                weights,
              )}
            />

            <div className="grid items-start gap-4 lg:grid-cols-2">
              <ReasonsList reasons={result.reasons} />
              <FindingsList findings={result.findings} />
            </div>
          </div>
        ) : null}

        {!pending && !result && !error ? <ScanEmptyState /> : null}
      </div>
    </div>
  );
}
