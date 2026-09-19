"use client";

import { useCallback, useEffect, useState } from "react";
import { CircleAlert, Play, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { CategoryGaps } from "@/components/assessment/category-gaps";
import { ConfusionMatrix } from "@/components/assessment/confusion-matrix";
import { HowToRead } from "@/components/assessment/how-to-read";
import { FailureList } from "@/components/assessment/failure-list";
import { WeightAnalysis } from "@/components/assessment/weight-analysis";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchDatasetInfo, runAssessment } from "@/lib/api";
import type { AssessmentResult, DatasetInfo } from "@/lib/types";

function MetricCard({
  label,
  question,
  value,
  hint,
  alarming,
}: {
  label: string;
  question: string;
  value: string;
  hint: string;
  alarming?: boolean;
}) {
  return (
    <Card className="gap-0 p-4">
      <span className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
        {label}
      </span>
      <span className="mt-1 text-xs leading-snug text-muted-foreground">{question}</span>
      <span
        className={`tnum mt-2.5 font-mono text-2xl font-semibold leading-none tracking-tight ${
          alarming ? "text-risk-high" : ""
        }`}
      >
        {value}
      </span>
      <span className="mt-1.5 text-xs text-muted-foreground">{hint}</span>
    </Card>
  );
}

export default function AssessmentPage() {
  const [dataset, setDataset] = useState<DatasetInfo | null>(null);
  const [result, setResult] = useState<AssessmentResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDatasetInfo().then(setDataset).catch(() => setDataset(null));
  }, []);

  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const data = await runAssessment({ phishingLimit: 250, legitLimit: 250 });
      setResult(data);
      toast.success(`Assessment complete — recall ${data.metrics.recall}%`);
    } catch (exception) {
      const message =
        exception instanceof Error ? exception.message : "Assessment failed";
      setError(message);
      toast.error("Assessment failed");
    } finally {
      setRunning(false);
    }
  }, []);

  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-8 sm:px-6 lg:px-8 lg:py-10">
      <PageHeader
        title="Self-Audit"
        description="Measures the detector against real phishing URLs from a live feed and real legitimate URLs, then reports where it fails and why."
        actions={
          <Button onClick={run} disabled={running} size="sm">
            <Play className={running ? "size-4 animate-pulse" : "size-4"} />
            {running ? "Running…" : "Run assessment"}
          </Button>
        }
      />

      <div className="mt-6 space-y-4">
        <Card>
          <CardContent className="space-y-3 text-sm leading-relaxed">
            <p className="text-muted-foreground">
              Phishing URLs come from the OpenPhish community feed; legitimate URLs
              combine the Tranco top-sites list with curated real deep links (article
              pages, repositories, sign-in pages) so the evaluation is not limited to
              bare domains.
            </p>
            <p className="text-muted-foreground">
              <span className="font-medium text-foreground">Scope:</span> no requests
              are made to any URL. Only the rule engine and the classifier are
              measured &mdash; the passive HTTPS and header checks need a live response
              and are therefore excluded.
            </p>
            {dataset ? (
              <div className="flex flex-wrap gap-x-5 gap-y-1 border-t pt-3 font-mono text-xs text-muted-foreground">
                <span>{dataset.phishing_available} phishing URLs available</span>
                <span>{dataset.curated_legitimate} curated legitimate URLs</span>
                <span>tranco: {dataset.tranco_present ? "loaded" : "missing"}</span>
              </div>
            ) : null}
          </CardContent>
        </Card>

        {error ? (
          <Alert variant="destructive">
            <CircleAlert />
            <AlertTitle>Assessment failed</AlertTitle>
            <AlertDescription className="font-mono text-xs">{error}</AlertDescription>
          </Alert>
        ) : null}

        {running ? (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[0, 1, 2, 3].map((index) => (
                <Skeleton key={index} className="h-[104px] rounded-xl" />
              ))}
            </div>
            <Skeleton className="h-64 rounded-xl" />
          </div>
        ) : null}

        {!running && result ? (
          <div className="space-y-4">
            <HowToRead />

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard
                label="Recall"
                question="How many real scams did it catch?"
                value={`${result.metrics.recall}%`}
                hint={`Caught ${result.counts.tp} of ${result.totals.phishing}. ${result.counts.fn} got through.`}
                alarming={result.metrics.recall < 50}
              />
              <MetricCard
                label="Precision"
                question="When it raised an alarm, was it right?"
                value={`${result.metrics.precision}%`}
                hint={`${result.counts.tp} of ${result.counts.tp + result.counts.fp} alarms were real phishing.`}
              />
              <MetricCard
                label="F1 score"
                question="The two above, blended into one number."
                value={`${result.metrics.f1}%`}
                hint="Used to compare settings at a glance."
                alarming={result.metrics.f1 < 50}
              />
              <MetricCard
                label="Evaluated"
                question="How big was the test?"
                value={String(result.totals.total)}
                hint={`${result.totals.phishing} known phishing · ${result.totals.legitimate} known safe`}
              />
            </div>

            {result.metrics.recall < 50 ? (
              <Alert>
                <ShieldAlert />
                <AlertTitle>Detection gap identified</AlertTitle>
                <AlertDescription className="leading-relaxed">
                  At the current weighting the system detects only{" "}
                  {result.metrics.recall}% of real phishing URLs, despite scoring far
                  higher on its own training benchmark. The weight analysis below
                  isolates the cause.
                </AlertDescription>
              </Alert>
            ) : null}

            <WeightAnalysis options={result.weight_analysis} />

            <div className="grid items-start gap-4 lg:grid-cols-2">
              <ConfusionMatrix counts={result.counts} />
              <CategoryGaps categories={result.categories} />
            </div>

            <div className="grid items-start gap-4 lg:grid-cols-2">
              <FailureList
                title="Missed phishing URLs"
                description="Real phishing that got through. Most have no visible warning signs in the address itself, which is exactly why they were missed."
                cases={result.false_negatives}
                emptyMessage="No phishing URLs were missed at this threshold."
              />
              <FailureList
                title="Wrongly flagged legitimate URLs"
                description="Safe sites treated as suspicious. These are typically genuine sign-in pages, which use the same words phishing sites imitate."
                cases={result.false_positives}
                emptyMessage="No legitimate URLs were wrongly flagged at this threshold."
              />
            </div>
          </div>
        ) : null}

        {!running && !result && !error ? (
          <Card className="items-center gap-3 border-dashed px-6 py-14 text-center shadow-none">
            <span className="flex size-11 items-center justify-center rounded-full border bg-muted/50">
              <ShieldAlert className="size-5 text-muted-foreground" strokeWidth={1.75} />
            </span>
            <div className="space-y-1">
              <p className="text-sm font-medium">No assessment run yet</p>
              <p className="mx-auto max-w-md text-xs leading-relaxed text-muted-foreground">
                Run the assessment to measure the detector against real phishing URLs
                and see which attack types it fails to catch.
              </p>
            </div>
          </Card>
        ) : null}
      </div>
    </div>
  );
}
