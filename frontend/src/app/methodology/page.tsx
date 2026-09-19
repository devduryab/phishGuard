import type { Metadata } from "next";

import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export const metadata: Metadata = {
  title: "Methodology — PhishGuard",
  description:
    "How the phishing risk score is calculated, which features the model uses, and the known limitations of the training data.",
};

const RULES = [
  { check: "URL length over 75 characters", points: 15 },
  { check: "Contains an “@” symbol", points: 20 },
  { check: "Hostname is a raw IP address", points: 20 },
  { check: "Three or more hyphens", points: 10 },
  { check: "Two or more account/security keywords", points: 15 },
  { check: "Not served over HTTPS", points: 15 },
];

const CHECKS = [
  { check: "Final response not over HTTPS", severity: "MEDIUM", points: 25 },
  { check: "TLS/SSL certificate could not be validated", severity: "HIGH", points: 35 },
  { check: "Host unreachable or request failed", severity: "MEDIUM", points: 20 },
  { check: "Missing Content-Security-Policy", severity: "LOW", points: 5 },
  { check: "Missing X-Content-Type-Options", severity: "LOW", points: 5 },
  { check: "Missing X-Frame-Options", severity: "LOW", points: 5 },
  { check: "Missing Referrer-Policy", severity: "LOW", points: 5 },
];

const USED_FEATURES = [
  "host_length",
  "dot_count",
  "hyphen_count",
  "digit_count",
  "has_ip",
  "https",
  "suspicious_words",
];

const EXCLUDED_FEATURES = [
  "path_length",
  "slash_count",
  "url_length",
  "at_count",
  "question_count",
  "equal_count",
];

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-xs font-medium uppercase tracking-[0.1em] text-muted-foreground">
      {children}
    </h2>
  );
}

export default function MethodologyPage() {
  return (
    <div className="mx-auto w-full max-w-3xl px-4 py-8 sm:px-6 lg:px-8 lg:py-10">
      <PageHeader
        title="Methodology"
        description="How a risk score is produced, what the machine-learning model actually learns from, and where this system is known to be weak."
      />

      <div className="mt-8 space-y-10">
        <section className="space-y-3">
          <SectionTitle>Scoring</SectionTitle>
          <Card>
            <CardContent className="space-y-4 text-sm leading-relaxed">
              <p>
                Three independent components each produce a score out of 100. They are
                combined into a single weighted result:
              </p>
              <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
{`final = (rule × 0.35) + (ml × 0.50) + (security × 0.15)`}
              </pre>
              <div className="grid gap-2 sm:grid-cols-3">
                {[
                  { band: "LOW", range: "0 – 39" },
                  { band: "MEDIUM", range: "40 – 69" },
                  { band: "HIGH", range: "70 – 100" },
                ].map((item) => (
                  <div key={item.band} className="rounded-lg border px-3 py-2">
                    <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
                      {item.band}
                    </p>
                    <p className="tnum mt-0.5 font-mono text-sm">{item.range}</p>
                  </div>
                ))}
              </div>
              <p className="text-muted-foreground">
                These weights were not chosen by intuition. An earlier split of
                0.60&nbsp;/&nbsp;0.25&nbsp;/&nbsp;0.15 gave the rule engine most of the
                influence, and the self-audit measured the result: only 9.2% of real
                phishing URLs were detected, because the rule engine recognises older
                phishing patterns while the classifier &mdash; capped at 0.25 &mdash;
                could not reach the threshold alone. Rebalancing raised recall to 82.4%
                without retraining the model.
              </p>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <SectionTitle>Rule engine</SectionTitle>
          <Card className="gap-0 overflow-hidden pb-0">
            <CardHeader className="gap-1 pb-4">
              <CardTitle className="text-sm font-medium">
                Hand-written URL heuristics
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                Applied to the URL text only. Points accumulate and are capped at 100.
              </p>
            </CardHeader>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-xs">Condition</TableHead>
                  <TableHead className="w-24 text-right text-xs">Points</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {RULES.map((rule) => (
                  <TableRow key={rule.check} className="hover:bg-transparent">
                    <TableCell className="text-sm">{rule.check}</TableCell>
                    <TableCell className="tnum text-right font-mono text-xs">
                      +{rule.points}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </section>

        <section className="space-y-3">
          <SectionTitle>Machine-learning model</SectionTitle>
          <Card>
            <CardContent className="space-y-5 text-sm leading-relaxed">
              <div className="space-y-2">
                <p>
                  A <span className="font-medium">RandomForest classifier</span> (200 trees,
                  balanced class weights) trained on the{" "}
                  <span className="font-medium">PhiUSIIL Phishing URL Dataset</span> from the
                  UCI Machine Learning Repository — 235,795 labelled URLs (134,850 legitimate,
                  100,945 phishing), licensed CC BY 4.0.
                </p>
                <p className="tnum font-mono text-xs text-muted-foreground">
                  Held-out test accuracy: 95% · precision 0.94–0.97 · recall 0.92–0.98
                </p>
              </div>

              <Separator />

              <div className="grid gap-5 sm:grid-cols-2">
                <div className="space-y-2">
                  <p className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
                    Features used
                  </p>
                  <ul className="flex flex-wrap gap-1.5">
                    {USED_FEATURES.map((feature) => (
                      <li
                        key={feature}
                        className="rounded border bg-muted/40 px-1.5 py-0.5 font-mono text-[11px]"
                      >
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="space-y-2">
                  <p className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
                    Deliberately excluded
                  </p>
                  <ul className="flex flex-wrap gap-1.5">
                    {EXCLUDED_FEATURES.map((feature) => (
                      <li
                        key={feature}
                        className="rounded border border-dashed px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground line-through"
                      >
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <SectionTitle>Known data limitations</SectionTitle>
          <Card>
            <CardContent className="space-y-3 text-sm leading-relaxed">
              <p>
                Every legitimate URL in the training set is a bare root domain served over
                HTTPS — none contain a path, a query string or an{" "}
                <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">@</code>{" "}
                symbol. Any feature that can only be non-zero when a path or query is present
                therefore has <span className="font-medium">no legitimate counter-examples</span>{" "}
                to learn from.
              </p>
              <p>
                Trained naively, the model exploited this: adding a single trailing{" "}
                <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">/</code> to a
                clean domain flipped its prediction from roughly 0% to 100% phishing. Similar
                shortcuts were found for the{" "}
                <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">www.</code>{" "}
                prefix and for query strings.
              </p>
              <p>
                Those features were removed and the affected behaviour is covered by
                regression tests. Reported accuracy dropped from an inflated 99–100% to a
                more honest 95%. Path and query heuristics are handled by the rule engine
                instead, which is not learned from this dataset and so is not subject to the
                same bias.
              </p>
              <p className="text-muted-foreground">
                This system estimates risk. It is not a guarantee, and both false positives
                and false negatives are possible.
              </p>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <SectionTitle>Passive security checks</SectionTitle>
          <Card className="gap-0 overflow-hidden pb-0">
            <CardHeader className="gap-1 pb-4">
              <CardTitle className="text-sm font-medium">
                Performed against the live response
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                One HTTP GET request. No exploitation, credential testing or port scanning.
              </p>
            </CardHeader>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-xs">Observation</TableHead>
                  <TableHead className="w-24 text-xs">Severity</TableHead>
                  <TableHead className="w-20 text-right text-xs">Points</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {CHECKS.map((item) => (
                  <TableRow key={item.check} className="hover:bg-transparent">
                    <TableCell className="text-sm">{item.check}</TableCell>
                    <TableCell className="font-mono text-[11px] uppercase tracking-[0.08em] text-muted-foreground">
                      {item.severity}
                    </TableCell>
                    <TableCell className="tnum text-right font-mono text-xs">
                      +{item.points}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </section>
      </div>
    </div>
  );
}
