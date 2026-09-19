"use client";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  formatTimestamp,
  riskBadgeClass,
  severityDotClass,
  severityRank,
} from "@/lib/risk";
import type { ScanRecord } from "@/lib/types";

export function ScanDetailDialog({
  scan,
  onOpenChange,
}: {
  scan: ScanRecord | null;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={Boolean(scan)} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] gap-0 overflow-hidden p-0 sm:max-w-2xl">
        {scan ? (
          <>
            <DialogHeader className="space-y-2.5 p-6 pb-4 text-left">
              <div className="flex items-center gap-2">
                <span
                  className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.1em] ${riskBadgeClass(scan.risk_level)}`}
                >
                  {scan.risk_level}
                </span>
                <DialogTitle className="tnum font-mono text-base">
                  {scan.final_score} / 100
                </DialogTitle>
              </div>
              <DialogDescription className="break-all font-mono text-xs">
                {scan.url}
              </DialogDescription>
              <p className="text-xs text-muted-foreground">
                Scanned {formatTimestamp(scan.created_at)} · scan #{scan.id}
              </p>
            </DialogHeader>

            <Separator />

            <ScrollArea className="max-h-[55vh]">
              <div className="space-y-5 p-6">
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: "Rule", value: scan.rule_score },
                    { label: "ML", value: scan.ml_score },
                    { label: "Security", value: scan.security_score },
                  ].map((item) => (
                    <div key={item.label} className="rounded-lg border p-3">
                      <span className="text-xs text-muted-foreground">{item.label}</span>
                      <p className="tnum mt-1 font-mono text-lg font-semibold leading-none">
                        {item.value}
                      </p>
                    </div>
                  ))}
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
                    Why this score
                  </h3>
                  <ul className="space-y-1.5">
                    {scan.reasons.map((reason, index) => (
                      <li key={index} className="text-sm leading-relaxed">
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
                    Security findings
                  </h3>
                  <ul className="space-y-2.5">
                    {[...scan.findings]
                      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
                      .map((finding, index) => (
                        <li key={index} className="flex gap-2.5">
                          <span
                            className={`mt-[7px] size-1.5 shrink-0 rounded-full ${severityDotClass(finding.severity)}`}
                          />
                          <div className="min-w-0">
                            <p className="text-sm font-medium">{finding.title}</p>
                            <p className="mt-0.5 break-words font-mono text-xs text-muted-foreground">
                              {finding.detail}
                            </p>
                          </div>
                        </li>
                      ))}
                  </ul>
                </div>
              </div>
            </ScrollArea>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
