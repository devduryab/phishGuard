"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { CircleAlert, Inbox, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { HistoryTable } from "@/components/history/history-table";
import { ScanDetailDialog } from "@/components/history/scan-detail-dialog";
import { StatCards } from "@/components/history/stat-cards";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchHistory } from "@/lib/api";
import type { ScanRecord } from "@/lib/types";

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [selected, setSelected] = useState<ScanRecord | null>(null);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      setScans(await fetchHistory());
      setError(null);
    } catch (exception) {
      setError(exception instanceof Error ? exception.message : "Could not load history");
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-8 sm:px-6 lg:px-8 lg:py-10">
      <PageHeader
        title="Scan History"
        description="Every analysis is written to a local SQLite database with its scores, reasons and findings, so any result can be traced back to the checks that produced it."
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={refreshing ? "size-4 animate-spin" : "size-4"} />
            Refresh
          </Button>
        }
      />

      <div className="mt-6 space-y-4">
        {error ? (
          <Alert variant="destructive">
            <CircleAlert />
            <AlertTitle>Could not load history</AlertTitle>
            <AlertDescription className="font-mono text-xs">{error}</AlertDescription>
          </Alert>
        ) : null}

        {scans === null && !error ? (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[0, 1, 2, 3].map((index) => (
                <Skeleton key={index} className="h-[104px] rounded-xl" />
              ))}
            </div>
            <Skeleton className="h-72 rounded-xl" />
          </div>
        ) : null}

        {scans && scans.length === 0 ? (
          <Card className="items-center gap-3 border-dashed px-6 py-14 text-center shadow-none">
            <span className="flex size-11 items-center justify-center rounded-full border bg-muted/50">
              <Inbox className="size-5 text-muted-foreground" strokeWidth={1.75} />
            </span>
            <div className="space-y-1">
              <p className="text-sm font-medium">No scans recorded yet</p>
              <p className="mx-auto max-w-sm text-xs leading-relaxed text-muted-foreground">
                Run your first analysis and it will appear here with its full score
                breakdown and security findings.
              </p>
            </div>
            <Button asChild size="sm" className="mt-1">
              <Link href="/">Open scanner</Link>
            </Button>
          </Card>
        ) : null}

        {scans && scans.length > 0 ? (
          <div className="space-y-5">
            <StatCards scans={scans} />
            <HistoryTable scans={scans} onSelect={setSelected} />
          </div>
        ) : null}
      </div>

      <ScanDetailDialog
        scan={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </div>
  );
}
