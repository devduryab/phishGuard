"use client";

import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Search } from "lucide-react";

import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { formatRelative, riskBadgeClass } from "@/lib/risk";
import type { RiskLevel, ScanRecord } from "@/lib/types";

type SortKey = "created_at" | "final_score";

export function HistoryTable({
  scans,
  onSelect,
}: {
  scans: ScanRecord[];
  onSelect: (scan: ScanRecord) => void;
}) {
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState<RiskLevel | "ALL">("ALL");
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [descending, setDescending] = useState(true);

  const rows = useMemo(() => {
    const filtered = scans.filter((scan) => {
      const matchesLevel = level === "ALL" || scan.risk_level === level;
      const matchesQuery = scan.url.toLowerCase().includes(query.trim().toLowerCase());
      return matchesLevel && matchesQuery;
    });

    return filtered.sort((a, b) => {
      const direction = descending ? -1 : 1;
      if (sortKey === "final_score") {
        return (a.final_score - b.final_score) * direction;
      }
      return (a.id - b.id) * direction;
    });
  }, [scans, query, level, sortKey, descending]);

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setDescending((value) => !value);
    } else {
      setSortKey(key);
      setDescending(true);
    }
  }

  function SortHeader({ label, sortBy }: { label: string; sortBy: SortKey }) {
    const active = sortKey === sortBy;
    return (
      <button
        type="button"
        onClick={() => toggleSort(sortBy)}
        className={cn(
          "inline-flex items-center gap-1 transition-colors hover:text-foreground",
          active ? "text-foreground" : "text-muted-foreground",
        )}
      >
        {label}
        {active ? (
          descending ? (
            <ArrowDown className="size-3" />
          ) : (
            <ArrowUp className="size-3" />
          )
        ) : null}
      </button>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter by URL"
            className="h-9 pl-9 font-mono text-sm"
          />
        </div>
        <Select value={level} onValueChange={(value) => setLevel(value as RiskLevel | "ALL")}>
          <SelectTrigger className="h-9 sm:w-44">
            <SelectValue placeholder="All risk levels" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All risk levels</SelectItem>
            <SelectItem value="HIGH">High risk</SelectItem>
            <SelectItem value="MEDIUM">Medium risk</SelectItem>
            <SelectItem value="LOW">Low risk</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="overflow-hidden rounded-xl border">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-[42%] text-xs">URL</TableHead>
                <TableHead className="text-xs">Level</TableHead>
                <TableHead className="text-right text-xs">
                  <SortHeader label="Score" sortBy="final_score" />
                </TableHead>
                <TableHead className="hidden text-right text-xs sm:table-cell">Rule</TableHead>
                <TableHead className="hidden text-right text-xs sm:table-cell">ML</TableHead>
                <TableHead className="hidden text-right text-xs sm:table-cell">Sec</TableHead>
                <TableHead className="text-right text-xs">
                  <SortHeader label="When" sortBy="created_at" />
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={7} className="h-28 text-center text-sm text-muted-foreground">
                    No scans match this filter.
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((scan) => (
                  <TableRow
                    key={scan.id}
                    onClick={() => onSelect(scan)}
                    className="cursor-pointer"
                  >
                    <TableCell className="max-w-0">
                      <span className="block truncate font-mono text-xs" title={scan.url}>
                        {scan.url}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.08em] ${riskBadgeClass(scan.risk_level)}`}
                      >
                        {scan.risk_level}
                      </span>
                    </TableCell>
                    <TableCell className="tnum text-right font-mono text-xs font-medium">
                      {scan.final_score}
                    </TableCell>
                    <TableCell className="tnum hidden text-right font-mono text-xs text-muted-foreground sm:table-cell">
                      {scan.rule_score}
                    </TableCell>
                    <TableCell className="tnum hidden text-right font-mono text-xs text-muted-foreground sm:table-cell">
                      {scan.ml_score}
                    </TableCell>
                    <TableCell className="tnum hidden text-right font-mono text-xs text-muted-foreground sm:table-cell">
                      {scan.security_score}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right text-xs text-muted-foreground">
                      {formatRelative(scan.created_at)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        {rows.length} of {scans.length} scans · select a row for full findings
      </p>
    </div>
  );
}
