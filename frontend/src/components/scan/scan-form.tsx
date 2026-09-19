"use client";

import { Loader2, Search } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const EXAMPLES = [
  "https://example.com",
  "http://192.0.2.10/login-verify-account",
  "http://free-bonus-gift-signin-now.test",
];

export function ScanForm({
  onScan,
  pending,
}: {
  onScan: (url: string) => void;
  pending: boolean;
}) {
  const [value, setValue] = useState("");

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = value.trim();
    if (trimmed && !pending) onScan(trimmed);
  }

  return (
    <Card className="p-5">
      <form onSubmit={submit} className="space-y-3">
        <Label htmlFor="url" className="text-sm font-medium">
          Website URL
        </Label>

        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="url"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder="example.com or https://example.com/login"
              autoComplete="off"
              spellCheck={false}
              disabled={pending}
              className="h-10 pl-9 font-mono text-sm"
            />
          </div>
          <Button type="submit" disabled={pending || !value.trim()} className="h-10 sm:w-32">
            {pending ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Analysing
              </>
            ) : (
              "Analyse"
            )}
          </Button>
        </div>

        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 pt-0.5">
          <span className="text-xs text-muted-foreground">Try:</span>
          {EXAMPLES.map((example) => (
            <button
              key={example}
              type="button"
              disabled={pending}
              onClick={() => setValue(example)}
              className="rounded border bg-muted/40 px-2 py-0.5 font-mono text-[11px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:opacity-50"
            >
              {example}
            </button>
          ))}
        </div>

        <p className="border-t pt-3 text-xs leading-relaxed text-muted-foreground">
          Only analyse websites you own or are authorised to test. The scanner performs
          passive checks only — it never attempts to exploit or log in to a target.
        </p>
      </form>
    </Card>
  );
}
