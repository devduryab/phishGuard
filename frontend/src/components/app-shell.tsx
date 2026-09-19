"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { BookOpen, History, Menu, ScanLine, ShieldAlert, ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { ThemeToggle } from "@/components/theme-toggle";

const NAV = [
  { href: "/", label: "Scanner", icon: ScanLine },
  { href: "/history", label: "History", icon: History },
  { href: "/assessment", label: "vulnerability Assessment", icon: ShieldAlert },
  { href: "/methodology", label: "Methodology", icon: BookOpen },
];

function Wordmark() {
  return (
    <Link href="/" className="flex items-center gap-2.5">
      <span className="flex size-8 items-center justify-center rounded-[10px] bg-foreground text-background">
        <ShieldCheck className="size-[18px]" strokeWidth={2.25} />
      </span>
      <span className="flex flex-col leading-none">
        <span className="text-sm font-semibold tracking-tight">PhishGuard</span>
        <span className="mt-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          URL Analysis
        </span>
      </span>
    </Link>
  );
}

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();

  return (
    <nav className="flex flex-col gap-0.5">
      {NAV.map(({ href, label, icon: Icon }) => {
        const active = pathname === href;
        return (
          <Link
            key={href}
            href={href}
            onClick={onNavigate}
            className={cn(
              "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
              active
                ? "bg-accent font-medium text-accent-foreground"
                : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
            )}
          >
            <Icon className="size-4" strokeWidth={2} />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}

function SystemStatus() {
  return (
    <div className="rounded-lg border bg-background/60 px-3 py-2.5">
      <div className="flex items-center gap-2">
        <span className="relative flex size-1.5">
          <span className="absolute inline-flex size-full animate-ping rounded-full bg-risk-low opacity-60" />
          <span className="relative inline-flex size-1.5 rounded-full bg-risk-low" />
        </span>
        <span className="text-xs font-medium">Detector online</span>
      </div>
      <p className="mt-1.5 font-mono text-[10px] leading-relaxed text-muted-foreground">
        Rules + RandomForest
        <br />
        Local analysis only
      </p>
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="flex min-h-screen">
      <aside className="fixed inset-y-0 left-0 hidden w-62 flex-col justify-between border-r bg-sidebar px-4 py-5 lg:flex">
        <div className="flex flex-col gap-7">
          <Wordmark />
          <NavLinks />
        </div>
        <div className="flex flex-col gap-3">
          <SystemStatus />
          <div className="flex items-center justify-between px-1">
            <span className="font-mono text-[10px] text-muted-foreground">
              v1.0 · FYP build
            </span>
            <ThemeToggle />
          </div>
        </div>
      </aside>

      <div className="flex w-full flex-col lg:pl-60">
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b bg-background/80 px-4 backdrop-blur lg:hidden">
          <Sheet open={open} onOpenChange={setOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="size-9" aria-label="Open navigation">
                <Menu className="size-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 px-4 py-5">
              <SheetTitle className="sr-only">Navigation</SheetTitle>
              <div className="flex h-full flex-col justify-between">
                <div className="flex flex-col gap-7">
                  <Wordmark />
                  <NavLinks onNavigate={() => setOpen(false)} />
                </div>
                <SystemStatus />
              </div>
            </SheetContent>
          </Sheet>

          <Wordmark />
          <ThemeToggle />
        </header>

        <main className="flex-1">{children}</main>
      </div>
    </div>
  );
}
