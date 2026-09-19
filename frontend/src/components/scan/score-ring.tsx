import { formatScore, riskStroke } from "@/lib/risk";
import type { RiskLevel } from "@/lib/types";

export function ScoreRing({
  score,
  level,
  size = 132,
}: {
  score: number;
  level: RiskLevel;
  size?: number;
}) {
  const stroke = 9;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference - (clamped / 100) * circumference;

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={stroke}
          className="stroke-muted"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          stroke={riskStroke(level)}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 700ms cubic-bezier(0.22, 1, 0.36, 1)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tnum font-mono text-[30px] font-semibold leading-none tracking-tight">
          {formatScore(score)}
        </span>
        <span className="mt-1 font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
          of 100
        </span>
      </div>
    </div>
  );
}
