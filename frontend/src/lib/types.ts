export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH";

export interface Finding {
  severity: Severity;
  title: string;
  detail: string;
}

export interface ScanSummary {
  summary: string;
  source: "llm" | "fallback";
  model?: string;
  reason?: string;
}

export interface AiStatus {
  available: boolean;
  model_ready: boolean;
  models: string[];
}

export interface ScanResult {
  id: number;
  url: string;
  level: RiskLevel;
  score: number;
  rule_score: number;
  ml_score: number;
  security_score: number;
  reasons: string[];
  findings: Finding[];
}

export interface ScanRecord {
  id: number;
  url: string;
  risk_level: RiskLevel;
  final_score: number;
  rule_score: number;
  ml_score: number;
  security_score: number;
  reasons: string[];
  findings: Finding[];
  created_at: string;
}

export interface Weights {
  rule: number;
  ml: number;
  security: number;
}

export interface EvalCounts {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface EvalMetrics {
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
}

export interface CategoryResult {
  category: string;
  label: string;
  total: number;
  detected: number;
  missed: number;
  detection_rate: number;
}

export interface WeightOption extends EvalMetrics {
  rule_weight: number;
  ml_weight: number;
  security_weight: number;
  is_current: boolean;
  is_best: boolean;
  counts: EvalCounts;
}

export interface FailureCase {
  url: string;
  score: number;
  rule_score: number;
  ml_score: number;
  category?: string;
  reasons?: string[];
}

export interface SweepPoint {
  threshold: number;
  recall: number;
  precision: number;
  f1: number;
  false_positives: number;
}

export interface AssessmentResult {
  id: number;
  threshold: number;
  counts: EvalCounts;
  metrics: EvalMetrics;
  totals: { phishing: number; legitimate: number; total: number };
  categories: CategoryResult[];
  false_negatives: FailureCase[];
  false_positives: FailureCase[];
  sweep: SweepPoint[];
  weight_analysis: WeightOption[];
  current_weights: Weights;
}

export interface DatasetInfo {
  phishing_available: number;
  phishing_feed_present: boolean;
  phishing_feed_updated: number | null;
  tranco_present: boolean;
  curated_legitimate: number;
}
