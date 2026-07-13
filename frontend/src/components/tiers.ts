import type { ConfidenceTier } from "../api/types";

// Color coding for confidence tiers. Recall-biased security context: lower tiers
// still surface prominently rather than being hidden (analysis-modules-rbac.md).
export const TIER_COLORS: Record<ConfidenceTier, string> = {
  CONFIRMED: "#b91c1c", // red — exact CPE
  HIGH_CONFIDENCE: "#c2410c", // orange-red
  POSSIBLE: "#b45309", // amber
  LOW_CONFIDENCE: "#4d7c0f", // olive
};

export const TIER_ORDER: ConfidenceTier[] = [
  "CONFIRMED",
  "HIGH_CONFIDENCE",
  "POSSIBLE",
  "LOW_CONFIDENCE",
];

export function tierColor(tier: string): string {
  return TIER_COLORS[tier as ConfidenceTier] ?? "#475569";
}
