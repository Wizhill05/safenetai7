export type RiskStatus = "safe" | "suspicious" | "dangerous";

export const scamKeywords = [
  "urgent",
  "verify",
  "payment",
  "password",
  "bank",
  "reward",
  "free",
  "click",
  "limited",
  "act now",
  "suspended",
  "crypto",
  "lottery",
];

export function extractKeywords(input: string): string[] {
  const lower = input.toLowerCase();
  return scamKeywords.filter((keyword) => lower.includes(keyword));
}

export function mapRiskStatus(score: number): RiskStatus {
  if (score >= 75) return "dangerous";
  if (score >= 45) return "suspicious";
  return "safe";
}

export function mapStatusLabel(status: RiskStatus): string {
  if (status === "dangerous") return "Dangerous";
  if (status === "suspicious") return "Suspicious";
  return "Safe";
}
