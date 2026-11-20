import type { Indicator, RiskLevel, RuleAnalysis, ScanType } from "./types";

/** Score thresholds: 0–24 Low, 25–49 Medium, 50–74 High, 75–100 Critical. */
export function riskLevelFor(score: number): RiskLevel {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function clampScore(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

export function scoreIndicators(indicators: Indicator[]): number {
  return clampScore(indicators.reduce((sum, i) => sum + Math.max(0, i.weight), 0));
}

const SEVERITY_RANK = { high: 3, medium: 2, low: 1, info: 0 } as const;

export function sortIndicators(indicators: Indicator[]): Indicator[] {
  return [...indicators].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.weight - a.weight,
  );
}

const LOW_SCORE_DISCLAIMER =
  "A low score does not guarantee safety — new scams appear every day and some leave no obvious signs.";

function summaryFor(level: RiskLevel, type: ScanType): string {
  const subject =
    type === "url" ? "This link" : type === "job" ? "This job offer" : type === "screenshot" ? "This screenshot" : "This message";
  switch (level) {
    case "critical":
      return `${subject} shows strong signs of possible fraud.`;
    case "high":
      return `${subject} has multiple significant warning signs.`;
    case "medium":
      return `${subject} has some suspicious characteristics.`;
    default:
      return `${subject} shows few warning signs.`;
  }
}

export function buildExplanation(indicators: Indicator[], level: RiskLevel): string {
  const scored = sortIndicators(indicators.filter((i) => i.weight > 0));
  if (scored.length === 0) {
    return `We did not detect any of the warning signs we check for. ${LOW_SCORE_DISCLAIMER}`;
  }
  const top = scored.slice(0, 3).map((i) => i.label.toLowerCase());
  const list = top.length > 1 ? `${top.slice(0, -1).join(", ")} and ${top[top.length - 1]}` : top[0];
  const count = scored.length;
  const base = `We found ${count} warning sign${count === 1 ? "" : "s"}. The most important: ${list}.`;
  return level === "low" ? `${base} ${LOW_SCORE_DISCLAIMER}` : base;
}

const CODE_ADVICE: Array<[RegExp, string]> = [
  [/^msg\.otp|^job\.sensitive/, "Never share OTPs, PINs, passwords, card details or ID documents — no bank, employer or official will ask for them over chat."],
  [/^msg\.remote_access/, "Do not install screen-sharing apps (AnyDesk, TeamViewer, QuickSupport) at a stranger's request."],
  [/^job\.fee|^msg\.payment/, "Do not pay any fee, deposit or 'processing charge'. Genuine employers and prize schemes never ask you to pay first."],
  [/^msg\.impersonation|^url\.brand/, "Contact the organisation directly using the official website or the number on your card — not the one in the message."],
  [/^job\.free_email|^job\.chat_only/, "Verify the recruiter on the company's official careers page or LinkedIn before replying."],
  [/^url\.|^msg\.link/, "Don't open the link. If you already did, don't enter any details and close the page."],
];

export function buildRecommendations(indicators: Indicator[], level: RiskLevel): string[] {
  const recs: string[] = [];
  const codes = indicators.filter((i) => i.weight > 0).map((i) => i.code);
  for (const [re, advice] of CODE_ADVICE) {
    if (codes.some((c) => re.test(c)) && !recs.includes(advice)) recs.push(advice);
  }
  if (level === "critical" || level === "high") {
    recs.push("Block and report the sender. In India you can report at cybercrime.gov.in or call 1930.");
    recs.push("If you've shared money or details, contact your bank immediately and change affected passwords.");
  } else if (level === "medium") {
    recs.push("Pause before acting. Verify the sender through an independent, official channel.");
  } else {
    recs.push("Stay cautious: verify anything unexpected that asks for money, logins or personal details.");
  }
  return recs.slice(0, 6);
}

export function finalize(scanType: ScanType, indicators: Indicator[]): RuleAnalysis {
  const sorted = sortIndicators(indicators);
  const riskScore = scoreIndicators(sorted);
  const riskLevel = riskLevelFor(riskScore);
  return {
    scanType,
    indicators: sorted,
    riskScore,
    riskLevel,
    summary: summaryFor(riskLevel, scanType),
    explanation: buildExplanation(sorted, riskLevel),
    recommendations: buildRecommendations(sorted, riskLevel),
  };
}

