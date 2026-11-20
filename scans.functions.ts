import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import {
  analyzeJob,
  analyzeMessage,
  analyzeScreenshotText,
  analyzeUrl,
  buildExplanation,
  buildRecommendations,
  clampScore,
  riskLevelFor,
  sortIndicators,
  type Indicator,
  type RiskLevel,
  type RuleAnalysis,
  type ScanType,
} from "@/lib/detection";

export interface ScanSummary {
  id: string;
  scanType: ScanType;
  inputText: string;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  createdAt: string;
}

export interface ScanReport extends ScanSummary {
  extractedText: string | null;
  explanation: string;
  recommendations: string[];
  indicators: Indicator[];
  engineMode: "rules" | "rules+ai";
  aiVerdict: string | null;
}

type Supa = SupabaseClient<Database>;

const RATE_WINDOW_MIN = 10;
const RATE_MAX_SCANS = 30;
const RATE_MAX_SCREENSHOTS = 10;

async function enforceRateLimit(supabase: Supa, userId: string, screenshotsOnly = false) {
  const since = new Date(Date.now() - RATE_WINDOW_MIN * 60_000).toISOString();
  let q = supabase.from("scans").select("id", { count: "exact", head: true }).eq("user_id", userId).gte("created_at", since);
  if (screenshotsOnly) q = q.eq("scan_type", "screenshot");
  const { count, error } = await q;
  if (error) throw new Error("Couldn't check your scan limit. Please try again.");
  const max = screenshotsOnly ? RATE_MAX_SCREENSHOTS : RATE_MAX_SCANS;
  if ((count ?? 0) >= max) {
    throw new Error(`You've reached the limit of ${max} ${screenshotsOnly ? "screenshot " : ""}scans per ${RATE_WINDOW_MIN} minutes. Please wait a few minutes.`);
  }
}

async function combineWithAi(analysis: RuleAnalysis, content: string) {
  const { aiReview } = await import("./ai-review.server");
  const review = await aiReview(analysis.scanType, content, analysis.indicators, analysis.riskScore);
  if (!review) return { ...analysis, engineMode: "rules" as const, aiVerdict: null };

  const aiIndicators: Indicator[] = review.reasons.map((r, idx) => ({
    code: `ai.reason_${idx + 1}`,
    label: r.label.slice(0, 120),
    detail: r.detail.slice(0, 500),
    severity: r.severity,
    weight: 0,
    source: "ai",
  }));
  const riskScore = clampScore(analysis.riskScore + review.adjustment);
  const riskLevel = riskLevelFor(riskScore);
  const indicators = sortIndicators([...analysis.indicators, ...aiIndicators]);
  const adj = review.adjustment === 0 ? "agreed with the rule-based score" : `adjusted the score by ${review.adjustment > 0 ? "+" : ""}${review.adjustment}`;
  const ruleExplanation = buildExplanation(analysis.indicators, riskLevel);
  return {
    ...analysis,
    riskScore,
    riskLevel,
    indicators,
    explanation: `${ruleExplanation} AI review ${adj}: ${review.summary}`,
    recommendations: buildRecommendations(analysis.indicators, riskLevel),
    summary: riskLevel === analysis.riskLevel ? analysis.summary : summaryFromLevel(riskLevel, analysis.scanType),
    engineMode: "rules+ai" as const,
    aiVerdict: review.verdict,
  };
}

function summaryFromLevel(level: RiskLevel, type: ScanType) {
  const subject = type === "url" ? "This link" : type === "job" ? "This job offer" : type === "screenshot" ? "This screenshot" : "This message";
  return {
    critical: `${subject} shows strong signs of possible fraud.`,
    high: `${subject} has multiple significant warning signs.`,
    medium: `${subject} has some suspicious characteristics.`,
    low: `${subject} shows few warning signs.`,
  }[level];
}

async function persist(
  supabase: Supa,
  userId: string,
  result: Awaited<ReturnType<typeof combineWithAi>>,
  inputText: string,
  extractedText: string | null,
): Promise<ScanReport> {
  const { data: scan, error } = await supabase
    .from("scans")
    .insert({
      user_id: userId,
      scan_type: result.scanType,
      input_text: inputText.slice(0, 10000),
      extracted_text: extractedText,
      risk_score: result.riskScore,
      risk_level: result.riskLevel,
      summary: result.summary,
      explanation: result.explanation,
      recommendations: result.recommendations,
      engine_mode: result.engineMode,
      ai_verdict: result.aiVerdict,
    })
    .select("*")
    .single();
  if (error || !scan) {
    console.error(error);
    throw new Error("Analysis finished but we couldn't save it. Please try again.");
  }
  if (result.indicators.length) {
    const { error: indErr } = await supabase.from("scan_indicators").insert(
      result.indicators.map((i) => ({
        scan_id: scan.id,
        user_id: userId,
        code: i.code,
        label: i.label,
        detail: i.detail,
        severity: i.severity,
        weight: i.weight,
        source: i.source,
      })),
    );
    if (indErr) console.error(indErr);
  }
  return {
    id: scan.id,
    scanType: scan.scan_type as ScanType,
    inputText: scan.input_text,
    extractedText: scan.extracted_text,
    riskScore: scan.risk_score,
    riskLevel: scan.risk_level as RiskLevel,
    summary: scan.summary,
    explanation: scan.explanation,
    recommendations: (scan.recommendations as string[]) ?? [],
    indicators: result.indicators,
    engineMode: scan.engine_mode as "rules" | "rules+ai",
    aiVerdict: scan.ai_verdict,
    createdAt: scan.created_at,
  };
}

const textScanInput = z.object({
  type: z.enum(["url", "message", "job"]),
  content: z.string().min(1).max(8000),
});

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => textScanInput.parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    let analysis: RuleAnalysis;
    try {
      analysis = data.type === "url" ? analyzeUrl(data.content) : data.type === "job" ? analyzeJob(data.content) : analyzeMessage(data.content);
    } catch (e) {
      throw new Error(e instanceof Error ? e.message : "Invalid input.");
    }
    await enforceRateLimit(supabase, userId);
    const combined = await combineWithAi(analysis, data.content.trim());
    return persist(supabase, userId, combined, data.content.trim(), null);
  });

const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
const screenshotInput = z.object({
  imageDataUrl: z
    .string()
    .max(Math.ceil((MAX_IMAGE_BYTES * 4) / 3) + 100, "Image is larger than 4 MB.")
    .regex(/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/, "Please upload a PNG, JPG or WEBP image."),
  fileName: z.string().max(200).optional(),
});

export const scanScreenshot = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => screenshotInput.parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await enforceRateLimit(supabase, userId);
    await enforceRateLimit(supabase, userId, true);
    const { extractTextFromImage } = await import("./ai-review.server");
    const text = await extractTextFromImage(data.imageDataUrl);
    const analysis = analyzeScreenshotText(text);
    const combined = await combineWithAi(analysis, text);
    const label = `Screenshot${data.fileName ? `: ${data.fileName.replace(/[^\w .-]/g, "").slice(0, 120)}` : ""}`;
    return persist(supabase, userId, combined, label, text);
  });

type ScanRow = Pick<Database["public"]["Tables"]["scans"]["Row"], "id" | "scan_type" | "input_text" | "risk_score" | "risk_level" | "summary" | "created_at">;

function toSummary(row: ScanRow): ScanSummary {
  return {
    id: row.id,
    scanType: row.scan_type as ScanType,
    inputText: row.input_text,
    riskScore: row.risk_score,
    riskLevel: row.risk_level as RiskLevel,
    summary: row.summary,
    createdAt: row.created_at,
  };
}

const listInput = z.object({
  type: z.enum(["url", "message", "job", "screenshot"]).optional(),
  level: z.enum(["low", "medium", "high", "critical"]).optional(),
});

export const listScans = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => listInput.parse(input ?? {}))
  .handler(async ({ data, context }) => {
    let q = context.supabase
      .from("scans")
      .select("id, scan_type, input_text, risk_score, risk_level, summary, created_at")
      .order("created_at", { ascending: false })
      .limit(200);
    if (data.type) q = q.eq("scan_type", data.type);
    if (data.level) q = q.eq("risk_level", data.level);
    const { data: rows, error } = await q;
    if (error) throw new Error("Couldn't load your scan history.");
    return (rows ?? []).map(toSummary);
  });

export const getScan = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }): Promise<ScanReport | null> => {
    const { data: row, error } = await context.supabase.from("scans").select("*").eq("id", data.id).maybeSingle();
    if (error) throw new Error("Couldn't load this report.");
    if (!row) return null;
    const { data: inds } = await context.supabase
      .from("scan_indicators")
      .select("code, label, detail, severity, weight, source")
      .eq("scan_id", data.id);
    return {
      ...toSummary(row),
      extractedText: row.extracted_text,
      explanation: row.explanation,
      recommendations: (row.recommendations as string[]) ?? [],
      indicators: sortIndicators((inds ?? []) as Indicator[]),
      engineMode: row.engine_mode as "rules" | "rules+ai",
      aiVerdict: row.ai_verdict,
    };
  });

export const deleteScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase.from("scans").delete().eq("id", data.id);
    if (error) throw new Error("Couldn't delete this scan.");
    return { ok: true };
  });

export interface DashboardStats {
  total: number;
  suspicious: number;
  highRisk: number;
  byLevel: Record<RiskLevel, number>;
  byType: Record<ScanType, number>;
  recent: ScanSummary[];
  displayName: string | null;
}

export const getDashboard = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<DashboardStats> => {
    const { supabase, userId } = context;
    const [{ data: rows, error }, { data: profile }] = await Promise.all([
      supabase
        .from("scans")
        .select("id, scan_type, input_text, risk_score, risk_level, summary, created_at")
        .order("created_at", { ascending: false })
        .limit(1000),
      supabase.from("profiles").select("display_name").eq("id", userId).maybeSingle(),
    ]);
    if (error) throw new Error("Couldn't load your dashboard.");
    const all = (rows ?? []).map(toSummary);
    const byLevel: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    const byType: Record<ScanType, number> = { url: 0, message: 0, job: 0, screenshot: 0 };
    for (const s of all) {
      byLevel[s.riskLevel]++;
      byType[s.scanType]++;
    }
    return {
      total: all.length,
      suspicious: byLevel.medium + byLevel.high + byLevel.critical,
      highRisk: byLevel.high + byLevel.critical,
      byLevel,
      byType,
      recent: all.slice(0, 5),
      displayName: profile?.display_name ?? null,
    };
  });

