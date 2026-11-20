import { finalize } from "./scoring";
import type { Indicator, RuleAnalysis } from "./types";
import { MESSAGE_RULES, linkIndicators, matchRules, messageIndicators, validateText } from "./message";

const FREE_EMAIL = /\b[\w.+-]+@(gmail|yahoo|ymail|outlook|hotmail|rediffmail|proton(mail)?|aol|zoho|mail|yandex|gmx)\.(com|in|co\.in|me|ru|net)\b/i;

const JOB_RULES = [
  {
    code: "job.fee",
    label: "Asks for a registration fee or deposit",
    detail: "Mentions a registration fee, security deposit, training or kit charge. Real employers never charge you to get a job.",
    severity: "high" as const,
    weight: 35,
    patterns: [
      /\b(registration|security|joining|training|onboarding|interview|verification|processing|document(ation)?|kit|uniform|laptop) (fee|fees|charge|charges|deposit|amount)\b/i,
      /\b(refundable|one[- ]time) (deposit|fee|payment|amount)\b/i,
      /\bpay\b[^.\n]{0,30}\b(to (confirm|book|secure|get) (your )?(seat|slot|job|offer|joining))\b/i,
    ],
  },
  {
    code: "job.task_scam",
    label: "Task-based 'like and earn' scheme",
    detail: "Offers money for liking videos, rating hotels/products or completing 'prepaid tasks' — a widespread scam that ends with you paying in.",
    severity: "high" as const,
    weight: 30,
    patterns: [
      /\b(like|subscribe to)\b[^.\n]{0,25}\b(youtube )?(videos?|channels?|posts?)\b[^.\n]{0,40}\b(earn|paid|pay|₹|rs)/i,
      /\b(rate|review)\b[^.\n]{0,20}\b(hotels?|products?|restaurants?|movies?)\b[^.\n]{0,40}\b(earn|paid|commission)/i,
      /\b(prepaid|merchant|daily) tasks?\b|\btask[s]? (and|&) earn\b/i,
    ],
  },
  {
    code: "job.sensitive_info",
    label: "Requests sensitive personal documents",
    detail: "Asks for Aadhaar, PAN, bank details, passport or card information before any verified interview — these can be misused for fraud.",
    severity: "high" as const,
    weight: 22,
    patterns: [
      /\b(aadhaa?r|pan card|pan number|bank (account )?details|account number|ifsc|passport|atm card|debit card|credit card|selfie with)\b/i,
    ],
  },
  {
    code: "job.unrealistic_pay",
    label: "Unrealistic salary or easy-money promise",
    detail: "Promises high pay for little work, daily payouts or guaranteed income without experience — too good to be true.",
    severity: "medium" as const,
    weight: 18,
    patterns: [
      /\bearn\b[^.\n]{0,30}(₹|rs\.?|inr|\$)\s?\d[\d,]{2,}[^.\n]{0,25}\b(per|a|\/|daily|every) ?(day|hour|hr|week)\b/i,
      /(₹|rs\.?|inr|\$)\s?\d[\d,]{3,}\s*(\/|per|a)\s*(day|hour|hr)\b/i,
      /\b(guaranteed|assured|fixed) (income|salary|earning|returns?|job|placement)\b/i,
      /\b(no experience|no qualification|no skills?)( (is|are))? (required|needed)\b[^.\n]{0,60}(₹|rs|earn|salary|income)/i,
      /\bearn (up to )?(₹|rs\.?|inr|\$)?\s?\d[\d,]*\s?(k|lakh|lakhs)?\b[^.\n]{0,20}\b(from home|daily|part[- ]time)\b/i,
    ],
  },
  {
    code: "job.suspicious_language",
    label: "Suspicious recruitment language",
    detail: "Claims you're selected without an interview, offers 'direct joining' or 'limited seats' — genuine hiring involves real evaluation.",
    severity: "medium" as const,
    weight: 14,
    patterns: [
      /\b(selected|shortlisted|hired)\b[^.\n]{0,30}\b(without|no) (an )?interview\b/i,
      /\b(direct|immediate|instant) (joining|selection|hiring|offer)\b/i,
      /\b(limited (seats|slots|vacancies)|hurry|only (a )?few (seats|slots) left)\b/i,
      /\b(work from home|part[- ]time)\b[^.\n]{0,40}\b(housewives|students|anyone)\b/i,
    ],
  },
  {
    code: "job.chat_only",
    label: "Recruitment only via WhatsApp or Telegram",
    detail: "The 'HR' asks to continue only on WhatsApp or Telegram instead of official email or company portals.",
    severity: "low" as const,
    weight: 8,
    patterns: [/\b(whatsapp|telegram|t\.me|wa\.me)\b/i],
  },
];

export function jobIndicators(text: string): Indicator[] {
  const out: Indicator[] = [...matchRules(text, JOB_RULES)];
  const email = text.match(FREE_EMAIL);
  if (email) {
    out.push({
      code: "job.free_email",
      label: "Recruiter uses a free email address",
      detail: `${email[0]} is a free webmail address. Established companies recruit from their own domain.`,
      severity: "medium",
      weight: 15,
      source: "rules",
    });
  }
  // Reuse general scam signals that also apply to job scams.
  const shared = matchRules(
    text,
    MESSAGE_RULES.filter((r) => ["msg.otp_request", "msg.urgency", "msg.payment_demand", "msg.remote_access"].includes(r.code)),
  );
  const codes = new Set(out.map((i) => i.code));
  for (const s of shared) {
    // Fee rule already covers most payment language — avoid double counting.
    if (s.code === "msg.payment_demand" && codes.has("job.fee")) continue;
    out.push(s);
  }
  out.push(...linkIndicators(text));
  return out;
}

export function analyzeJob(text: string): RuleAnalysis {
  return finalize("job", jobIndicators(validateText(text, 15)));
}

const JOB_CONTEXT = /\b(job|internship|intern|hiring|recruit(er|ment)?|vacancy|salary|stipend|offer letter|hr team|work from home|part[- ]time)\b/i;

/** Screenshot text: general message rules, plus job rules when the text looks job-related. */
export function screenshotIndicators(text: string): Indicator[] {
  const base = messageIndicators(text);
  if (!JOB_CONTEXT.test(text)) return base;
  const seen = new Set(base.map((i) => i.code));
  const extra = jobIndicators(text).filter((i) => !seen.has(i.code) && i.code.startsWith("job."));
  return [...base, ...extra];
}

export function analyzeScreenshotText(text: string): RuleAnalysis {
  return finalize("screenshot", screenshotIndicators(validateText(text, 4)));
}

