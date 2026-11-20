import { finalize } from "./scoring";
import type { Indicator, RuleAnalysis, Severity } from "./types";
import { analyzeUrlIndicators, extractUrls } from "./url";

interface PatternRule {
  code: string;
  label: string;
  detail: string;
  severity: Severity;
  weight: number;
  patterns: RegExp[];
}

export const MESSAGE_RULES: PatternRule[] = [
  {
    code: "msg.otp_request",
    label: "Asks for an OTP, PIN or password",
    detail: "Requests a one-time code, PIN, CVV or password. No genuine bank, app or company will ever ask you to share these.",
    severity: "high",
    weight: 30,
    patterns: [
      /\b(share|send|tell|provide|give|forward|enter)\b[^.\n]{0,40}\b(otp|one[- ]time (password|code)|verification code|pin|cvv|password|upi pin|mpin)\b/i,
      /\b(otp|cvv|upi pin|mpin)\b[^.\n]{0,30}\b(share|send|tell|provide|reply|forward)\b/i,
    ],
  },
  {
    code: "msg.remote_access",
    label: "Asks you to install a screen-sharing app",
    detail: "Mentions remote-access apps like AnyDesk or TeamViewer, which let a scammer control your phone and bank apps.",
    severity: "high",
    weight: 30,
    patterns: [/\b(anydesk|teamviewer|quick ?support|rustdesk|airdroid|screen ?shar(e|ing))\b/i],
  },
  {
    code: "msg.fake_verification",
    label: "Fake verification or account-block threat",
    detail: "Claims your account, KYC, SIM or card needs urgent verification or will be blocked — a very common pretext for stealing details.",
    severity: "high",
    weight: 20,
    patterns: [
      /\b(kyc|e-?kyc)\b[^.\n]{0,40}\b(update|expire|pending|verify|complete|block|suspend)/i,
      /\b(verify|update|re-?activate|confirm)\b[^.\n]{0,25}\b(your )?(account|identity|pan|aadhaar|kyc|details|card|sim)\b/i,
      /\b(account|card|sim|number|wallet)\b[^.\n]{0,30}\b(will be|has been|is) (blocked|suspended|closed|deactivated|disabled|frozen)/i,
    ],
  },
  {
    code: "msg.prize",
    label: "Prize, lottery or reward bait",
    detail: "Promises a prize, lottery win, cashback or reward you didn't enter for. Unexpected winnings are a classic scam hook.",
    severity: "high",
    weight: 20,
    patterns: [
      /\b(you('ve| have)? won|winner|lottery|jackpot|lucky draw|lucky winner|prize money)\b/i,
      /\bclaim (your )?(reward|prize|gift|cashback|bonus|refund)\b/i,
      /\bcongratulations?\b[^.\n]{0,60}\b(selected|won|winner|reward|prize)\b/i,
    ],
  },
  {
    code: "msg.payment_demand",
    label: "Demands a payment or money transfer",
    detail: "Asks you to pay, transfer money, scan a QR code or buy gift cards. Scammers push for payment before you can think.",
    severity: "medium",
    weight: 18,
    patterns: [
      /\b(pay|paying|deposit)\b[^.\n]{0,25}\b(fee|fees|charge|charges|amount|fine|penalty|tax)\b/i,
      /\b(processing|registration|clearance|delivery|customs|release) (fee|charge)s?\b/i,
      /\b(send|transfer)\b[^.\n]{0,20}(money|amount|payment|rs\.?|₹|inr|\$)/i,
      /\bgift ?cards?\b|\b(bitcoin|btc|usdt|crypto ?wallet)\b/i,
      /\bscan (the |this )?qr\b/i,
    ],
  },
  {
    code: "msg.urgency",
    label: "Urgency and pressure tactics",
    detail: "Uses deadlines or threats ('immediately', 'within 24 hours', 'last chance') to rush you into acting without checking.",
    severity: "medium",
    weight: 12,
    patterns: [
      /\b(urgent(ly)?|immediately|right away|act now|asap|last chance|final (notice|warning)|today only|expires? (today|soon|in)|within \d+ ?(hours?|hrs?|minutes?|mins?))\b/i,
      /\b(legal action|arrest|fir|penalty|disconnect(ed|ion)?)\b[^.\n]{0,30}\b(today|tonight|immediately|if you (do not|don't))\b/i,
    ],
  },
  {
    code: "msg.impersonation",
    label: "Impersonates a bank, company or authority",
    detail: "Claims to be from a bank, delivery company, government department, police or customer care. Scammers borrow trusted names.",
    severity: "medium",
    weight: 12,
    patterns: [
      /\b(dear (customer|user|sir\/madam|account ?holder)|customer care|support team|helpdesk)\b/i,
      /\b(rbi|trai|income tax|it department|cyber ?cell|police|customs|electricity (board|bill|department)|courier|fedex|dhl|blue ?dart|india ?post)\b/i,
      /\b(your )(sbi|hdfc|icici|axis|kotak|paytm|phonepe|amazon|flipkart|netflix|bank) (account|card|wallet)\b/i,
    ],
  },
  {
    code: "msg.secrecy",
    label: "Asks you to keep it secret",
    detail: "Tells you not to tell anyone or to keep the conversation confidential — isolation is a manipulation tactic.",
    severity: "low",
    weight: 8,
    patterns: [/\b(don'?t|do not) (tell|inform|share this with) (anyone|anybody|your family|the bank)\b|\bkeep (this|it) (confidential|secret)\b/i],
  },
  {
    code: "msg.callback",
    label: "Pushes you to call an unknown number",
    detail: "Asks you to call or WhatsApp a phone number from the message instead of an official contact.",
    severity: "low",
    weight: 6,
    patterns: [/\b(call|contact|whatsapp|dial)\b[^.\n]{0,25}(\+?\d[\d\s-]{8,}\d)/i],
  },
];

function shoutiness(text: string): boolean {
  const letters = text.replace(/[^a-z]/gi, "");
  if (letters.length < 30) return false;
  const upper = letters.replace(/[^A-Z]/g, "").length;
  return upper / letters.length > 0.6 || (text.match(/!/g) ?? []).length >= 4;
}

export function matchRules(text: string, rules: PatternRule[]): Indicator[] {
  const out: Indicator[] = [];
  for (const rule of rules) {
    const hit = rule.patterns.some((p) => p.test(text));
    if (hit) {
      out.push({
        code: rule.code,
        label: rule.label,
        detail: rule.detail,
        severity: rule.severity,
        weight: rule.weight,
        source: "rules",
      });
    }
  }
  return out;
}

export function linkIndicators(text: string): Indicator[] {
  const urls = extractUrls(text);
  if (urls.length === 0) return [];
  let worst = { url: "", score: 0, labels: [] as string[] };
  for (const u of urls) {
    try {
      const inds = analyzeUrlIndicators(u);
      const score = Math.min(100, inds.reduce((s, i) => s + i.weight, 0));
      if (score > worst.score) worst = { url: u, score, labels: inds.map((i) => i.label.toLowerCase()) };
    } catch {
      /* unparseable link: ignore */
    }
  }
  const out: Indicator[] = [];
  if (worst.score >= 20) {
    out.push({
      code: "msg.link_suspicious",
      label: "Contains a suspicious link",
      detail: `${worst.url} — ${worst.labels.slice(0, 3).join(", ")}.`,
      severity: worst.score >= 40 ? "high" : "medium",
      weight: Math.max(12, Math.round(worst.score * 0.5)),
      source: "rules",
    });
  } else {
    out.push({
      code: "msg.link_present",
      label: "Contains a link",
      detail: `Found ${urls.length} link${urls.length > 1 ? "s" : ""}: ${urls.slice(0, 3).join(", ")}. Treat unexpected links with caution.`,
      severity: "low",
      weight: 4,
      source: "rules",
    });
  }
  return out;
}

export function messageIndicators(text: string): Indicator[] {
  const out = [...matchRules(text, MESSAGE_RULES), ...linkIndicators(text)];
  if (shoutiness(text)) {
    out.push({
      code: "msg.shouting",
      label: "Excessive capitals or exclamation marks",
      detail: "Heavy use of CAPITALS or !!! is common in mass scam messages.",
      severity: "low",
      weight: 5,
      source: "rules",
    });
  }
  const codes = new Set(out.map((i) => i.code));
  if (codes.has("msg.otp_request") && (codes.has("msg.urgency") || codes.has("msg.impersonation") || codes.has("msg.fake_verification"))) {
    out.push({
      code: "msg.takeover_pattern",
      label: "Classic account-takeover pattern",
      detail: "Combines a request for your code or password with urgency or impersonation — the textbook pattern of account-theft scams.",
      severity: "high",
      weight: 15,
      source: "rules",
    });
  }
  return out;
}

export function validateText(text: string, min = 8): string {
  const t = text.trim();
  if (t.length < min) throw new Error("Please paste a bit more text so we can analyse it.");
  if (t.length > 8000) throw new Error("That's too long — please paste up to 8,000 characters.");
  return t;
}

export function analyzeMessage(text: string): RuleAnalysis {
  return finalize("message", messageIndicators(validateText(text)));
}

