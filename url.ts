import { finalize } from "./scoring";
import type { Indicator, RuleAnalysis } from "./types";

/**
 * Structural URL analysis. Works purely on the text of the URL —
 * it NEVER fetches or opens the submitted address.
 */

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
  "shorturl.at", "tiny.cc", "buff.ly", "rebrand.ly", "t.ly", "s.id", "v.gd",
]);

const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
  "work", "support", "rest", "loan", "win", "bid", "icu", "cam", "buzz", "monster",
]);

const SECOND_LEVEL_SUFFIXES = new Set([
  "co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "nic.in", "firm.in",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp",
  "com.br", "com.sg", "com.my", "co.za", "com.mx",
]);

/** brand keyword -> official registrable domains */
const BRANDS: Record<string, string[]> = {
  paypal: ["paypal.com"],
  amazon: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
  google: ["google.com", "google.co.in"],
  microsoft: ["microsoft.com", "live.com", "office.com"],
  apple: ["apple.com", "icloud.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com", "fb.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  sbi: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"],
  hdfc: ["hdfcbank.com", "hdfc.com"],
  icici: ["icicibank.com"],
  paytm: ["paytm.com"],
  phonepe: ["phonepe.com"],
  flipkart: ["flipkart.com"],
  irctc: ["irctc.co.in"],
  linkedin: ["linkedin.com"],
};

const KEYWORDS = [
  "login", "signin", "verify", "verification", "secure", "account", "update", "banking",
  "wallet", "kyc", "otp", "password", "free", "gift", "prize", "reward", "confirm",
  "suspend", "unlock", "refund", "claim", "bonus", "lucky",
];

const RISKY_EXTENSIONS = /\.(exe|apk|scr|bat|msi|cmd|jar|vbs|ps1)(\?|#|$)/i;

export function normalizeUrl(raw: string): URL {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Please enter a URL.");
  if (/\s/.test(trimmed)) throw new Error("A URL can't contain spaces.");
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error("That doesn't look like a valid URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http and https links can be analysed.");
  }
  if (!url.hostname) throw new Error("That doesn't look like a valid URL.");
  return url;
}

export function registrableDomain(hostname: string): string {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (SECOND_LEVEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

function isIp(hostname: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  if (hostname.startsWith("[") || hostname.includes(":")) return true;
  // Decimal / hex encoded IPs such as http://3232235777 or 0xC0A80001
  if (/^(0x[0-9a-f]+|\d{8,10})$/i.test(hostname)) return true;
  return false;
}

export function analyzeUrlIndicators(raw: string): Indicator[] {
  const url = normalizeUrl(raw);
  const full = raw.trim();
  const host = url.hostname.toLowerCase();
  const domain = registrableDomain(host);
  const tld = host.split(".").pop() ?? "";
  const out: Indicator[] = [];
  const add = (i: Omit<Indicator, "source">) => out.push({ ...i, source: "rules" });

  if (url.protocol === "http:") {
    add({
      code: "url.no_https",
      label: "No HTTPS encryption",
      detail: "The link uses plain http://, so anything you type could be intercepted. (HTTPS alone does not mean a site is safe.)",
      severity: "medium",
      weight: 15,
    });
  }

  if (isIp(host)) {
    add({
      code: "url.ip_host",
      label: "IP address instead of a domain",
      detail: `The link points to a raw IP address (${host}). Legitimate services almost always use a named domain.`,
      severity: "high",
      weight: 25,
    });
  }

  if (host.split(".").some((l) => l.startsWith("xn--"))) {
    add({
      code: "url.punycode",
      label: "Punycode / look-alike characters",
      detail: "The domain uses encoded international characters (xn--), a common trick to imitate real brands with look-alike letters.",
      severity: "high",
      weight: 25,
    });
  }

  if (url.username || /^[a-z]+:\/\/[^/]*@/i.test(full)) {
    add({
      code: "url.userinfo",
      label: "Hidden destination using '@'",
      detail: "Everything before an '@' in a link is ignored by the browser. Attackers use this to make a link look like it goes somewhere else.",
      severity: "high",
      weight: 25,
    });
  }

  if (SHORTENERS.has(host) || SHORTENERS.has(domain)) {
    add({
      code: "url.shortener",
      label: "Shortened link hides the destination",
      detail: `${domain} is a link shortener, so you can't see where it really leads.`,
      severity: "medium",
      weight: 12,
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    add({
      code: "url.suspicious_tld",
      label: `Uncommon domain ending (.${tld})`,
      detail: `Domains ending in .${tld} are cheap to register and frequently used in phishing campaigns.`,
      severity: "medium",
      weight: 10,
    });
  }

  const labels = host.split(".");
  const subdomainCount = Math.max(0, labels.length - domain.split(".").length);
  if (!isIp(host) && subdomainCount >= 3) {
    add({
      code: "url.deep_subdomains",
      label: "Unusually deep subdomain structure",
      detail: `The address has ${subdomainCount} subdomain levels before ${domain}, often used to push the real domain out of view.`,
      severity: "medium",
      weight: 12,
    });
  }

  const hyphens = (domain.match(/-/g) ?? []).length;
  if (hyphens >= 2) {
    add({
      code: "url.hyphens",
      label: "Many hyphens in the domain",
      detail: `"${domain}" contains ${hyphens} hyphens — typical of throwaway look-alike domains.`,
      severity: "low",
      weight: 8,
    });
  }

  for (const [brand, official] of Object.entries(BRANDS)) {
    const inHost = host.includes(brand);
    const inPath = url.pathname.toLowerCase().includes(brand);
    if ((inHost || inPath) && !official.includes(domain)) {
      add({
        code: "url.brand_impersonation",
        label: `Mentions "${brand}" but isn't its official site`,
        detail: `The link references ${brand}, but the real domain is ${domain}, not ${official[0]}. This is a common impersonation trick.`,
        severity: "high",
        weight: inHost ? 25 : 15,
      });
      break;
    }
  }

  const haystack = `${host}${url.pathname}${url.search}`.toLowerCase();
  const hits = KEYWORDS.filter((k) => haystack.includes(k));
  if (hits.length > 0) {
    add({
      code: "url.keywords",
      label: "Suspicious keywords in the link",
      detail: `Contains: ${hits.slice(0, 6).join(", ")}. Phishing links often use words that create urgency or imitate login pages.`,
      severity: hits.length >= 3 ? "medium" : "low",
      weight: Math.min(18, hits.length * 6),
    });
  }

  if (full.length > 120) {
    add({
      code: "url.very_long",
      label: "Very long URL",
      detail: `The link is ${full.length} characters long. Overly long links can hide the real destination.`,
      severity: "low",
      weight: 12,
    });
  } else if (full.length > 75) {
    add({
      code: "url.long",
      label: "Long URL",
      detail: `The link is ${full.length} characters long, longer than typical.`,
      severity: "low",
      weight: 6,
    });
  }

  if (url.port && url.port !== "80" && url.port !== "443") {
    add({
      code: "url.port",
      label: `Non-standard port (${url.port})`,
      detail: "Normal websites don't need a custom port number in the address.",
      severity: "medium",
      weight: 10,
    });
  }

  if (/\/\/.*\/\//.test(full.replace(/^[a-z]+:\/\//i, "x://")) || /(redirect|url|next|goto)=https?/i.test(url.search)) {
    add({
      code: "url.redirect",
      label: "Embedded redirect",
      detail: "The link contains another address inside it, which may forward you somewhere else.",
      severity: "medium",
      weight: 10,
    });
  }

  if (RISKY_EXTENSIONS.test(url.pathname)) {
    add({
      code: "url.executable",
      label: "Downloads an app or program file",
      detail: "The link points directly to an installable file (e.g. .apk or .exe). Fake apps are a common way to steal OTPs and banking data.",
      severity: "high",
      weight: 25,
    });
  }

  const encoded = (full.match(/%[0-9a-f]{2}/gi) ?? []).length;
  if (encoded >= 6) {
    add({
      code: "url.obfuscated",
      label: "Heavily encoded characters",
      detail: `${encoded} encoded characters were found, which can be used to disguise the link.`,
      severity: "low",
      weight: 6,
    });
  }

  return out;
}

export function analyzeUrl(raw: string): RuleAnalysis {
  return finalize("url", analyzeUrlIndicators(raw));
}

const URL_IN_TEXT = /(?<![@\w.-])((?:https?:\/\/|www\.)[^\s<>"')]+|(?:[a-z0-9-]+\.)+(?:com|in|net|org|info|xyz|top|ly|co|me|link|click|site|online|shop|live|io|app)(?![a-z0-9-])(?:\/[^\s<>"')]*)?)/gi;

export function extractUrls(text: string): string[] {
  const found = text.match(URL_IN_TEXT) ?? [];
  const cleaned = found.map((u) => u.replace(/[.,;:!?]+$/, ""));
  return Array.from(new Set(cleaned)).slice(0, 10);
}

