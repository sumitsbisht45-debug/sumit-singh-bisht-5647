import { describe, expect, it } from "vitest";
import {
  analyzeJob,
  analyzeMessage,
  analyzeUrl,
  extractUrls,
  riskLevelFor,
} from "@/lib/detection";

const codes = (r: { indicators: { code: string }[] }) => r.indicators.map((i) => i.code);

describe("risk levels", () => {
  it("maps score bands to the four risk levels", () => {
    expect(riskLevelFor(0)).toBe("low");
    expect(riskLevelFor(24)).toBe("low");
    expect(riskLevelFor(25)).toBe("medium");
    expect(riskLevelFor(49)).toBe("medium");
    expect(riskLevelFor(50)).toBe("high");
    expect(riskLevelFor(74)).toBe("high");
    expect(riskLevelFor(75)).toBe("critical");
    expect(riskLevelFor(100)).toBe("critical");
  });

  it("low-risk explanations warn that a low score is not a guarantee", () => {
    const r = analyzeUrl("https://www.wikipedia.org");
    expect(r.riskLevel).toBe("low");
    expect(r.explanation).toMatch(/does not guarantee safety/);
  });
});

describe("URL scanner", () => {
  it("flags IP-based hosts and missing HTTPS", () => {
    const r = analyzeUrl("http://192.168.10.5/login");
    expect(codes(r)).toEqual(expect.arrayContaining(["url.ip_host", "url.no_https"]));
  });

  it("flags punycode domains", () => {
    expect(codes(analyzeUrl("https://xn--pypal-4ve.com"))).toContain("url.punycode");
  });

  it("flags brand impersonation but not the official domain", () => {
    expect(codes(analyzeUrl("https://paypal-secure-login.xyz/verify"))).toContain("url.brand_impersonation");
    expect(codes(analyzeUrl("https://www.paypal.com/signin"))).not.toContain("url.brand_impersonation");
    expect(codes(analyzeUrl("https://www.onlinesbi.sbi"))).not.toContain("url.brand_impersonation");
  });

  it("rates a typical phishing link as high or critical", () => {
    const r = analyzeUrl("http://sbi-kyc-update.verify-account.secure.login.top/update?id=1");
    expect(["high", "critical"]).toContain(r.riskLevel);
  });

  it("rejects non-web schemes", () => {
    expect(() => analyzeUrl("javascript:alert(1)")).toThrow();
  });
});

describe("message scanner", () => {
  it("detects OTP requests combined with urgency as critical", () => {
    const r = analyzeMessage(
      "Dear customer, your SBI account will be blocked today. Share the OTP sent to your mobile immediately to verify your account.",
    );
    expect(codes(r)).toEqual(expect.arrayContaining(["msg.otp_request", "msg.urgency", "msg.takeover_pattern"]));
    expect(r.riskLevel).toBe("critical");
  });

  it("detects prize scams", () => {
    expect(codes(analyzeMessage("Congratulations! You have won Rs 25,00,000 in the lucky draw. Claim your prize now."))).toContain("msg.prize");
  });

  it("keeps an ordinary message low risk", () => {
    const r = analyzeMessage("Hey, are we still meeting for lunch at 1pm tomorrow? Let me know.");
    expect(r.riskLevel).toBe("low");
    expect(r.riskScore).toBe(0);
  });
});

describe("job scanner", () => {
  it("flags registration fees and free-email recruiters", () => {
    const r = analyzeJob(
      "You are selected for Data Entry job without interview. Pay registration fee of Rs 1999 to confirm your seat. Contact hr.jobs2024@gmail.com",
    );
    expect(codes(r)).toEqual(expect.arrayContaining(["job.fee", "job.free_email", "job.suspicious_language"]));
    expect(["high", "critical"]).toContain(r.riskLevel);
  });

  it("does not treat an email address as a link", () => {
    expect(extractUrls("Write to hr@company.com for details")).toEqual([]);
  });
});

