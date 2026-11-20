# Architecture

```text
Browser (React, TanStack Router)
   │  server function RPC + bearer token (attachSupabaseAuth)
   ▼
Server functions  src/lib/scans.functions.ts   (requireSupabaseAuth → RLS as the user)
   ├─ rate limit check (scans table, 10-minute window)
   ├─ rule engine      src/lib/detection/*      (pure TypeScript, unit-tested)
   ├─ AI review / OCR  src/lib/ai-review.server.ts  (Lovable AI Gateway)
   └─ persist          scans + scan_indicators tables
   ▼
Lovable Cloud Postgres (row-level security: each user sees only their rows)
```

## Detection pipeline

1. **Validate** input (zod; max 8,000 chars text, 4 MB image, PNG/JPG/WEBP).
2. **Rules** (`analyzeUrl`, `analyzeMessage`, `analyzeJob`, `analyzeScreenshotText`) emit `Indicator`s, each with a
   code, label, detail, severity and weight. The score is the clamped sum of weights (0–100).
3. **AI second opinion** reviews the content plus the rule findings and returns a verdict, an adjustment in
   −15..+15 and up to 4 extra reasons (weight 0, `source: "ai"`). Content is passed as untrusted data.
   If the gateway fails, the scan is saved with `engine_mode = 'rules'`.
4. **Level bands:** 0–24 Low, 25–49 Medium, 50–74 High, 75–100 Critical. Low results always carry a
   "not a guarantee" notice.
5. **Explanation + recommendations** are generated from the indicators and level.

URLs are analysed structurally (IP hosts, punycode, shorteners, risky TLDs, brand look-alikes, `@` tricks,
excessive subdomains, credential keywords, etc.). No request is ever made to the submitted link.

## Data model

| Table | Purpose |
| --- | --- |
| `profiles` | Display name; created by a trigger on signup. |
| `scans` | One row per scan: input, extracted text, score, level, summary, explanation, recommendations, engine mode, AI verdict. |
| `scan_indicators` | Warning signs for a scan (cascade-deleted with the scan). |

All three tables have RLS enabled with select/insert/delete policies scoped to `auth.uid()`.

## Routes

| Path | Access | Purpose |
| --- | --- | --- |
| `/` | public | Landing page |
| `/auth`, `/reset-password` | public | Sign in / sign up / password reset |
| `/privacy` | public | Privacy & safety notice |
| `/dashboard` | signed in | Stats, risk chart, recent activity |
| `/scan`, `/scan/url`, `/scan/message`, `/scan/job`, `/scan/screenshot` | signed in | Scanners |
| `/history`, `/history/$scanId` | signed in | History list and report detail |

