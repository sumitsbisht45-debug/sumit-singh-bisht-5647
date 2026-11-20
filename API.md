# Server API

All endpoints are TanStack server functions in `src/lib/scans.functions.ts`. Each one uses the
`requireSupabaseAuth` middleware, so the caller must be signed in; database access runs as that user under
row-level security. There are no public HTTP endpoints.

Call them from React with `useServerFn(fn)`; errors are thrown as `Error` with a user-friendly message.

| Function | Method | Input | Returns |
| --- | --- | --- | --- |
| `runScan` | POST | `{ type: "url" \| "message" \| "job", content: string (1–8000) }` | `ScanReport` |
| `scanScreenshot` | POST | `{ imageDataUrl: "data:image/(png\|jpeg\|webp);base64,…" (≤4 MB), fileName?: string }` | `ScanReport` |
| `listScans` | GET | `{ type?: ScanType, level?: RiskLevel }` | `ScanSummary[]` (newest first, max 200) |
| `getScan` | GET | `{ id: uuid }` | `ScanReport \| null` |
| `deleteScan` | POST | `{ id: uuid }` | `{ ok: true }` |
| `getDashboard` | GET | — | `DashboardStats` |

## Types

```ts
type ScanType = "url" | "message" | "job" | "screenshot";
type RiskLevel = "low" | "medium" | "high" | "critical";

interface ScanSummary { id; scanType; inputText; riskScore /* 0–100 */; riskLevel; summary; createdAt }
interface ScanReport extends ScanSummary {
  extractedText: string | null;      // screenshot OCR text
  explanation: string;
  recommendations: string[];
  indicators: { code; label; detail; severity: "info"|"low"|"medium"|"high"; weight; source: "rules"|"ai" }[];
  engineMode: "rules" | "rules+ai";  // "rules" = AI review was unavailable
  aiVerdict: "likely_safe" | "suspicious" | "likely_scam" | null;
}
```

## Limits

- 30 scans per user per 10 minutes, of which at most 10 screenshot scans.
- Text input up to 8,000 characters; images up to 4 MB.

