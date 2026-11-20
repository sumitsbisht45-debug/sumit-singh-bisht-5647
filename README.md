# ScamShield AI

Explainable scam and phishing checks for links, messages, job offers and screenshots. Each scan returns a
0–100 risk score, a risk level, the warning signs found, a plain-language explanation and next steps.

> ScamShield AI gives a risk estimate, not a guarantee. A low score does not mean something is safe.

## Features

- **URL scanner** — structural analysis only (the link is never opened or fetched).
- **Message scanner** — SMS, email and WhatsApp text: urgency, credential requests, payment pressure, impersonation, embedded links.
- **Job offer scanner** — upfront fees, unrealistic pay, off-platform contact, missing company details.
- **Screenshot scanner** — reads the text in an image with AI vision, then runs the message/job rules.
- **AI second opinion** on every scan (bounded ±15 points); falls back to rules only when unavailable, and the report says so.
- **Dashboard** and **scan history** with type/risk filters, report detail and delete.
- Private per-user data (row-level security), rate limits (30 scans / 10 screenshots per 10 minutes).

## Tech stack

| Layer | Choice |
| --- | --- |
| App | TanStack Start v1 (React 19, Vite 7), Tailwind CSS v4, shadcn/ui |
| Server logic | TanStack `createServerFn` (runs on Cloudflare Workers) |
| Auth + database | Lovable Cloud (Postgres + auth: email/password, Google, Lovable) |
| AI | Lovable AI Gateway (`@lovable.dev/ai-gateway`) |
| Offline ML | Python / scikit-learn in `ml_engine/` (not served) |

## Local development

```sh
bun install
cp .env.example .env   # fill in your backend URL and publishable key
bun run dev            # http://localhost:8080
bun run test           # detection rule tests (vitest)
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Server API](docs/API.md)
- [ML evaluation](docs/ML_EVALUATION.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Offline ML engine](ml_engine/README.md)

