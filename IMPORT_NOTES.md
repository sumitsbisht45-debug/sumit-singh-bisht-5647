# Import notes — ScamShield AI

This repository pack was assembled from the `SCAMSHIELD_MODEL_CODE.md` file supplied by the project owner.

## What is included

- Project README and architecture/API/ML evaluation documentation
- TypeScript detection types, scoring, URL, message and job rules
- AI review and scan server-function source
- Detection unit tests
- Offline Python ML training scripts, feature extraction, requirements and evaluation JSON reports

## Important: this is not a complete Lovable export

The supplied source file contains these 20 named files only. It does not include the complete Lovable frontend or all dependencies referenced by the included code. In particular, the full app routes/components, package manifest and lockfile, Supabase generated types/auth middleware, database migrations/schema, and environment configuration are not present in the supplied material.

For a runnable copy of the actual Lovable prototype, also export or sync the full project from Lovable to GitHub. Do not replace missing files with guesses.

## Before publishing

- Review the repository for credentials, API keys, private user data and real screenshots.
- Keep secrets in local environment variables or the hosting provider's secret manager.
- Check that any dataset files and model artifacts have appropriate licences before uploading.
- The ML evaluation document explicitly says the offline models are not used by the live app; do not present those metrics as live application accuracy.
