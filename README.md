# ScamShield AI — ML engine (offline research track)

This folder contains **offline** Python training scripts for the classical ML models described in the
project brief (TF‑IDF + Logistic Regression for messages, Random Forest for URLs).

> **Status: trained and evaluated offline, not deployed.** The live app runs an explainable rule engine
> (`src/lib/detection/`) plus an AI second opinion. Results from the latest training run, with caveats, are
> in [`docs/ML_EVALUATION.md`](../docs/ML_EVALUATION.md); raw output is in `reports/`.

## Datasets (download yourself — not redistributed here)

| Model | Dataset | Licence |
| --- | --- | --- |
| Message classifier | [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | CC BY 4.0 |
| URL classifier | [UCI PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | CC BY 4.0 |

Place the files at `ml_engine/data/SMSSpamCollection` and `ml_engine/data/PhiUSIIL_Phishing_URL_Dataset.csv`.

Note: SMS spam ≠ scam. The SMS dataset labels marketing spam too, so treat that model as a baseline only.

## Run

```bash
cd ml_engine
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python train_message_model.py   # prints precision / recall / F1 + confusion matrix
python train_url_model.py
```

Each script writes `models/*.joblib` and `reports/*.json` with the real evaluation results.

## Serving (future work)

To use a trained model in production, host it behind a small HTTP API (e.g. FastAPI on Render) and call it
from the app's server functions. The URL feature extractor in `features.py` mirrors the checks in
`src/lib/detection/url.ts` so both engines stay explainable.

