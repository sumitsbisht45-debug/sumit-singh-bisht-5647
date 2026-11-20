# ML evaluation (offline)

These results come from running `ml_engine/train_message_model.py` and `ml_engine/train_url_model.py`
on 17 Nov 2026 (scikit-learn, stratified 80/20 split, `random_state=42`). Raw output is in
`ml_engine/reports/*.json`. **These models are not used by the live app**, which runs the explainable rule
engine plus the AI second opinion.

## Message model — TF-IDF + Logistic Regression

Dataset: UCI SMS Spam Collection (5,574 messages, CC BY 4.0). Test set: 1,115 messages (149 spam).

| Metric (spam class) | Value |
| --- | --- |
| Precision | 0.965 |
| Recall | 0.926 |
| F1 | 0.945 |
| Accuracy (all) | 0.986 |

Confusion matrix `[[TN, FP], [FN, TP]]`: `[[961, 5], [11, 138]]`

Caveats: the dataset labels marketing **spam**, not specifically **scams**, it is from 2011–2012 and
UK/Singapore-centric. Expect much lower performance on modern scam texts (delivery, UPI/KYC, job scams).

## URL model — Random Forest on structural features

Dataset: UCI PhiUSIIL Phishing URL Dataset (235,795 URLs, CC BY 4.0). Test set: 47,159 URLs (20,189 phishing).
Features: the 15 structural checks in `ml_engine/features.py` (mirrors `src/lib/detection/url.ts`).

| Metric (phishing class) | Value |
| --- | --- |
| Precision | 0.975 |
| Recall | 0.936 |
| F1 | 0.955 |
| Accuracy (all) | 0.962 |

Confusion matrix `[[TN, FP], [FN, TP]]`: `[[26483, 487], [1292, 18897]]`

Top feature importances: `is_https` 0.43, `length` 0.25, `n_digits` 0.14, `n_hyphens` 0.05.

Caveats: the model leans heavily on `is_https` and URL length, which reflects how this dataset was
collected (legitimate URLs are mostly short `https://` home pages). Modern phishing sites routinely use
HTTPS, so real-world accuracy will be lower than the table suggests. Treat these numbers as a baseline,
not a production claim.

## Reproduce

```bash
cd ml_engine
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# download the two datasets into ml_engine/data/ (see ml_engine/README.md)
python train_message_model.py
python train_url_model.py
```

