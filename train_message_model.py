"""TF-IDF + Logistic Regression baseline on the UCI SMS Spam Collection (CC BY 4.0)."""
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).parent
DATA = ROOT / "data" / "SMSSpamCollection"


def main() -> None:
    if not DATA.exists():
        raise SystemExit(f"Dataset not found at {DATA}. See README for the download link.")
    df = pd.read_csv(DATA, sep="\t", header=None, names=["label", "text"])
    y = (df["label"] == "spam").astype(int)
    X_train, X_test, y_train, y_test = train_test_split(df["text"], y, test_size=0.2, stratify=y, random_state=42)

    model = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
    ])
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    report = classification_report(y_test, pred, target_names=["ham", "spam"], output_dict=True)
    cm = confusion_matrix(y_test, pred).tolist()
    print(classification_report(y_test, pred, target_names=["ham", "spam"]))
    print("Confusion matrix [[TN, FP], [FN, TP]]:", cm)

    (ROOT / "models").mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)
    joblib.dump(model, ROOT / "models" / "message_tfidf_logreg.joblib")
    (ROOT / "reports" / "message_model.json").write_text(json.dumps({"report": report, "confusion_matrix": cm}, indent=2))


if __name__ == "__main__":
    main()

