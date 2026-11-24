import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, classification_report
from xgboost import XGBClassifier
from app.features import extract_url_features

def train_model(csv_path="phishing_site_urls.csv"):
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path).dropna()
    df.columns = [c.strip().lower() for c in df.columns]

    if df["label"].dtype == object:
        df["label"] = df["label"].str.strip().str.lower().map({
            "bad": 1, "phishing": 1, "1": 1,
            "good": 0, "legitimate": 0, "benign": 0, "0": 0
        })
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])

    # Up to 40,000 unique URLs for strong generalization
    if len(df) > 40000:
        df = df.sample(n=40000, random_state=42)

    urls = df["url"].astype(str).tolist()
    y = df["label"].astype(int).values

    print(f"Extracting 27 lexical & structural features for {len(urls)} URLs...")
    X = np.array([extract_url_features(u) for u in urls])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training upgraded XGBoost Classifier...")
    model = XGBClassifier(
        n_estimators=350,
        max_depth=7,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n--- Upgraded Evaluation Metrics ---")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print(f"Precision: {precision_score(y_test, y_pred) * 100:.2f}%")
    print(f"Recall:    {recall_score(y_test, y_pred) * 100:.2f}%")
    print(f"F1-Score:  {f1_score(y_test, y_pred) * 100:.2f}%")
    print("\n" + classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))

    joblib.dump(model, "model/phishing_model.joblib")
    print("SUCCESS: Upgraded 27-feature model saved to model/phishing_model.joblib")

if __name__ == "__main__":
    train_model()