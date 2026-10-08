import json
import os
import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MODEL_PATH = os.path.join(BASE_DIR, "models", "random_forest.joblib")
DATA_PATH = os.path.join(BASE_DIR, "data", "processed", "url_features.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "reports", "evaluation_report.json")


def main():
    print("=" * 70)
    print("PHISHLENS - MODEL EVALUATION")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load model
    # ---------------------------------------------------------
    print("\nLoading trained model...")
    model_data = joblib.load(MODEL_PATH)

    # The training pipeline may save either the model directly
    # or a dictionary containing the model and feature names.
    if isinstance(model_data, dict):
        model = model_data.get("model")
        feature_names = model_data.get("features")

        if model is None:
            raise ValueError("Could not find 'model' inside saved model file.")
    else:
        model = model_data
        feature_names = None

    # ---------------------------------------------------------
    # Load dataset
    # ---------------------------------------------------------
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    print(f"Dataset shape: {df.shape}")

    # ---------------------------------------------------------
    # Prepare features
    # ---------------------------------------------------------
    target = "label"

    if feature_names is None:
        feature_names = [
            column for column in df.columns
            if column not in ["url", "label"]
        ]

    X = df[feature_names]

    # Match the training label encoding:
    # legitimate = 0
    # phishing = 1
    y = df[target].map({
        "legitimate": 0,
        "phishing": 1
    })

    if y.isna().any():
        raise ValueError("Unknown labels found in dataset.")

    y = y.astype(int)

    # ---------------------------------------------------------
    # Predictions
    # ---------------------------------------------------------
    print("\nGenerating predictions...")

    y_pred = model.predict(X)

    if hasattr(model, "predict_proba"):
        y_probability = model.predict_proba(X)[:, 1]
    else:
        y_probability = None

    # ---------------------------------------------------------
    # Metrics
    # ---------------------------------------------------------
    accuracy = accuracy_score(y, y_pred)
    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)

    if y_probability is not None:
        roc_auc = roc_auc_score(y, y_probability)
    else:
        roc_auc = None

    cm = confusion_matrix(y, y_pred)

    report = classification_report(
        y,
        y_pred,
        target_names=["legitimate", "phishing"],
        zero_division=0,
        output_dict=True
    )

    # ---------------------------------------------------------
    # Display results
    # ---------------------------------------------------------
    print("\n" + "=" * 70)
    print("EVALUATION RESULTS")
    print("=" * 70)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    if roc_auc is not None:
        print(f"ROC-AUC  : {roc_auc:.4f}")

    print("\nConfusion Matrix:")
    print(cm)

    print("\nClassification Report:")
    print(
        classification_report(
            y,
            y_pred,
            target_names=["legitimate", "phishing"],
            zero_division=0
        )
    )

    # ---------------------------------------------------------
    # Save report
    # ---------------------------------------------------------
    evaluation = {
        "dataset": {
            "total_samples": int(len(df)),
            "features": len(feature_names)
        },
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "roc_auc": float(roc_auc) if roc_auc is not None else None
        },
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "feature_names": feature_names
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(evaluation, f, indent=4)

    print(f"\nEvaluation report saved to:")
    print(OUTPUT_PATH)

    print("\n" + "=" * 70)
    print("MODEL EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()