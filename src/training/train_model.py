# src/training/train_model.py

from pathlib import Path
import json
import time

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


DATA_PATH = "data/processed/url_features_v2.csv"
MODEL_DIR = Path("models")
REPORT_DIR = Path("data/reports")

# These features are retained by the feature extractor for
# explanation/frontend purposes, but are excluded from ML training
# because the dataset contains a strong HTTP/HTTPS class bias.
EXCLUDED_FEATURES = [
    "has_http",
    "has_https",
]


def load_dataset():
    print("=" * 70)
    print("PHISHINGLENS MODEL TRAINING - DEBIASED")
    print("=" * 70)

    print(f"Loading: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)

    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    return df


def prepare_data(df):

    # Remove URL and label from model inputs.
    X = df.drop(columns=["url", "label"])

    # ---------------------------------------------------------
    # REMOVE DATASET-BIASED PROTOCOL FEATURES
    # ---------------------------------------------------------

    print()
    print("=" * 70)
    print("FEATURE DEBIASING")
    print("=" * 70)

    print("Excluded from ML training:")

    for feature in EXCLUDED_FEATURES:
        print(f"  - {feature}")

    X = X.drop(
        columns=EXCLUDED_FEATURES,
        errors="ignore"
    )

    # Phishing = 1
    # Legitimate = 0
    y = df["label"].map({
        "legitimate": 0,
        "phishing": 1
    })

    return X, y


def evaluate_model(name, model, X_test, y_test):

    start = time.time()

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    elapsed = time.time() - start

    metrics = {
        "model": name,
        "accuracy": accuracy_score(
            y_test,
            predictions
        ),
        "precision": precision_score(
            y_test,
            predictions
        ),
        "recall": recall_score(
            y_test,
            predictions
        ),
        "f1": f1_score(
            y_test,
            predictions
        ),
        "roc_auc": roc_auc_score(
            y_test,
            probabilities
        ),
        "pr_auc": average_precision_score(
            y_test,
            probabilities
        ),
        "prediction_time_seconds": elapsed,
    }

    print()
    print("=" * 70)
    print(name)
    print("=" * 70)

    print(
        f"Accuracy : {metrics['accuracy']:.4f}"
    )
    print(
        f"Precision: {metrics['precision']:.4f}"
    )
    print(
        f"Recall   : {metrics['recall']:.4f}"
    )
    print(
        f"F1 Score : {metrics['f1']:.4f}"
    )
    print(
        f"ROC-AUC  : {metrics['roc_auc']:.4f}"
    )
    print(
        f"PR-AUC   : {metrics['pr_auc']:.4f}"
    )

    print()
    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    print()
    print("Classification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Legitimate",
                "Phishing"
            ]
        )
    )

    return metrics


def main():

    df = load_dataset()

    X, y = prepare_data(df)

    print()
    print("Feature matrix:", X.shape)
    print("Target:", y.shape)

    # ---------------------------------------------------------
    # TRAIN / VALIDATION / TEST SPLIT
    # ---------------------------------------------------------

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y
    )

    X_val, X_test, y_val, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=0.50,
        random_state=42,
        stratify=y_temp
    )

    print()
    print("=" * 70)
    print("DATA SPLIT")
    print("=" * 70)

    print(f"Training   : {len(X_train):,}")
    print(f"Validation : {len(X_val):,}")
    print(f"Test       : {len(X_test):,}")

    # ---------------------------------------------------------
    # MODELS
    # ---------------------------------------------------------

    models = {

        "Logistic Regression": Pipeline([
            (
                "scaler",
                StandardScaler()
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    random_state=42
                )
            )
        ]),

        "Random Forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            max_features="sqrt",
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        ),
    }

    results = []

    trained_models = {}

    # ---------------------------------------------------------
    # TRAIN
    # ---------------------------------------------------------

    for name, model in models.items():

        print()
        print("=" * 70)
        print(f"TRAINING: {name}")
        print("=" * 70)

        start = time.time()

        model.fit(
            X_train,
            y_train
        )

        training_time = time.time() - start

        print(
            f"Training completed in "
            f"{training_time:.2f} seconds"
        )

        # Evaluate on validation set
        validation_metrics = evaluate_model(
            f"{name} - Validation",
            model,
            X_val,
            y_val
        )

        validation_metrics[
            "training_time_seconds"
        ] = training_time

        results.append(
            validation_metrics
        )

        trained_models[name] = model

    # ---------------------------------------------------------
    # SELECT BEST MODEL USING VALIDATION F1
    # ---------------------------------------------------------

    results_df = pd.DataFrame(results)

    best_index = results_df["f1"].idxmax()

    best_model_name = results_df.loc[
        best_index,
        "model"
    ].replace(" - Validation", "")

    best_model = trained_models[
        best_model_name
    ]

    print()
    print("=" * 70)
    print("BEST MODEL")
    print("=" * 70)

    print(best_model_name)

    # ---------------------------------------------------------
    # FINAL TEST EVALUATION
    # ---------------------------------------------------------

    test_metrics = evaluate_model(
        f"{best_model_name} - FINAL TEST",
        best_model,
        X_test,
        y_test
    )

    # ---------------------------------------------------------
    # RANDOM FOREST FEATURE IMPORTANCE
    # ---------------------------------------------------------

    feature_importance = None

    if best_model_name == "Random Forest":

        importance = best_model.feature_importances_

        feature_importance = pd.DataFrame({
            "feature": X.columns,
            "importance": importance
        }).sort_values(
            "importance",
            ascending=False
        )

        print()
        print("=" * 70)
        print("TOP 20 FEATURES")
        print("=" * 70)

        print(
            feature_importance.head(20).to_string(
                index=False
            )
        )

        feature_importance.to_csv(
            REPORT_DIR / "feature_importance_debiased_v2.csv",
            index=False
        )

    # ---------------------------------------------------------
    # SAVE MODEL
    # ---------------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    model_path = MODEL_DIR / "phishinglens_model_debiased_v2.joblib"

    joblib.dump(
        best_model,
        model_path
    )

    # ---------------------------------------------------------
    # SAVE METRICS
    # ---------------------------------------------------------

    report = {
        "dataset_rows": len(df),
        "original_feature_count": len(df.columns) - 2,
        "excluded_features": EXCLUDED_FEATURES,
        "feature_count": X.shape[1],
        "training_rows": len(X_train),
        "validation_rows": len(X_val),
        "test_rows": len(X_test),
        "best_model": best_model_name,
        "validation_results": results,
        "final_test_results": test_metrics,
    }

    metrics_path = (
        REPORT_DIR /
        "model_metrics_debiased_v2.json"
    )

    with open(
        metrics_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print()
    print("=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

    print(f"Best model : {best_model_name}")
    print(f"Model saved: {model_path}")
    print(f"Metrics    : {metrics_path}")


if __name__ == "__main__":
    main()