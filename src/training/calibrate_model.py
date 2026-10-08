
# src/training/calibrate_model.py

from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
    log_loss,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split


DATA_PATH = Path("data/processed/url_features_v2.csv")

BASE_MODEL_PATH = Path(
    "models/phishinglens_model_debiased_v2.joblib"
)

MODEL_DIR = Path("models")
REPORT_DIR = Path("data/reports")

# Must match src/training/train_model.py
EXCLUDED_FEATURES = [
    "has_http",
    "has_https",
]

# Save separately to protect the current deployed model.
OUTPUT_MODEL_PATH = (
    MODEL_DIR / "phishinglens_calibrated_debiased_v3.joblib"
)

REPORT_PATH = (
    REPORT_DIR / "calibration_report_debiased_v3.json"
)


def main():
    started = time.time()

    print("=" * 70)
    print("PHISHINGLENS DEBIASED MODEL CALIBRATION")
    print("=" * 70)

    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Feature dataset not found: {DATA_PATH}"
        )

    if not BASE_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Debiased base model not found: {BASE_MODEL_PATH}. "
            "Run the debiased training script first."
        )

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # LOAD DATA
    # ---------------------------------------------------------

    print("\nLoading feature dataset...")

    df = pd.read_csv(DATA_PATH)

    required_columns = {"url", "label"}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Dataset is missing required columns: "
            f"{sorted(missing_columns)}"
        )

    X = df.drop(columns=["url", "label"])

    X = X.drop(
        columns=EXCLUDED_FEATURES,
        errors="ignore",
    )

    y = (
        df["label"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map({
            "legitimate": 0,
            "phishing": 1,
        })
    )

    if y.isna().any():
        raise ValueError(
            "Unknown or missing labels found in the dataset. "
            "Check the label column before calibration."
        )

    if X.isna().any().any():
        raise ValueError(
            "Missing feature values detected. "
            "Apply the same preprocessing used during training."
        )

    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError(
            "Non-finite feature values detected."
        )

    print(f"Dataset rows: {len(df):,}")
    print(f"Debiased features: {X.shape[1]}")
    print(f"Excluded features: {EXCLUDED_FEATURES}")

    # ---------------------------------------------------------
    # RECREATE THE ORIGINAL TRAIN / VALIDATION / TEST SPLIT
    # ---------------------------------------------------------

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )

    X_calibration, X_test, y_calibration, y_test = (
        train_test_split(
            X_temp,
            y_temp,
            test_size=0.50,
            random_state=42,
            stratify=y_temp,
        )
    )

    print("\nData split:")
    print(f"Training:   {len(X_train):,}")
    print(f"Calibration: {len(X_calibration):,}")
    print(f"Final test:  {len(X_test):,}")

    # ---------------------------------------------------------
    # LOAD THE ALREADY-TRAINED DEBIASED MODEL
    # ---------------------------------------------------------

    print("\nLoading existing debiased model...")

    base_model = joblib.load(BASE_MODEL_PATH)

    expected_features = getattr(
        base_model,
        "feature_names_in_",
        None,
    )

    if expected_features is not None:
        expected_features = list(expected_features)

        missing = sorted(
            set(expected_features) - set(X.columns)
        )

        extra = sorted(
            set(X.columns) - set(expected_features)
        )

        if missing or extra:
            raise ValueError(
                "Training/calibration feature mismatch. "
                f"Missing: {missing}; extra: {extra}"
            )

        # Preserve the exact column order used during training.
        X = X.reindex(columns=expected_features)

        # Recreate the split after enforcing feature order.
        X_train, X_temp, y_train, y_temp = train_test_split(
            X,
            y,
            test_size=0.30,
            random_state=42,
            stratify=y,
        )

        X_calibration, X_test, y_calibration, y_test = (
            train_test_split(
                X_temp,
                y_temp,
                test_size=0.50,
                random_state=42,
                stratify=y_temp,
            )
        )

    print("Base model:", type(base_model).__name__)
    print("Base model loaded successfully.")

    # ---------------------------------------------------------
    # CALIBRATE THE FROZEN MODEL
    # ---------------------------------------------------------

    print("\nCalibrating probabilities using sigmoid scaling...")
    print("The fitted base model will not be retrained.")

    calibrated_model = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model),
        method="sigmoid",
    )

    calibrated_model.fit(
        X_calibration,
        y_calibration,
    )

    # ---------------------------------------------------------
    # EVALUATE ON THE UNTOUCHED TEST SET
    # ---------------------------------------------------------

    print("\nEvaluating on the held-out test set...")

    probabilities = calibrated_model.predict_proba(X_test)

    classes = list(calibrated_model.classes_)

    legitimate_index = classes.index(0)
    phishing_index = classes.index(1)

    legitimate_probability = probabilities[:, legitimate_index]
    phishing_probability = probabilities[:, phishing_index]

    predictions = (phishing_probability >= 0.5).astype(int)

    metrics = {
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "precision": float(
            precision_score(
                y_test, predictions, zero_division=0
            )
        ),
        "recall": float(
            recall_score(
                y_test, predictions, zero_division=0
            )
        ),
        "f1": float(
            f1_score(
                y_test, predictions, zero_division=0
            )
        ),
        "roc_auc": float(
            roc_auc_score(y_test, phishing_probability)
        ),
        "average_precision": float(
            average_precision_score(
                y_test, phishing_probability
            )
        ),
        "brier_score": float(
            brier_score_loss(y_test, phishing_probability)
        ),
        "log_loss": float(
            log_loss(
                y_test,
                probabilities,
                labels=classes,
            )
        ),
        "confusion_matrix": confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1],
        ).tolist(),
    }

    print("\n" + "=" * 70)
    print("HELD-OUT TEST RESULTS")
    print("=" * 70)

    for name, value in metrics.items():
        if isinstance(value, float):
            print(f"{name}: {value:.4f}")
        else:
            print(f"{name}: {value}")

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Legitimate", "Phishing"],
            zero_division=0,
        )
    )

    print(
        "\nAverage phishing probability:",
        f"{np.mean(phishing_probability):.4f}",
    )

    print(
        "Average legitimate probability:",
        f"{np.mean(legitimate_probability):.4f}",
    )

    # ---------------------------------------------------------
    # SAVE TO A NEW FILE
    # ---------------------------------------------------------

    print("\nSaving calibrated model...")

    joblib.dump(
        calibrated_model,
        OUTPUT_MODEL_PATH,
    )

    report = {
        "method": "sigmoid",
        "calibration_strategy": "FrozenEstimator",
        "base_model": str(BASE_MODEL_PATH),
        "output_model": str(OUTPUT_MODEL_PATH),
        "excluded_features": EXCLUDED_FEATURES,
        "dataset_rows": int(len(df)),
        "feature_count": int(X.shape[1]),
        "training_rows": int(len(X_train)),
        "calibration_rows": int(len(X_calibration)),
        "test_rows": int(len(X_test)),
        "metrics": metrics,
        "average_phishing_probability": float(
            np.mean(phishing_probability)
        ),
        "average_legitimate_probability": float(
            np.mean(legitimate_probability)
        ),
        "elapsed_seconds": round(time.time() - started, 2),
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n" + "=" * 70)
    print("CALIBRATION COMPLETE")
    print("=" * 70)
    print(f"Model saved: {OUTPUT_MODEL_PATH}")
    print(f"Report saved: {REPORT_PATH}")
    print("Original model preserved.")
    print(f"Elapsed time: {time.time() - started:.2f} seconds")


if __name__ == "__main__":
    main()
