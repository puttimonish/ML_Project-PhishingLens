from pathlib import Path

import pandas as pd


def load_feature_dataset(file_path: str) -> pd.DataFrame:
    """Load the engineered feature dataset."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Feature dataset not found: {path}"
        )

    return pd.read_csv(path)


def analyze_features(df: pd.DataFrame) -> None:
    """Compare numerical features between phishing and legitimate URLs."""

    feature_columns = [
        column
        for column in df.columns
        if column not in {"url", "label"}
    ]

    print("=" * 70)
    print("PHISHLENS FEATURE ANALYSIS")
    print("=" * 70)

    print(f"Total URLs: {len(df):,}")
    print(f"Total features: {len(feature_columns)}")

    print("\nLabel distribution:")
    print(df["label"].value_counts())

    # Mean feature values by class
    class_means = (
        df.groupby("label")[feature_columns]
        .mean()
        .T
    )

    class_means["difference"] = (
        class_means["phishing"]
        - class_means["legitimate"]
    )

    class_means["absolute_difference"] = (
        class_means["difference"].abs()
    )

    class_means = class_means.sort_values(
        "absolute_difference",
        ascending=False,
    )

    print("\n" + "=" * 70)
    print("FEATURE DIFFERENCES")
    print("=" * 70)

    print(
        class_means[
            [
                "phishing",
                "legitimate",
                "difference",
            ]
        ].to_string()
    )

    # Save statistics
    output_dir = Path("data/reports")
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    statistics_path = (
        output_dir /
        "feature_statistics.csv"
    )

    class_means.to_csv(
        statistics_path
    )

    print(
        f"\nFeature statistics saved to: "
        f"{statistics_path}"
    )


def main():

    feature_dataset = (
        "data/processed/"
        "url_features.csv"
    )

    df = load_feature_dataset(
        feature_dataset
    )

    analyze_features(df)


if __name__ == "__main__":
    main()