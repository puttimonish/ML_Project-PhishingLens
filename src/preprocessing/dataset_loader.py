from pathlib import Path
import pandas as pd


def load_dataset(file_path: str) -> pd.DataFrame:
    """Load the raw phishing URL dataset."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    df = pd.read_csv(path)

    print("=" * 60)
    print("DATASET LOADED")
    print("=" * 60)
    print(f"Rows: {len(df):,}")
    print(f"Columns: {list(df.columns)}")

    return df


def validate_dataset(df: pd.DataFrame) -> None:
    """Validate the expected URL dataset structure."""

    required_columns = {"label", "url"}

    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    if df["url"].isna().any():
        raise ValueError("Dataset contains missing URLs.")

    if df["label"].isna().any():
        raise ValueError("Dataset contains missing labels.")

    valid_labels = {"phishing", "legitimate"}

    actual_labels = set(df["label"].unique())

    invalid_labels = actual_labels - valid_labels

    if invalid_labels:
        raise ValueError(
            f"Unexpected labels found: {invalid_labels}"
        )

    print("Dataset validation: PASSED")


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and standardize the raw dataset."""

    df = df[["label", "url"]].copy()

    # Normalize URL strings
    df["url"] = (
        df["url"]
        .astype(str)
        .str.strip()
    )

    # Normalize labels
    df["label"] = (
        df["label"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    # Remove empty URLs
    df = df[df["url"] != ""]

    # Remove duplicate URLs
    before = len(df)

    df = df.drop_duplicates(
        subset="url",
        keep="first"
    )

    duplicates_removed = before - len(df)

    print(f"Duplicate URLs removed: {duplicates_removed:,}")
    print(f"Rows after cleaning: {len(df):,}")

    return df.reset_index(drop=True)


def create_dataset_report(df: pd.DataFrame) -> str:
    """Create a human-readable dataset report."""

    phishing_count = int(
        (df["label"] == "phishing").sum()
    )

    legitimate_count = int(
        (df["label"] == "legitimate").sum()
    )

    total = len(df)

    phishing_percentage = (
        phishing_count / total * 100
        if total else 0
    )

    legitimate_percentage = (
        legitimate_count / total * 100
        if total else 0
    )

    report = f"""
PHISHLENS DATASET REPORT
========================

Total URLs:
{total:,}

Phishing URLs:
{phishing_count:,} ({phishing_percentage:.2f}%)

Legitimate URLs:
{legitimate_count:,} ({legitimate_percentage:.2f}%)

Missing URLs:
{df["url"].isna().sum():,}

Missing labels:
{df["label"].isna().sum():,}

Unique URLs:
{df["url"].nunique():,}

Labels:
{df["label"].unique().tolist()}
"""

    return report


def save_clean_dataset(
    df: pd.DataFrame,
    output_path: str
) -> None:
    """Save the cleaned dataset."""

    output = Path(output_path)

    output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        output,
        index=False
    )

    print(f"Clean dataset saved to: {output}")


def main():
    raw_dataset = (
        "data/external/"
        "URL_Phishing_Detection_Dataset/"
        "balanced_urls.csv"
    )

    clean_dataset_path = (
        "data/processed/"
        "clean_urls.csv"
    )

    report_path = (
        "data/reports/"
        "dataset_report.txt"
    )

    df = load_dataset(raw_dataset)

    validate_dataset(df)

    df = clean_dataset(df)

    report = create_dataset_report(df)

    print(report)

    save_clean_dataset(
        df,
        clean_dataset_path
    )

    report_file = Path(report_path)

    report_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    report_file.write_text(
        report,
        encoding="utf-8"
    )

    print(f"Dataset report saved to: {report_file}")


if __name__ == "__main__":
    main()