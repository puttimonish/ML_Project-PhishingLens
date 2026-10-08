# src/preprocessing/feature_extractor.py

from pathlib import Path
import pandas as pd

from src.features.url_features import extract_url_features


CHECKPOINT_SIZE = 10000


# ============================================================
# SINGLE URL FEATURE EXTRACTION
# ============================================================

def extract_features(url: str) -> dict:
    """
    Extract all PhishingLens features from a single URL.

    This function is used by the prediction system.
    """

    if not isinstance(url, str):
        url = str(url)

    if not url.strip():
        raise ValueError("URL cannot be empty.")

    return extract_url_features(url)


# ============================================================
# DATASET FEATURE EXTRACTION
# ============================================================

def extract_features_from_dataset(
    input_path: str,
    output_path: str
) -> pd.DataFrame:

    input_file = Path(input_path)
    output_file = Path(output_path)

    print("=" * 70)
    print("PHISHINGLENS FEATURE EXTRACTION")
    print("=" * 70)

    print(f"Loading dataset: {input_file}")

    df = pd.read_csv(input_file)

    print(f"Rows loaded: {len(df):,}")
    print()

    feature_rows = []

    print("Extracting URL features...")
    print("Checkpoint interval:", CHECKPOINT_SIZE)
    print()

    for index, url in enumerate(df["url"]):

        try:
            features = extract_url_features(str(url))

        except Exception as error:
            print()
            print("=" * 70)
            print("FEATURE EXTRACTION ERROR")
            print("=" * 70)
            print("Row:", index)
            print("URL:", url)
            print("Error:", error)
            raise

        feature_rows.append(features)

        current = index + 1

        if current % CHECKPOINT_SIZE == 0:

            percentage = (
                current / len(df)
            ) * 100

            print(
                f"Processed: {current:,} / {len(df):,} "
                f"({percentage:.1f}%)"
            )

    print()
    print("Building feature dataframe...")

    feature_df = pd.DataFrame(feature_rows)

    feature_df.insert(
        0,
        "url",
        df["url"].values
    )

    feature_df.insert(
        1,
        "label",
        df["label"].values
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    feature_df.to_csv(
        output_file,
        index=False
    )

    print()
    print("=" * 70)
    print("FEATURE EXTRACTION COMPLETE")
    print("=" * 70)

    print(f"Rows: {len(feature_df):,}")
    print(f"Columns: {len(feature_df.columns)}")
    print(
        f"Model features: "
        f"{len(feature_df.columns) - 2}"
    )
    print(f"Saved to: {output_file}")

    return feature_df


# ============================================================
# MAIN
# ============================================================

def main():

    input_path = "data/processed/clean_urls.csv"

    output_path = (
        "data/processed/url_features_v2.csv"
    )

    extract_features_from_dataset(
        input_path,
        output_path
    )


if __name__ == "__main__":
    main()