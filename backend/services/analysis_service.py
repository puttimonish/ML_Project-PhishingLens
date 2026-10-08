from pathlib import Path

from src.prediction.predictor import analyze_url


MODEL_PATH = Path(
    "models/phishinglens_calibrated_v2.joblib"
)


def analyze_url_service(url: str) -> dict:

    url = url.strip()

    if not url:
        raise ValueError(
            "URL cannot be empty."
        )

    return analyze_url(url)


def model_is_loaded() -> bool:

    return MODEL_PATH.exists()