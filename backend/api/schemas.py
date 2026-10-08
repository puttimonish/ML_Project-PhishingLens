
from typing import Any, Dict, List

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="URL to analyze",
    )


class AnalyzeResponse(BaseModel):
    url: str

    # Final prediction after contextual rules
    prediction: str

    # Original machine-learning prediction and decision reason
    model_prediction: str
    decision_reason: str

    # Machine-learning probabilities
    phishing_probability: float
    legitimate_probability: float

    # Contextual risk score
    risk_score: int
    risk_level: str
    ml_score: float
    positive_adjustment: int
    negative_adjustment: int

    # Contextual assessment
    assessment: str
    assessment_reason: str
    recommended_action: str

    # Explanations and extracted features
    explanations: List[str]
    features: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    service: str
    model_loaded: bool