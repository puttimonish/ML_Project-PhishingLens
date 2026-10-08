from fastapi import APIRouter, HTTPException

from backend.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse
)

from backend.services.analysis_service import (
    analyze_url_service,
    model_is_loaded
)


router = APIRouter(
    prefix="/api/v1",
    tags=["PhishingLens API"]
)


@router.get(
    "/health",
    response_model=HealthResponse
)
def health_check():

    return {
        "status": "healthy",
        "service": "PhishingLens API",
        "model_loaded": model_is_loaded()
    }


@router.post(
    "/analyze",
    response_model=AnalyzeResponse
)
def analyze_url_endpoint(
    request: AnalyzeRequest
):

    try:

        result = analyze_url_service(
            request.url
        )

        return result

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {error}"
        )