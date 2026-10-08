def calculate_risk(prediction, confidence, features):
    """
    Calculate a human-readable risk assessment
    using the model prediction and URL characteristics.
    """

    prediction = prediction.upper()

    risk_score = 0
    indicators = []

    # ---------------------------------------------------------
    # Model prediction
    # ---------------------------------------------------------

    if prediction == "PHISHING":
        risk_score += 60
        indicators.append("Machine-learning model classified the URL as phishing.")

        if confidence >= 0.90:
            risk_score += 20
        elif confidence >= 0.70:
            risk_score += 10

    else:
        risk_score += 5

    # ---------------------------------------------------------
    # Suspicious URL characteristics
    # ---------------------------------------------------------

    if features.get("has_ip", 0):
        risk_score += 10
        indicators.append("URL uses an IP address instead of a conventional domain.")

    if features.get("has_suspicious_keyword", 0):
        risk_score += 10
        indicators.append("URL contains suspicious security-related keywords.")

    if features.get("suspicious_keyword_count", 0) >= 2:
        risk_score += 5
        indicators.append("Multiple suspicious keywords were detected.")

    if features.get("has_port", 0):
        risk_score += 5
        indicators.append("Non-standard port detected.")

    if features.get("at_count", 0) > 0:
        risk_score += 5
        indicators.append("URL contains '@', which can obscure the actual destination.")

    if features.get("percent_encoding_count", 0) >= 2:
        risk_score += 5
        indicators.append("Multiple percent-encoded characters detected.")

    if features.get("subdomain_count", 0) >= 3:
        risk_score += 5
        indicators.append("URL contains multiple subdomain levels.")

    if features.get("consecutive_digit_count", 0) >= 2:
        risk_score += 5
        indicators.append("Unusually long numeric sequences detected.")

    # ---------------------------------------------------------
    # URL length
    # ---------------------------------------------------------

    if features.get("url_length", 0) >= 150:
        risk_score += 5
        indicators.append("URL is unusually long.")

    # ---------------------------------------------------------
    # Cap score
    # ---------------------------------------------------------

    risk_score = min(risk_score, 100)

    # ---------------------------------------------------------
    # Risk category
    # ---------------------------------------------------------

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators
    }