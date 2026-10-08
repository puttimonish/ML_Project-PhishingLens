from pathlib import Path
from urllib.parse import urlparse



import joblib

import pandas as pd



from src.preprocessing.feature_extractor import extract_features





# ============================================================

# MODEL CONFIGURATION

# ============================================================



MODEL_PATH = Path("models/phishinglens_calibrated_v2.joblib")





# ============================================================

# LOAD MODEL

# ============================================================



class PhishingPredictor:

          def __init__(self, model_path=MODEL_PATH):

                    self.model_path = Path(model_path)



                    if not self.model_path.exists():

                              raise FileNotFoundError(f"Model not found: {self.model_path}")



                    self.model = joblib.load(self.model_path)

                    self.model_features = None



                    # Recover feature names from the trained model.

                    if hasattr(self.model, "feature_names_in_"):

                              self.model_features = list(self.model.feature_names_in_)



                    # Support calibrated classifiers.

                    elif hasattr(self.model, "calibrated_classifiers_"):

                              calibrated_models = self.model.calibrated_classifiers_

                              if calibrated_models:

                                        estimator = calibrated_models[0].estimator

                                        if hasattr(estimator, "feature_names_in_"):

                                                  self.model_features = list(estimator.feature_names_in_)



          # ========================================================

          # MACHINE LEARNING PREDICTION

          # ========================================================



          def predict(self, url):

                    features = extract_features(url)

                    feature_df = pd.DataFrame([features])



                    # Match the feature order used during training.

                    if self.model_features is not None:

                              missing_features = [

                                        feature for feature in self.model_features

                                        if feature not in feature_df.columns

                              ]

                              if missing_features:

                                        raise ValueError(f"Missing model features: {missing_features}")



                              feature_df = feature_df[self.model_features]



                    probabilities = self.model.predict_proba(feature_df)[0]

                    classes = list(self.model.classes_)



                    if 1 not in classes:

                              raise ValueError(

                                        "The trained model does not contain the expected phishing class label 1."

                              )



                    phishing_index = classes.index(1)

                    phishing_probability = float(probabilities[phishing_index])

                    legitimate_probability = 1.0 - phishing_probability



                    # This is the model's classification; contextual assessment is separate.

                    prediction = "PHISHING" if phishing_probability >= 0.50 else "LEGITIMATE"



                    return {

                              "prediction": prediction,

                              "phishing_probability": phishing_probability,

                              "legitimate_probability": legitimate_probability,

                              "features": features,

                    }





# ============================================================

# CONTEXTUAL RISK SCORE

# ============================================================



def calculate_risk_score(phishing_probability, features):

          """Calculate a contextual risk score from 0 to 100.



          The model probability is kept separate from the contextual risk score.

          """

          ml_score = phishing_probability * 100

          positive_adjustment = 0

          negative_adjustment = 0



          # Suspicious indicators

          if features.get("brand_domain_mismatch", 0):

                    positive_adjustment += 20

          if features.get("has_ip", 0):

                    positive_adjustment += 12

          if features.get("has_punycode", 0):

                    positive_adjustment += 10

          if features.get("has_encoded_characters", 0):

                    positive_adjustment += 7

          if features.get("has_suspicious_keyword", 0):

                    positive_adjustment += 7

          if features.get("at_count", 0) > 0:

                    positive_adjustment += 7

          if features.get("percent_encoding_count", 0) >= 2:

                    positive_adjustment += 5

          if features.get("subdomain_count", 0) >= 3:

                    positive_adjustment += 5

          if features.get("consecutive_digit_count", 0) >= 6:

                    positive_adjustment += 5

          if features.get("url_length", 0) >= 150:

                    positive_adjustment += 5



          # Contextual reductions. An official-domain match is a signal, not a guarantee.

          if (

                    features.get("brand_match", 0)

                    and not features.get("brand_domain_mismatch", 0)

          ):

                    negative_adjustment += 20



          # Numeric/hash fragments can be normal application data.

          if (

                    features.get("fragment_is_numeric", 0)

                    and features.get("fragment_has_hash_identifier", 0)

                    and not features.get("brand_domain_mismatch", 0)

                    and not features.get("has_suspicious_keyword", 0)

          ):

                    negative_adjustment += 5



          risk_score = ml_score + positive_adjustment - negative_adjustment

          risk_score = max(0, min(round(risk_score), 100))



          if risk_score < 30:

                    risk_level = "LOW"

          elif risk_score < 70:

                    risk_level = "SUSPICIOUS"

          else:

                    risk_level = "HIGH"



          return {

                    "risk_score": risk_score,

                    "risk_level": risk_level,

                    "ml_score": round(ml_score, 2),

                    "positive_adjustment": positive_adjustment,

                    "negative_adjustment": negative_adjustment,

          }





# ============================================================

# EXPLANATION ENGINE

# ============================================================



def generate_explanations(features):

          explanations = []



          if features.get("has_https", 0):

                    explanations.append("The URL uses HTTPS.")

          else:

                    explanations.append("The URL does not use HTTPS.")



          # Check mismatch before brand_match: deceptive domains may contain a brand name.

          if features.get("brand_domain_mismatch", 0):

                    explanations.append(

                              "A known brand name appears in a domain that does not match its official registered domain."

                    )

          elif features.get("brand_match", 0):

                    explanations.append(

                              "The detected brand matches its expected registered domain."

                    )



          if features.get("has_suspicious_keyword", 0):

                    count = features.get("suspicious_keyword_count", 1)

                    explanations.append(

                              f"The URL contains {count} suspicious security-related keyword(s)."

                    )



          if features.get("has_ip", 0):

                    explanations.append(

                              "The URL uses an IP address instead of a conventional domain."

                    )



          if features.get("has_punycode", 0):

                    explanations.append(

                              "The domain contains Punycode, which can sometimes be used in look-alike domains."

                    )



          if features.get("has_encoded_characters", 0):

                    explanations.append("Encoded characters were detected in the URL.")



          if features.get("at_count", 0) > 0:

                    explanations.append("The URL contains '@', which can obscure the actual destination.")



          if features.get("subdomain_count", 0) >= 3:

                    explanations.append("The URL contains multiple levels of subdomains.")



          if features.get("percent_encoding_count", 0) >= 2:

                    explanations.append("Multiple percent-encoded characters were detected.")



          if (

                    features.get("fragment_is_numeric", 0)

                    and features.get("fragment_has_hash_identifier", 0)

                    and not features.get("brand_domain_mismatch", 0)

          ):

                    explanations.append(

                              "The URL contains a numeric client-side fragment; this can be normal application data and is not automatically treated as a phishing indicator."

                    )



          return explanations





# ============================================================

# USER-FACING CONTEXTUAL ASSESSMENT

# ============================================================



def determine_assessment(phishing_probability, features):

          """Create a contextual assessment without changing model probabilities.



          phishing_probability is a fraction between 0.0 and 1.0.

          """

          brand_mismatch = bool(features.get("brand_domain_mismatch", 0))

          brand_match = bool(features.get("brand_match", 0))

          suspicious_keyword = bool(features.get("has_suspicious_keyword", 0))



          if phishing_probability >= 0.80:

                    return {

                              "assessment": "HIGH RISK",

                              "assessment_reason": "The model estimates a high phishing probability.",

                              "recommended_action": "Avoid entering credentials or sensitive information.",

                    }



          if brand_mismatch:

                    return {

                              "assessment": "SUSPICIOUS",

                              "assessment_reason": (

                                        "A recognized brand name appears on a domain that does not match its official domain."

                              ),

                              "recommended_action": "Verify the domain using the brand's official website.",

                    }



          if brand_match and phishing_probability >= 0.50:

                    return {

                              "assessment": "REVIEW",

                              "assessment_reason": (

                                        "The model flags this URL, but the domain matches a recognized brand domain. "

                                        "These conflicting signals require further review."

                              ),

                              "recommended_action": "Verify the complete URL before entering sensitive data.",

                    }



          if phishing_probability >= 0.50 or suspicious_keyword:

                    return {

                              "assessment": "SUSPICIOUS",

                              "assessment_reason": "The model or URL indicators raise a potential phishing concern.",

                              "recommended_action": "Do not enter sensitive information until the URL is verified.",

                    }



          if phishing_probability >= 0.25:

                    return {

                              "assessment": "REVIEW",

                              "assessment_reason": (

                                        "The model indicates some phishing risk, so additional verification is recommended."

                              ),

                              "recommended_action": "Check the registered domain and destination before proceeding.",

                    }



          return {

                    "assessment": "LOW RISK",

                    "assessment_reason": (

                              "The model estimates a low phishing probability and no stronger assessment rule was triggered."

                    ),

                    "recommended_action": "Remain cautious; a low-risk assessment is not a guarantee of safety.",

          }





# ============================================================

# COMPLETE URL ANALYSIS

# ============================================================



def _is_supported_telegram_web_url(url, features):
    """Recognize a narrow set of official Telegram Web client URLs.

    This contextual rule does not prove that Telegram content or linked messages
    are safe. It only prevents a known, exact official client URL pattern from
    being classified as phishing solely because the model dislikes its fragment.
    """
    try:
        parsed = urlparse(str(url).strip())
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return False

    if parsed.scheme.lower() != "https":
        return False
    if hostname != "web.telegram.org":
        return False
    if port not in (None, 443):
        return False
    if not parsed.path.startswith("/k/"):
        return False
    if not bool(features.get("brand_match", 0)):
        return False
    if bool(features.get("brand_domain_mismatch", 0)):
        return False

    fragment = parsed.fragment
    numeric_fragment = bool(fragment) and fragment.lstrip("-").isdigit()
    username_fragment = bool(
        fragment
        and len(fragment) >= 6
        and fragment.startswith("@")
        and fragment[1].isalpha()
        and all(character.isalnum() or character == "_" for character in fragment[1:])
        and len(fragment[1:]) <= 32
    )
    return numeric_fragment or username_fragment


def analyze_url(url):
    """Analyze a URL and return ML probabilities plus contextual assessment.

    Model probabilities are never rewritten by contextual rules. The final
    prediction and risk score may differ when a narrow, explicit URL-context
    rule has strong evidence, and that decision is reported transparently.
    """
    url = str(url).strip()
    if not url:
        raise ValueError("URL cannot be empty.")

    predictor = PhishingPredictor()
    result = predictor.predict(url)
    features = result["features"]
    model_prediction = result["prediction"]
    phishing_probability = float(result["phishing_probability"])

    risk = calculate_risk_score(phishing_probability, features)
    explanations = generate_explanations(features)
    final_prediction = model_prediction
    decision_reason = "Final prediction follows the machine-learning model; contextual indicators are shown separately."
    assessment = determine_assessment(phishing_probability, features)

    if _is_supported_telegram_web_url(url, features):
        final_prediction = "LEGITIMATE"
        risk["risk_score"] = min(int(risk["risk_score"]), 15)
        risk["risk_level"] = "LOW"
        decision_reason = (
            "The exact official HTTPS hostname web.telegram.org, the /k/ client path, "
            "and a recognized Telegram-style client fragment match a supported URL pattern. "
            "The original model probability is preserved separately."
        )
        assessment = {
            "assessment": "LOW RISK",
            "assessment_reason": (
                "This URL matches a narrow official Telegram Web client pattern. "
                "This assessment concerns the URL host and structure, not the safety of messages or links inside Telegram."
            ),
            "recommended_action": (
                "Check that the browser remains on https://web.telegram.org and be cautious with links, files, and messages received in chats."
            ),
        }
        explanations.append(
            "Contextual rule: the exact official Telegram Web hostname and supported client-side fragment pattern were recognized. "
            "A numeric or username-style fragment alone is not evidence of phishing."
        )

    elif features.get("brand_domain_mismatch", 0):
        # Do not let a low ML probability conceal a strong domain-impersonation signal.
        final_prediction = "PHISHING"
        risk["risk_score"] = max(int(risk["risk_score"]), 70)
        risk["risk_level"] = "HIGH"
        decision_reason = (
            "A recognized brand name appears on a domain that does not match its expected registered domain. "
            "The contextual rule raises the final risk even if the model probability is low."
        )
        assessment = {
            "assessment": "HIGH RISK",
            "assessment_reason": "The URL contains a detected brand-domain mismatch, which is a strong impersonation warning sign.",
            "recommended_action": "Do not enter credentials or payment details. Navigate to the brand by typing its known official address.",
        }

    return {
        "url": url,
        "prediction": final_prediction,
        "model_prediction": model_prediction,
        "decision_reason": decision_reason,
        "phishing_probability": round(phishing_probability * 100, 2),
        "legitimate_probability": round(float(result["legitimate_probability"]) * 100, 2),
        "risk_score": int(risk["risk_score"]),
        "risk_level": risk["risk_level"],
        "ml_score": risk["ml_score"],
        "positive_adjustment": risk["positive_adjustment"],
        "negative_adjustment": risk["negative_adjustment"],
        "assessment": assessment["assessment"],
        "assessment_reason": assessment["assessment_reason"],
        "recommended_action": assessment["recommended_action"],
        "explanations": explanations,
        "features": features,
    }


if __name__ == "__main__":

          test_urls = [

                    "https://chatgpt.com/",

                    "https://evilchatgpt.com/login",

                    "https://chatgpt.com.evil-example.com/login",

                    "https://web.telegram.org/k/#-2632530375",
                    "https://web.telegram.org/k/#@reddym_07",

          ]



          for test_url in test_urls:

                    print("\n" + "=" * 70)

                    print("PHISHINGLENS URL ANALYSIS")

                    print("=" * 70)

                    try:

                              result = analyze_url(test_url)

                              print("URL:", result["url"])

                              print("Prediction:", result["prediction"])

                              print("Phishing probability:", result["phishing_probability"], "%")

                              print("Legitimate probability:", result["legitimate_probability"], "%")

                              print("Risk score:", result["risk_score"], "/ 100")

                              print("Risk level:", result["risk_level"])

                              print("Assessment:", result["assessment"])

                              print("Reason:", result["assessment_reason"])

                              print("Recommended action:", result["recommended_action"])

                              print("Positive adjustment:", result["positive_adjustment"])

                              print("Negative adjustment:", result["negative_adjustment"])

                              print("\nExplanations:")

                              for explanation in result["explanations"]:

                                        print("-", explanation)

                    except Exception as error:

                              print("Analysis failed:", error)



          print("\n" + "=" * 70)
