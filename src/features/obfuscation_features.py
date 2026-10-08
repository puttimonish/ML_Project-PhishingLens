# src/features/obfuscation_features.py

import re
from urllib.parse import unquote


def extract_obfuscation_features(url: str) -> dict:
    """
    Detect URL encoding, hexadecimal obfuscation,
    punycode and suspicious URL patterns.
    """

    features = {
        "percent_encoding_count": 0,
        "hex_encoding_count": 0,
        "encoded_slash_count": 0,
        "encoded_at_count": 0,
        "encoded_dot_count": 0,
        "encoded_equals_count": 0,
        "has_punycode": 0,
        "has_encoded_characters": 0,
        "double_encoding_count": 0,
    }

    try:

        url_lower = url.lower()

        # Percent encoded characters.
        percent_matches = re.findall(
            r"%[0-9a-f]{2}",
            url_lower
        )

        features["percent_encoding_count"] = len(
            percent_matches
        )

        features["has_encoded_characters"] = int(
            len(percent_matches) > 0
        )

        # Specific encoded characters.
        features["encoded_slash_count"] = len(
            re.findall(r"%2f", url_lower)
        )

        features["encoded_at_count"] = len(
            re.findall(r"%40", url_lower)
        )

        features["encoded_dot_count"] = len(
            re.findall(r"%2e", url_lower)
        )

        features["encoded_equals_count"] = len(
            re.findall(r"%3d", url_lower)
        )

        # Hexadecimal sequences.
        hex_matches = re.findall(
            r"(?:%[0-9a-f]{2})+",
            url_lower
        )

        features["hex_encoding_count"] = len(
            hex_matches
        )

        # Punycode.
        features["has_punycode"] = int(
            "xn--" in url_lower
        )

        # Double encoding.
        decoded_once = unquote(url_lower)

        double_encoded = re.findall(
            r"%[0-9a-f]{2}",
            decoded_once
        )

        features["double_encoding_count"] = len(
            double_encoded
        )

    except Exception:
        pass

    return features