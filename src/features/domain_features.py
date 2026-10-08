# src/features/domain_features.py

import math
import re
import tldextract
from urllib.parse import urlparse


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""

    if not text:
        return 0.0

    frequency = {}

    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    length = len(text)

    entropy = 0.0

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_domain_features(url: str) -> dict:
    """
    Extract advanced domain and subdomain features.
    """

    features = {
        "registered_domain_length": 0,
        "subdomain_length": 0,
        "subdomain_count": 0,
        "domain_digit_count": 0,
        "domain_hyphen_count": 0,
        "domain_underscore_count": 0,
        "domain_entropy": 0.0,
        "subdomain_entropy": 0.0,
        "tld_length": 0,
        "has_punycode": 0,
        "has_numeric_tld": 0,
        "domain_has_digits": 0,
        "domain_has_hyphen": 0,
        "subdomain_has_hyphen": 0,
    }

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return features

        hostname = hostname.rstrip(".")

        extracted = tldextract.extract(hostname)

        subdomain = extracted.subdomain or ""
        domain = extracted.domain or ""
        suffix = extracted.suffix or ""

        # Registered domain
        if suffix:
            registered_domain = f"{domain}.{suffix}"
        else:
            registered_domain = domain

        # Length features
        features["registered_domain_length"] = len(
            registered_domain
        )

        features["subdomain_length"] = len(
            subdomain
        )

        # Number of subdomain components
        if subdomain:
            parts = [
                part
                for part in subdomain.split(".")
                if part
            ]

            features["subdomain_count"] = len(parts)

        # Domain character statistics
        features["domain_digit_count"] = sum(
            char.isdigit()
            for char in domain
        )

        features["domain_hyphen_count"] = domain.count(
            "-"
        )

        features["domain_underscore_count"] = domain.count(
            "_"
        )

        # Entropy
        features["domain_entropy"] = calculate_entropy(
            domain
        )

        features["subdomain_entropy"] = calculate_entropy(
            subdomain
        )

        # TLD
        features["tld_length"] = len(
            suffix
        )

        # Punycode detection
        features["has_punycode"] = int(
            "xn--" in hostname.lower()
        )

        # Numeric TLD
        features["has_numeric_tld"] = int(
            bool(re.search(r"\d", suffix))
        )

        # Domain flags
        features["domain_has_digits"] = int(
            bool(re.search(r"\d", domain))
        )

        features["domain_has_hyphen"] = int(
            "-" in domain
        )

        # Subdomain flags
        features["subdomain_has_hyphen"] = int(
            "-" in subdomain
        )

    except Exception:
        pass

    return features