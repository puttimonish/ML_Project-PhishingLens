import re
from urllib.parse import urlparse

import tldextract

from src.features.domain_features import extract_domain_features


BRAND_DOMAINS = {
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "paypal": ["paypal.com"],
    "telegram": ["telegram.org"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com"],
    "youtube": ["youtube.com"],
    "whatsapp": ["whatsapp.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "steampowered": ["steampowered.com"],
    "discord": ["discord.com"],
    "chatgpt": ["chatgpt.com"],
    "openai": ["openai.com"],
}


def _brand_in_text(brand: str, text: str) -> bool:
    """Match a brand as a separate alphanumeric token."""
    if not text:
        return False

    pattern = rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])"
    return bool(re.search(pattern, text.lower()))


def detect_brand_features(url: str) -> dict:
    """Detect known brands and possible domain impersonation."""
    url = str(url).strip()
    parsed = urlparse(url)

    # Also support URLs entered without a scheme.
    if not parsed.scheme:
        parsed = urlparse("http://" + url)

    hostname = (parsed.hostname or "").lower().rstrip(".")
    path = (parsed.path or "").lower()

    # Keep the same domain feature extraction used by the project.
    extract_domain_features(url)

    registered_domain = ""
    domain_label = ""
    subdomain_text = ""

    try:
        extracted = tldextract.extract(hostname)

        domain_label = (extracted.domain or "").lower()

        if extracted.domain and extracted.suffix:
            registered_domain = (
                f"{extracted.domain}.{extracted.suffix}"
            ).lower()
        elif extracted.domain:
            registered_domain = extracted.domain.lower()

        subdomain_text = (extracted.subdomain or "").lower()

    except Exception:
        registered_domain = hostname
        domain_label = hostname.split(".")[0] if hostname else ""

    brand_detected = ""
    brand_match = 0
    brand_in_subdomain = 0
    brand_in_path = 0
    brand_domain_mismatch = 0

    for brand, official_domains in BRAND_DOMAINS.items():
        official_domains = [
            domain.lower() for domain in official_domains
        ]

        # The registered domain must match an official domain.
        official_match = registered_domain in official_domains

        # Detect both separate brand tokens and embedded names
        # in the registered domain, e.g. evilchatgpt.com.
        brand_in_registered_label = brand in domain_label

        hostname_has_brand = (
            _brand_in_text(brand, hostname)
            or brand_in_registered_label
        )

        in_subdomain = _brand_in_text(brand, subdomain_text)
        in_path = _brand_in_text(brand, path)

        if hostname_has_brand or in_path:
            brand_detected = brand
            brand_match = int(official_match)
            brand_in_subdomain = int(in_subdomain)
            brand_in_path = int(in_path)

            # A brand appearing in a non-official registered
            # domain or in a deceptive subdomain is a warning.
            if hostname_has_brand and not official_match:
                brand_domain_mismatch = 1

            break

    return {
        "brand_detected": brand_detected,
        "brand_match": brand_match,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "brand_domain_mismatch": brand_domain_mismatch,
    }
