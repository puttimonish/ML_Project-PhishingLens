# src/features/url_features.py

import math
import re
from urllib.parse import urlparse

from src.features.domain_features import extract_domain_features
from src.features.brand_features import detect_brand_features
from src.features.obfuscation_features import extract_obfuscation_features


# =========================================================
# SUSPICIOUS KEYWORDS
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "passwd",
    "credential",
    "credentials",
    "authenticate",
    "authentication",
    "confirm",
    "confirmation",
    "update",
    "unlock",
    "suspend",
    "suspended",
    "payment",
    "billing",
    "invoice",
    "wallet",
    "banking",
    "bank",
    "recover",
    "recovery",
    "reset",
    "validate",
    "validation",
    "webmail",
    "admin",
    "support",
    "alert",
    "warning",
]


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(text):
    """
    Calculate Shannon entropy efficiently.

    Higher entropy can indicate a more random,
    obfuscated, or machine-generated string.
    """

    if not text:
        return 0.0

    length = len(text)

    counts = {}

    for char in text:
        counts[char] = counts.get(char, 0) + 1

    entropy = 0.0

    for count in counts.values():

        probability = count / length

        entropy -= (
            probability *
            math.log2(probability)
        )

    return entropy


# =========================================================
# SAFE URL PARSING
# =========================================================

def safe_url_parse(url: str):
    """
    Safely parse a URL.

    If the URL has no scheme, assume HTTP
    so that hostname/path information can
    still be extracted.
    """

    try:

        parsed = urlparse(url)

        if not parsed.scheme:

            parsed = urlparse(
                "http://" + url
            )

        return parsed

    except Exception:

        return None


# =========================================================
# MAIN FEATURE EXTRACTION
# =========================================================

def extract_url_features(url: str) -> dict:
    """
    Extract the complete PhishingLens
    feature set.

    Feature groups:

    1. Lexical URL features
    2. Host/domain features
    3. Brand intelligence
    4. Obfuscation features
    5. Fragment intelligence
    """

    # -----------------------------------------------------
    # BASIC DEFAULT FEATURES
    # -----------------------------------------------------

    features = {

        # URL structure
        "url_length": 0,
        "hostname_length": 0,
        "path_length": 0,
        "query_length": 0,
        "fragment_length": 0,

        # NEW: Fragment features
        "fragment_digit_count": 0,
        "fragment_letter_count": 0,
        "fragment_special_char_count": 0,
        "fragment_digit_ratio": 0.0,
        "fragment_entropy": 0.0,
        "fragment_is_numeric": 0,
        "fragment_has_hash_identifier": 0,

        # Character statistics
        "digit_count": 0,
        "letter_count": 0,
        "special_char_count": 0,
        "uppercase_count": 0,
        "dot_count": 0,
        "hyphen_count": 0,
        "underscore_count": 0,
        "slash_count": 0,
        "question_mark_count": 0,
        "equals_count": 0,
        "ampersand_count": 0,
        "at_count": 0,
        "percent_count": 0,
        "colon_count": 0,
        "semicolon_count": 0,

        # Ratios
        "digit_ratio": 0.0,
        "uppercase_ratio": 0.0,
        "special_char_ratio": 0.0,

        # Protocol
        "has_https": 0,
        "has_http": 0,

        # Host
        "has_ip": 0,

        # Suspicious keywords
        "has_suspicious_keyword": 0,
        "suspicious_keyword_count": 0,

        # Entropy
        "url_entropy": 0.0,
        "hostname_entropy": 0.0,

        # Domain
        "domain_length": 0,
        "tld_length": 0,

        # Network / URL structure
        "has_port": 0,
        "has_fragment": 0,
        "has_query": 0,
        "has_double_slash": 0,

        # Encoding
        "percent_encoding_count": 0,
        "hexadecimal_count": 0,

        # Sequential patterns
        "consecutive_digit_count": 0,
        "consecutive_hyphen_count": 0,

        # Path
        "path_depth": 0,
        "path_token_count": 0,
        "path_digit_count": 0,
        "path_special_char_count": 0,
        "path_entropy": 0.0,

        # Query
        "query_parameter_count": 0,
        "query_digit_count": 0,
        "query_entropy": 0.0,
    }

    # The rest of the function continues in Part 2. 
        # -----------------------------------------------------
    # PARSE URL
    # -----------------------------------------------------

    parsed = safe_url_parse(url)

    if parsed is None:
        return features

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Main URL without the fragment.
    #
    # Example:
    #
    # https://web.telegram.org/k/#-2632530375
    #
    # becomes:
    #
    # https://web.telegram.org/k/
    #
    # This prevents fragment identifiers from being
    # incorrectly counted as suspicious URL digits.
    main_url_without_fragment = url.split(
        "#",
        1
    )[0]

    # -----------------------------------------------------
    # FRAGMENT ANALYSIS
    # -----------------------------------------------------

    fragment_digit_count = sum(
        char.isdigit()
        for char in fragment
    )

    fragment_letter_count = sum(
        char.isalpha()
        for char in fragment
    )

    fragment_special_char_count = sum(
        not char.isalnum()
        for char in fragment
    )

    fragment_digit_ratio = (
        fragment_digit_count / len(fragment)
        if fragment
        else 0.0
    )

    fragment_entropy = calculate_entropy(
        fragment
    )

    # Detect fragments such as:
    #
    # -2632530375
    #
    # which are numeric identifiers rather than
    # part of the actual domain/path.
    fragment_is_numeric = int(
        bool(fragment)
        and fragment.lstrip("-").isdigit()
    )

    # Detect hash-style identifiers.
    fragment_has_hash_identifier = int(
        bool(fragment)
        and (
            fragment.startswith("-")
            or any(
                char.isdigit()
                for char in fragment
            )
        )
    )

    url_lower = url.lower()

    # -----------------------------------------------------
    # BASIC LENGTH FEATURES
    # -----------------------------------------------------

    features["url_length"] = len(url)

    features["hostname_length"] = len(
        hostname
    )

    features["path_length"] = len(
        path
    )

    features["query_length"] = len(
        query
    )

    features["fragment_length"] = len(
        fragment
    )

    # -----------------------------------------------------
    # FRAGMENT FEATURES
    # -----------------------------------------------------

    features["fragment_digit_count"] = (
        fragment_digit_count
    )

    features["fragment_letter_count"] = (
        fragment_letter_count
    )

    features["fragment_special_char_count"] = (
        fragment_special_char_count
    )

    features["fragment_digit_ratio"] = (
        fragment_digit_ratio
    )

    features["fragment_entropy"] = (
        fragment_entropy
    )

    features["fragment_is_numeric"] = (
        fragment_is_numeric
    )

    features["fragment_has_hash_identifier"] = (
        fragment_has_hash_identifier
    )
        # -----------------------------------------------------
    # CHARACTER FEATURES
    # -----------------------------------------------------

    # IMPORTANT:
    # Main URL character statistics exclude the fragment.
    #
    # This prevents a fragment such as:
    #
    # #-2632530375
    #
    # from making the URL appear to contain a
    # suspicious 10-digit sequence.

    features["digit_count"] = sum(
        char.isdigit()
        for char in main_url_without_fragment
    )

    features["letter_count"] = sum(
        char.isalpha()
        for char in url
    )

    features["uppercase_count"] = sum(
        char.isupper()
        for char in url
    )

    special_characters = set(
        "!@#$%^&*()_+-=[]{}|;:',.<>?/\\`~"
    )

    features["special_char_count"] = sum(
        char in special_characters
        for char in url
    )

    features["dot_count"] = url.count(
        "."
    )

    features["hyphen_count"] = url.count(
        "-"
    )

    features["underscore_count"] = url.count(
        "_"
    )

    features["slash_count"] = url.count(
        "/"
    )

    features["question_mark_count"] = url.count(
        "?"
    )

    features["equals_count"] = url.count(
        "="
    )

    features["ampersand_count"] = url.count(
        "&"
    )

    features["at_count"] = url.count(
        "@"
    )

    features["percent_count"] = url.count(
        "%"
    )

    features["colon_count"] = url.count(
        ":"
    )

    features["semicolon_count"] = url.count(
        ";"
    )

    # -----------------------------------------------------
    # RATIOS
    # -----------------------------------------------------

    main_url_length = max(
        len(main_url_without_fragment),
        1
    )

    url_length = max(
        len(url),
        1
    )

    features["digit_ratio"] = (
        features["digit_count"] /
        main_url_length
    )

    features["uppercase_ratio"] = (
        features["uppercase_count"] /
        url_length
    )

    features["special_char_ratio"] = (
        features["special_char_count"] /
        url_length
    )
        # -----------------------------------------------------
    # PROTOCOL
    # -----------------------------------------------------

    features["has_https"] = int(
        parsed.scheme.lower() == "https"
    )

    features["has_http"] = int(
        parsed.scheme.lower() == "http"
    )

    # -----------------------------------------------------
    # IP ADDRESS DETECTION
    # -----------------------------------------------------

    ipv4_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    features["has_ip"] = int(
        bool(
            re.match(
                ipv4_pattern,
                hostname
            )
        )
    )

    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:
            keyword_count += 1

    features["suspicious_keyword_count"] = (
        keyword_count
    )

    features["has_suspicious_keyword"] = int(
        keyword_count > 0
    )

    # -----------------------------------------------------
    # ENTROPY
    # -----------------------------------------------------

    features["url_entropy"] = calculate_entropy(
        url
    )

    features["hostname_entropy"] = (
        calculate_entropy(
            hostname
        )
    )

    # -----------------------------------------------------
    # BASIC DOMAIN INFORMATION
    # -----------------------------------------------------

    domain_parts = hostname.split(".")

    if len(domain_parts) >= 2:

        domain = domain_parts[-2]

        tld = domain_parts[-1]

        features["domain_length"] = len(
            domain
        )

        features["tld_length"] = len(
            tld
        )

    else:

        features["domain_length"] = len(
            hostname
        )

        features["tld_length"] = 0
            # -----------------------------------------------------
    # PORT
    # -----------------------------------------------------

    try:

        features["has_port"] = int(
            parsed.port is not None
        )

    except ValueError:

        features["has_port"] = 0

    # -----------------------------------------------------
    # QUERY / FRAGMENT
    # -----------------------------------------------------

    features["has_query"] = int(
        bool(query)
    )

    features["has_fragment"] = int(
        bool(fragment)
    )

    # -----------------------------------------------------
    # DOUBLE SLASH
    # -----------------------------------------------------

    # Remove the normal protocol separator first.
    #
    # Example:
    # https://example.com
    #
    # should NOT be considered a suspicious
    # double-slash URL.

    after_scheme = re.sub(
        r"^[a-zA-Z]+://",
        "",
        url
    )

    features["has_double_slash"] = int(
        "//" in after_scheme
    )

    # -----------------------------------------------------
    # PERCENT ENCODING
    # -----------------------------------------------------

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        url
    )

    features["percent_encoding_count"] = (
        len(encoded_matches)
    )

    # -----------------------------------------------------
    # HEXADECIMAL PATTERNS
    # -----------------------------------------------------

    hexadecimal_matches = re.findall(
        r"(?i)(?:0x[0-9a-f]+|%[0-9a-f]{2})",
        url
    )

    features["hexadecimal_count"] = (
        len(hexadecimal_matches)
    )

    # -----------------------------------------------------
    # CONSECUTIVE DIGITS
    # -----------------------------------------------------

    # IMPORTANT:
    # Search only the URL before the fragment.
    #
    # This prevents a legitimate fragment such as:
    #
    # #-2632530375
    #
    # from being interpreted as a suspicious
    # 10-digit URL sequence.

    digit_sequences = re.findall(
        r"\d+",
        main_url_without_fragment
    )

    features["consecutive_digit_count"] = max(
        [len(x) for x in digit_sequences],
        default=0
    )

    # -----------------------------------------------------
    # CONSECUTIVE HYPHENS
    # -----------------------------------------------------

    hyphen_sequences = re.findall(
        r"-+",
        url
    )

    features["consecutive_hyphen_count"] = max(
        [len(x) for x in hyphen_sequences],
        default=0
    )

    # -----------------------------------------------------
    # PATH FEATURES
    # -----------------------------------------------------

    if path:

        path_parts = [
            part
            for part in path.split("/")
            if part
        ]

        features["path_depth"] = len(
            path_parts
        )

        features["path_token_count"] = len(
            re.findall(
                r"[A-Za-z0-9]+",
                path
            )
        )

        features["path_digit_count"] = sum(
            char.isdigit()
            for char in path
        )

        features["path_special_char_count"] = sum(
            not char.isalnum()
            for char in path
        )

        features["path_entropy"] = (
            calculate_entropy(path)
        )
            # -----------------------------------------------------
    # QUERY FEATURES
    # -----------------------------------------------------

    if query:

        parameters = [
            parameter
            for parameter in query.split("&")
            if parameter
        ]

        features["query_parameter_count"] = len(
            parameters
        )

        features["query_digit_count"] = sum(
            char.isdigit()
            for char in query
        )

        features["query_entropy"] = (
            calculate_entropy(query)
        )

    # =====================================================
    # ADVANCED DOMAIN FEATURES
    # =====================================================

    domain_features = extract_domain_features(
        url
    )

    features.update(
        domain_features
    )

    # =====================================================
    # BRAND INTELLIGENCE
    # =====================================================

    brand_features = detect_brand_features(
        url
    )

    # Convert textual brand into numerical
    # features for machine learning.
    #
    # The actual brand name is kept separately
    # at the application layer.

    detected_brand = brand_features.pop(
        "brand_detected",
        ""
    )

    features.update(
        brand_features
    )

    # Number of characters in the detected
    # brand name.
    features["brand_name_length"] = len(
        detected_brand
    )
        # =====================================================
    # OBFUSCATION FEATURES
    # =====================================================

    obfuscation_features = (
        extract_obfuscation_features(url)
    )

    features.update(
        obfuscation_features
    )

    # =====================================================
    # FINAL FEATURE DICTIONARY
    # =====================================================

    return features