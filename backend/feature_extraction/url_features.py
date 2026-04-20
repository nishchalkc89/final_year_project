"""
URL-based feature extraction module.
Extracts structural and statistical features from raw URL strings.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
import tldextract


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "banking", "paypal", "amazon", "apple", "microsoft",
    "google", "facebook", "instagram", "netflix", "confirm", "validate",
    "password", "credential", "authenticate", "authorize", "wallet", "crypto",
    "prize", "winner", "free", "click", "urgent", "limited", "offer",
    "ebay", "chase", "wellsfargo", "citibank", "hsbc", "irs", "gov-",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".click", ".link",
    ".online", ".site", ".top", ".work", ".club", ".pw", ".cc",
    ".biz", ".info", ".su", ".ws", ".mobi",
}

IP_PATTERN = re.compile(
    r"(https?://)?((\d{1,3}\.){3}\d{1,3})"
)

HEX_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_url_features(url: str) -> dict:
    """Return a flat dict of numeric URL features used by the ML model."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return _empty_features()

    ext = tldextract.extract(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    full_url = url

    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    subdomains = [s for s in subdomain.split(".") if s] if subdomain else []

    has_ip = 1 if IP_PATTERN.match(url) else 0
    has_https = 1 if scheme == "https" else 0

    suspicious_word_count = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url.lower()
    )

    tld_with_dot = f".{suffix}" if suffix else ""
    has_suspicious_tld = 1 if tld_with_dot in SUSPICIOUS_TLDS else 0

    return {
        "url_length": len(full_url),
        "num_dots": full_url.count("."),
        "num_hyphens": full_url.count("-"),
        "num_underscores": full_url.count("_"),
        "num_slashes": full_url.count("/"),
        "num_at_sign": full_url.count("@"),
        "num_question_marks": full_url.count("?"),
        "num_equals": full_url.count("="),
        "num_percent": full_url.count("%"),
        "num_ampersands": full_url.count("&"),
        "num_digits_in_url": sum(c.isdigit() for c in full_url),
        "has_ip_address": has_ip,
        "has_https": has_https,
        "url_entropy": round(_shannon_entropy(full_url), 4),
        "num_subdomains": len(subdomains),
        "domain_length": len(domain),
        "has_suspicious_tld": has_suspicious_tld,
        "path_length": len(path),
        "query_length": len(query),
        "has_suspicious_words": 1 if suspicious_word_count > 0 else 0,
        "suspicious_word_count": suspicious_word_count,
        "num_hex_encoding": len(HEX_PATTERN.findall(full_url)),
        "has_double_slash_in_path": 1 if "//" in path else 0,
        "has_at_in_netloc": 1 if "@" in netloc else 0,
        "domain_has_digits": 1 if any(c.isdigit() for c in domain) else 0,
        "domain": f"{domain}.{suffix}" if suffix else domain,
        "scheme": scheme,
        "subdomain": subdomain,
        "tld": suffix,
    }


def _empty_features() -> dict:
    return {k: 0 for k in [
        "url_length", "num_dots", "num_hyphens", "num_underscores", "num_slashes",
        "num_at_sign", "num_question_marks", "num_equals", "num_percent",
        "num_ampersands", "num_digits_in_url", "has_ip_address", "has_https",
        "url_entropy", "num_subdomains", "domain_length", "has_suspicious_tld",
        "path_length", "query_length", "has_suspicious_words", "suspicious_word_count",
        "num_hex_encoding", "has_double_slash_in_path", "has_at_in_netloc",
        "domain_has_digits",
    ]} | {"domain": "", "scheme": "", "subdomain": "", "tld": ""}
