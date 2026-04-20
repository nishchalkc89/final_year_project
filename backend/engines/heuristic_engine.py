"""
Heuristic Detection Engine.
Rule-based analysis using blacklists, pattern matching, and expert rules.
Accepts an optional extra_blacklist set (from DB) at call time.
"""

import re
from config import BLACKLIST_FILE

_file_blacklist: set[str] = set()


def _load_file_blacklist() -> set[str]:
    global _file_blacklist
    if _file_blacklist:
        return _file_blacklist
    try:
        with open(BLACKLIST_FILE, "r") as f:
            _file_blacklist = {
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            }
    except FileNotFoundError:
        _file_blacklist = set()
    return _file_blacklist


BRAND_SQUATTING_PATTERNS = [
    (re.compile(r"paypa[l1]", re.I), "Brand squatting: PayPal impersonation"),
    (re.compile(r"g[o0]{2}gle", re.I), "Brand squatting: Google impersonation"),
    (re.compile(r"amaz[o0]n", re.I), "Brand squatting: Amazon impersonation"),
    (re.compile(r"app[l1]e", re.I), "Brand squatting: Apple impersonation"),
    (re.compile(r"micr[o0]soft", re.I), "Brand squatting: Microsoft impersonation"),
    (re.compile(r"faceb[o0]{2}k", re.I), "Brand squatting: Facebook impersonation"),
    (re.compile(r"netf[l1]ix", re.I), "Brand squatting: Netflix impersonation"),
    (re.compile(r"[i1]nstagram", re.I), "Brand squatting: Instagram impersonation"),
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".click",
    ".link", ".online", ".site", ".top", ".pw", ".cc",
}

IP_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
HEX_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")

LEGITIMATE_DOMAINS = {
    "paypal.com", "google.com", "amazon.com", "apple.com",
    "microsoft.com", "facebook.com", "netflix.com", "instagram.com",
}


def run_heuristic_engine(
    url: str,
    url_features: dict,
    extra_blacklist: set[str] | None = None,
) -> dict:
    """
    Analyze URL using rule-based heuristics.
    extra_blacklist: optional set of domains from the DB blacklist table.
    """
    file_bl = _load_file_blacklist()
    combined_bl = file_bl | (extra_blacklist or set())

    flags: list[str] = []
    penalty = 0
    url_lower = url.lower()
    domain = url_features.get("domain", "").lower()
    tld = url_features.get("tld", "").lower()

    # Rule 1: Blacklist (file + DB)
    if domain in combined_bl or url_lower in combined_bl:
        flags.append("URL found in phishing blacklist")
        penalty += 95
        return _build_result(min(penalty, 100), flags, True)

    for entry in combined_bl:
        if entry and len(entry) > 4 and entry in url_lower:
            flags.append(f"URL matches blacklist pattern: {entry[:50]}")
            penalty += 80
            break

    # Rule 2: IP address
    if IP_PATTERN.match(url):
        flags.append("IP address used instead of domain name")
        penalty += 35

    # Rule 3: URL length
    url_len = url_features.get("url_length", 0)
    if url_len > 100:
        flags.append(f"Excessively long URL ({url_len} characters)")
        penalty += 20
    elif url_len > 75:
        flags.append(f"Unusually long URL ({url_len} characters)")
        penalty += 10

    # Rule 4: Subdomains
    num_sub = url_features.get("num_subdomains", 0)
    if num_sub >= 4:
        flags.append(f"Excessive subdomains ({num_sub})")
        penalty += 25
    elif num_sub == 3:
        flags.append(f"Multiple subdomains ({num_sub})")
        penalty += 10

    # Rule 5: @ symbol
    if url_features.get("num_at_sign", 0) > 0:
        flags.append("'@' symbol in URL (browser ignores content before @)")
        penalty += 30

    # Rule 6: Suspicious TLD
    if url_features.get("has_suspicious_tld", 0):
        flags.append(f"High-risk TLD: .{tld}")
        penalty += 20

    # Rule 7: No HTTPS
    if not url_features.get("has_https", 0):
        flags.append("No HTTPS encryption")
        penalty += 15

    # Rule 8: Double slash in path
    if url_features.get("has_double_slash_in_path", 0):
        flags.append("Double slash (//) detected in URL path")
        penalty += 15

    # Rule 9: Hex encoding
    hex_count = url_features.get("num_hex_encoding", 0)
    if hex_count >= 5:
        flags.append(f"Excessive hex encoding ({hex_count} instances)")
        penalty += 20
    elif hex_count >= 2:
        flags.append(f"Percent encoding in URL ({hex_count} instances)")
        penalty += 8

    # Rule 10: Suspicious keywords
    sus_count = url_features.get("suspicious_word_count", 0)
    if sus_count >= 3:
        flags.append(f"Multiple suspicious keywords in URL ({sus_count})")
        penalty += 30
    elif sus_count >= 1:
        flags.append("Suspicious keyword detected in URL")
        penalty += 15

    # Rule 11: Digits in domain
    if url_features.get("domain_has_digits", 0):
        flags.append("Domain contains digits (possible brand spoofing)")
        penalty += 15

    # Rule 12: Brand squatting
    for pattern, message in BRAND_SQUATTING_PATTERNS:
        if pattern.search(url_lower):
            if not any(legit in url_lower for legit in LEGITIMATE_DOMAINS):
                flags.append(message)
                penalty += 40
                break

    # Rule 13: High entropy
    entropy = url_features.get("url_entropy", 0)
    if entropy > 5.5:
        flags.append(f"Very high URL entropy ({entropy:.2f}) — obfuscated URL")
        penalty += 15
    elif entropy > 4.8:
        flags.append(f"Elevated URL entropy ({entropy:.2f})")
        penalty += 5

    score = min(max(penalty, 0), 100)
    is_blacklisted = any("blacklist" in f.lower() for f in flags)
    return _build_result(score, flags, is_blacklisted)


def _build_result(score: float, flags: list[str], is_blacklisted: bool) -> dict:
    return {
        "score": round(score, 2),
        "flags": flags,
        "is_blacklisted": is_blacklisted,
        "num_flags": len(flags),
    }
