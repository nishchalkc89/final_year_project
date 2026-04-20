"""
PhishGuard Dataset Generator
Generates a realistic labeled phishing dataset (1000 samples).
Run: python generate_dataset.py
Output: dataset.csv
"""

import random
import math
import csv
import hashlib
from pathlib import Path

random.seed(42)

OUTPUT_FILE = Path(__file__).parent / "dataset.csv"

LEGITIMATE_DOMAINS = [
    "google", "facebook", "amazon", "microsoft", "apple", "twitter",
    "linkedin", "instagram", "github", "stackoverflow", "reddit",
    "wikipedia", "youtube", "netflix", "spotify", "dropbox", "slack",
    "zoom", "paypal", "ebay", "shopify", "wordpress", "medium",
    "nytimes", "bbc", "cnn", "reuters", "techcrunch", "wired",
]

LEGITIMATE_TLDS = [".com", ".org", ".net", ".edu", ".gov", ".io", ".co.uk"]

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "validate", "banking", "credential", "authenticate",
    "password-reset", "billing", "payment", "wallet", "prize",
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".click",
                   ".link", ".online", ".site", ".top", ".pw"]


def _entropy(s: str) -> float:
    from collections import Counter
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _gen_legitimate_sample(i: int) -> dict:
    domain_name = random.choice(LEGITIMATE_DOMAINS)
    tld = random.choice(LEGITIMATE_TLDS[:4])  # prefer .com/.org/.net/.edu
    has_subdomain = random.random() < 0.3
    subdomain = random.choice(["www", "mail", "docs", "shop"]) if has_subdomain else ""

    path_segs = random.randint(0, 3)
    path = "/" + "/".join(
        random.choice(["about", "products", "contact", "help", "faq", "blog", "news"])
        for _ in range(path_segs)
    ) if path_segs else "/"

    has_query = random.random() < 0.2
    query = f"?id={random.randint(1, 9999)}" if has_query else ""

    full_url = f"https://{subdomain + '.' if subdomain else ''}{domain_name}{tld}{path}{query}"

    return {
        "url_length": len(full_url),
        "num_dots": full_url.count("."),
        "num_hyphens": full_url.count("-"),
        "num_underscores": full_url.count("_"),
        "num_slashes": full_url.count("/"),
        "num_at_sign": 0,
        "num_question_marks": 1 if has_query else 0,
        "num_equals": 1 if has_query else 0,
        "num_percent": 0,
        "num_ampersands": 0,
        "num_digits_in_url": sum(c.isdigit() for c in full_url),
        "has_ip_address": 0,
        "has_https": 1,
        "url_entropy": round(_entropy(full_url), 4),
        "num_subdomains": 1 if has_subdomain else 0,
        "domain_length": len(domain_name),
        "has_suspicious_tld": 0,
        "path_length": len(path),
        "query_length": len(query),
        "has_suspicious_words": 0,
        "suspicious_word_count": 0,
        "num_hex_encoding": 0,
        "has_double_slash_in_path": 0,
        "has_at_in_netloc": 0,
        "domain_has_digits": 0,
        "has_login_form": 1 if random.random() < 0.25 else 0,
        "has_password_field": 1 if random.random() < 0.2 else 0,
        "has_iframe": 0,
        "has_meta_redirect": 0,
        "num_external_links": random.randint(2, 20),
        "form_action_external": 0,
        "num_scripts": random.randint(3, 15),
        "has_hidden_elements": 0,
        "domain_age_days": random.randint(365, 5000),
        "has_ssl": 1,
        "ssl_valid": 1,
        "domain_resolves": 1,
        "label": 0,
    }


def _gen_phishing_sample(i: int) -> dict:
    use_ip = random.random() < 0.2
    use_sus_tld = random.random() < 0.45
    use_long_url = random.random() < 0.6

    if use_ip:
        domain_str = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        tld = ""
        domain_name = domain_str
    else:
        legit_brand = random.choice(LEGITIMATE_DOMAINS[:10])
        junk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(4, 12)))
        domain_name = f"{legit_brand}-{junk}" if random.random() > 0.4 else f"{legit_brand}{random.randint(1, 99)}"
        tld = random.choice(SUSPICIOUS_TLDS) if use_sus_tld else ".com"

    num_sub = random.randint(0, 4)
    subdomains = ".".join(
        random.choice(["secure", "login", "verify", "account", "update", "billing"])
        for _ in range(num_sub)
    ) if num_sub else ""

    keyword = random.choice(PHISHING_KEYWORDS)
    path = f"/{keyword}/{random.randint(1000, 9999)}"
    if use_long_url:
        extra = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789-_", k=random.randint(20, 80)))
        path += f"/{extra}"

    has_query = random.random() < 0.6
    query_params = "&".join(
        f"{random.choice(['id', 'ref', 'token', 'key', 'redirect', 'next', 'url'])}={random.randint(1000, 99999)}"
        for _ in range(random.randint(1, 5))
    ) if has_query else ""
    query = f"?{query_params}" if has_query else ""

    has_https = random.random() < 0.55
    scheme = "https" if has_https else "http"

    full_url = f"{scheme}://{subdomains + '.' if subdomains else ''}{domain_name}{tld}{path}{query}"

    sus_word_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in full_url.lower())
    hex_count = random.randint(0, 6) if random.random() < 0.3 else 0

    return {
        "url_length": len(full_url),
        "num_dots": full_url.count("."),
        "num_hyphens": full_url.count("-"),
        "num_underscores": full_url.count("_"),
        "num_slashes": full_url.count("/"),
        "num_at_sign": 1 if random.random() < 0.15 else 0,
        "num_question_marks": 1 if has_query else 0,
        "num_equals": query_params.count("=") if has_query else 0,
        "num_percent": hex_count * 3,
        "num_ampersands": query_params.count("&") if has_query else 0,
        "num_digits_in_url": sum(c.isdigit() for c in full_url),
        "has_ip_address": 1 if use_ip else 0,
        "has_https": 1 if has_https else 0,
        "url_entropy": round(_entropy(full_url), 4),
        "num_subdomains": num_sub,
        "domain_length": len(domain_name.split(".")[0]) if not use_ip else 10,
        "has_suspicious_tld": 1 if use_sus_tld else 0,
        "path_length": len(path),
        "query_length": len(query),
        "has_suspicious_words": 1 if sus_word_hits > 0 else 0,
        "suspicious_word_count": sus_word_hits,
        "num_hex_encoding": hex_count,
        "has_double_slash_in_path": 1 if random.random() < 0.1 else 0,
        "has_at_in_netloc": 1 if random.random() < 0.1 else 0,
        "domain_has_digits": 1 if any(c.isdigit() for c in domain_name.split(".")[0]) else 0,
        "has_login_form": 1 if random.random() < 0.8 else 0,
        "has_password_field": 1 if random.random() < 0.75 else 0,
        "has_iframe": 1 if random.random() < 0.4 else 0,
        "has_meta_redirect": 1 if random.random() < 0.35 else 0,
        "num_external_links": random.randint(0, 5),
        "form_action_external": 1 if random.random() < 0.55 else 0,
        "num_scripts": random.randint(1, 8),
        "has_hidden_elements": 1 if random.random() < 0.45 else 0,
        "domain_age_days": random.randint(0, 90),
        "has_ssl": 1 if has_https else 0,
        "ssl_valid": 1 if (has_https and random.random() < 0.4) else 0,
        "domain_resolves": 1 if random.random() < 0.85 else 0,
        "label": 1,
    }


def generate_dataset(n_legitimate: int = 500, n_phishing: int = 500) -> list[dict]:
    samples = []
    for i in range(n_legitimate):
        samples.append(_gen_legitimate_sample(i))
    for i in range(n_phishing):
        samples.append(_gen_phishing_sample(i))
    random.shuffle(samples)
    return samples


def save_csv(samples: list[dict], path: Path):
    if not samples:
        return
    fieldnames = list(samples[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(samples)
    print(f"OK Dataset saved: {path} ({len(samples)} samples)")


if __name__ == "__main__":
    print("Generating PhishGuard dataset...")
    data = generate_dataset(500, 500)
    save_csv(data, OUTPUT_FILE)
    phishing = sum(1 for d in data if d["label"] == 1)
    legit = sum(1 for d in data if d["label"] == 0)
    print(f"   Legitimate: {legit} | Phishing: {phishing}")
