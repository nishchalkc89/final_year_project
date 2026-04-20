"""
Domain-level feature extraction.
Attempts WHOIS lookup for domain age; falls back to defaults gracefully.
"""

import socket
import ssl
import datetime
import re

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def extract_domain_features(domain: str) -> dict:
    """Return domain-level features including SSL and estimated age."""
    features = {
        "domain_age_days": -1,
        "has_ssl": 0,
        "ssl_valid": 0,
        "domain_resolves": 0,
        "whois_available": 0,
        "registrar": "",
        "creation_date": "",
    }

    if not domain or domain.startswith("http"):
        return features

    # DNS resolution check
    try:
        socket.gethostbyname(domain)
        features["domain_resolves"] = 1
    except socket.gaierror:
        pass

    # SSL certificate check
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=domain
        ) as ssock:
            ssock.settimeout(4)
            ssock.connect((domain, 443))
            cert = ssock.getpeercert()
            if cert:
                features["has_ssl"] = 1
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    not_after = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    )
                    if not_after > datetime.datetime.utcnow():
                        features["ssl_valid"] = 1
    except Exception:
        pass

    # WHOIS lookup for domain age
    if WHOIS_AVAILABLE:
        try:
            w = python_whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                if isinstance(creation, str):
                    for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S"):
                        try:
                            creation = datetime.datetime.strptime(creation, fmt)
                            break
                        except ValueError:
                            pass
                if isinstance(creation, datetime.datetime):
                    age = (datetime.datetime.utcnow() - creation).days
                    features["domain_age_days"] = max(age, 0)
                    features["whois_available"] = 1
                    features["creation_date"] = creation.strftime("%Y-%m-%d")
            if w.registrar:
                features["registrar"] = str(w.registrar)[:100]
        except Exception:
            pass

    return features
