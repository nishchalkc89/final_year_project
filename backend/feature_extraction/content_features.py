"""
Content-based feature extraction.
Fetches page HTML and inspects DOM elements for phishing indicators.
"""

import re
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from config import REQUEST_TIMEOUT


FORM_FIELD_PATTERNS = re.compile(
    r'(password|passwd|pwd|pass|secret|credit.?card|cvv|ssn|social.?security)',
    re.IGNORECASE,
)


def extract_content_features(url: str) -> dict:
    """Fetch page and return content-based features."""
    defaults = {
        "has_login_form": 0,
        "has_password_field": 0,
        "has_iframe": 0,
        "has_meta_redirect": 0,
        "num_external_links": 0,
        "num_internal_links": 0,
        "has_favicon": 0,
        "title_matches_domain": 0,
        "form_action_external": 0,
        "num_scripts": 0,
        "has_hidden_elements": 0,
        "page_title": "",
        "fetch_success": 0,
        "status_code": 0,
    }

    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        if "://" not in url:
            url = "http://" + url

        with httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
            defaults["status_code"] = response.status_code
            if response.status_code not in (200, 201, 202):
                return defaults
            html = response.text
    except Exception:
        return defaults

    defaults["fetch_success"] = 1
    soup = BeautifulSoup(html, "html.parser")
    parsed = urlparse(url)
    base_domain = parsed.netloc.lower()

    # Page title
    title_tag = soup.find("title")
    if title_tag:
        defaults["page_title"] = title_tag.get_text(strip=True)[:200]
        domain_part = base_domain.replace("www.", "").split(".")[0]
        if domain_part and domain_part.lower() in defaults["page_title"].lower():
            defaults["title_matches_domain"] = 1

    # Favicon
    favicon = soup.find("link", rel=lambda r: r and "icon" in str(r).lower())
    defaults["has_favicon"] = 1 if favicon else 0

    # Meta refresh redirect
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    defaults["has_meta_redirect"] = 1 if meta_refresh else 0

    # iFrames
    iframes = soup.find_all("iframe")
    defaults["has_iframe"] = 1 if iframes else 0

    # Scripts
    defaults["num_scripts"] = len(soup.find_all("script"))

    # Hidden elements
    hidden = soup.find_all(
        lambda tag: tag.get("style") and "display:none" in tag.get("style", "").replace(" ", "").lower()
    )
    defaults["has_hidden_elements"] = 1 if hidden else 0

    # Forms and password fields
    forms = soup.find_all("form")
    for form in forms:
        inputs = form.find_all("input")
        for inp in inputs:
            inp_type = inp.get("type", "").lower()
            inp_name = inp.get("name", "").lower()
            inp_id = inp.get("id", "").lower()
            if inp_type == "password" or FORM_FIELD_PATTERNS.search(inp_name + inp_id):
                defaults["has_password_field"] = 1
                defaults["has_login_form"] = 1

        # Check form action pointing externally
        action = form.get("action", "")
        if action:
            action_url = urljoin(url, action)
            action_domain = urlparse(action_url).netloc.lower()
            if action_domain and action_domain != base_domain:
                defaults["form_action_external"] = 1

    # External vs internal links
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if href.startswith("http"):
            link_domain = urlparse(href).netloc.lower()
            if link_domain != base_domain:
                defaults["num_external_links"] += 1
            else:
                defaults["num_internal_links"] += 1

    return defaults
