import re
import math
from urllib.parse import urlparse
from collections import Counter

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "paypal", "signin", "wallet", "free", "bonus",
    "suspend", "locked", "kyc", "alert", "auth", "credential", "webscr"
]

RISKY_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".work", ".info", ".buzz", ".rest", ".icu"
}

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def extract_url_features(url: str) -> list[float]:
    url = str(url).strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme.lower()
    except ValueError:
        cleaned = re.sub(r"[\[\]]", "", url)
        parts = cleaned.split("://", 1)
        scheme = parts[0].lower() if len(parts) > 1 else "http"
        rest = parts[1] if len(parts) > 1 else parts[0]
        host_and_path = rest.split("/", 1)
        hostname = host_and_path[0].split(":", 1)[0].lower()
        path_and_query = ("/" + host_and_path[1]) if len(host_and_path) > 1 else ""
        pq_split = path_and_query.split("?", 1)
        path = pq_split[0]
        query = pq_split[1] if len(pq_split) > 1 else ""

    # Core lengths
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # Character & symbol counts
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    at_count = url.count("@")
    slash_count = url.count("/")
    question_count = url.count("?")
    equal_count = url.count("=")
    ampersand_count = url.count("&")
    underscore_count = url.count("_")
    percent_count = url.count("%")

    digit_count = sum(c.isdigit() for c in url)
    letter_count = sum(c.isalpha() for c in url)
    host_digit_count = sum(c.isdigit() for c in hostname)

    # Structural & risk indicators
    has_https = 1 if scheme == "https" else 0
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    has_punycode = 1 if "xn--" in hostname else 0
    has_risky_tld = 1 if any(hostname.endswith(tld) for tld in RISKY_TLDS) else 0
    subdomain_count = max(0, hostname.count(".") - 1)
    path_depth = len([seg for seg in path.split("/") if seg])
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())

    # Ratios & entropy
    digit_to_url_ratio = digit_count / max(1, url_length)
    host_to_url_ratio = hostname_length / max(1, url_length)
    domain_entropy = calculate_entropy(hostname)
    path_entropy = calculate_entropy(path)

    return [
        float(url_length), float(hostname_length), float(path_length), float(query_length),
        float(dot_count), float(hyphen_count), float(at_count), float(slash_count),
        float(question_count), float(equal_count), float(ampersand_count),
        float(underscore_count), float(percent_count),
        float(digit_count), float(letter_count), float(host_digit_count),
        float(has_https), float(has_ip), float(has_punycode), float(has_risky_tld),
        float(subdomain_count), float(path_depth), float(keyword_hits),
        float(digit_to_url_ratio), float(host_to_url_ratio),
        float(domain_entropy), float(path_entropy)
    ]