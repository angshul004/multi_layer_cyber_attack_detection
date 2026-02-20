from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
]

FEATURE_NAMES = [
    # Required baseline features
    "url_length",
    "dot_count",
    "hyphen_count",
    "slash_count",
    "subdomain_count",
    "has_ip_address",
    "uses_https",
    "suspicious_keyword_count",
    # Extra features for stronger classification
    "digit_count",
    "special_char_count",
    "domain_length",
    "path_length",
    "query_length",
    "fragment_length",
    "query_param_count",
    "ampersand_count",
    "at_symbol_count",
    "percent_count",
    "double_slash_count",
    "has_port_number",
    "is_shortened_domain",
    "host_entropy",
    "path_entropy",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "cutt.ly",
    "rb.gy",
    "tiny.cc",
}


def _safe_parse(url: str):
    candidate = url if "://" in url else f"http://{url}"
    try:
        return urlparse(candidate)
    except ValueError:
        # Some datasets contain malformed bracketed hosts that break urlparse.
        sanitized = candidate.replace("[", "").replace("]", "")
        try:
            return urlparse(sanitized)
        except ValueError:
            return urlparse("http://invalid.local")


def _host_from_url(url: str) -> str:
    parsed = _safe_parse(url)
    host = parsed.netloc or parsed.path.split("/")[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host.strip().lower()


def _has_ip_address(host: str) -> int:
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def _subdomain_count(host: str) -> int:
    if not host or _has_ip_address(host):
        return 0
    parts = [p for p in host.split(".") if p]
    return max(len(parts) - 2, 0)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(url: str) -> list:
    url = (url or "").strip()
    host = _host_from_url(url)
    parsed = _safe_parse(url)
    url_lower = url.lower()

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    url_length = len(url)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    slash_count = url.count("/")
    subdomain_count = _subdomain_count(host)
    has_ip = _has_ip_address(host)
    uses_https = 1 if parsed.scheme.lower() == "https" else 0
    suspicious_keyword_count = sum(url_lower.count(key) for key in SUSPICIOUS_KEYWORDS)
    digit_count = sum(ch.isdigit() for ch in url)
    special_char_count = len(re.findall(r"[^a-zA-Z0-9]", url))
    domain_length = len(host)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)
    query_param_count = query.count("=")
    ampersand_count = query.count("&")
    at_symbol_count = url.count("@")
    percent_count = url.count("%")
    double_slash_count = max(url.count("//") - 1, 0)
    has_port_number = 1 if ":" in (parsed.netloc or "") else 0
    is_shortened_domain = 1 if host in SHORTENER_DOMAINS else 0
    host_entropy = _entropy(host)
    path_entropy = _entropy(path)

    return [
        url_length,
        dot_count,
        hyphen_count,
        slash_count,
        subdomain_count,
        has_ip,
        uses_https,
        suspicious_keyword_count,
        digit_count,
        special_char_count,
        domain_length,
        path_length,
        query_length,
        fragment_length,
        query_param_count,
        ampersand_count,
        at_symbol_count,
        percent_count,
        double_slash_count,
        has_port_number,
        is_shortened_domain,
        host_entropy,
        path_entropy,
    ]


def extract_feature_map(url: str) -> dict:
    values = extract_features(url)
    return {name: value for name, value in zip(FEATURE_NAMES, values)}
