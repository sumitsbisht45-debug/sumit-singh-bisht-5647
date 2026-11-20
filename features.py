"""URL feature extraction mirroring src/lib/detection/url.ts. Never fetches the URL."""
import re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "support"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "bank", "wallet", "kyc", "otp",
            "password", "free", "gift", "prize", "reward", "confirm", "suspend", "unlock", "refund"]

FEATURE_NAMES = [
    "length", "is_https", "is_ip", "has_punycode", "has_at", "n_subdomains", "n_hyphens", "n_digits",
    "n_dots", "n_keywords", "is_shortener", "suspicious_tld", "has_port", "n_encoded", "has_exe",
]


def url_features(raw: str) -> list[float]:
    s = raw.strip()
    parsed = urlparse(s if "://" in s else f"http://{s}")
    host = (parsed.hostname or "").lower()
    labels = host.split(".") if host else []
    tld = labels[-1] if labels else ""
    hay = (host + parsed.path + parsed.query).lower()
    return [
        len(s),
        1.0 if parsed.scheme == "https" else 0.0,
        1.0 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) else 0.0,
        1.0 if any(l.startswith("xn--") for l in labels) else 0.0,
        1.0 if "@" in (parsed.netloc or "") else 0.0,
        max(0, len(labels) - 2),
        host.count("-"),
        sum(c.isdigit() for c in host),
        host.count("."),
        sum(k in hay for k in KEYWORDS),
        1.0 if host in SHORTENERS else 0.0,
        1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        1.0 if parsed.port not in (None, 80, 443) else 0.0,
        len(re.findall(r"%[0-9a-fA-F]{2}", s)),
        1.0 if re.search(r"\.(exe|apk|scr|bat|msi)$", parsed.path, re.I) else 0.0,
    ]

