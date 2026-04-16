from urllib.parse import urlparse
import re
import ipaddress
from .utils import tld_bucket

def get_tld(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        if parts[-2] in ['co', 'ac', 'gov']:
            return '.' + parts[-2] + '.' + parts[-1]
    return '.' + parts[-1] if parts else ''

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return 1
    except:
        return 0

def extract_features(url: str):
    # 🔥 FIX: normalize URL
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    url_length = len(url)
    domain_length = len(domain)

    is_ip = is_ip_address(domain)

    tld = get_tld(domain)
    tld_length = len(tld)
    tld_risk = tld_bucket(tld)

    subdomains = max(len(domain.split('.')) - 2, 0)

    obfuscated_chars = url.count('%') + url.count('\\x')
    has_obfuscation = 1 if obfuscated_chars > 0 else 0
    obfuscation_ratio = obfuscated_chars / url_length if url_length else 0

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)

    letter_ratio = letters / url_length if url_length else 0
    digit_ratio = digits / url_length if url_length else 0

    equals = url.count('=')
    qmark = url.count('?')
    ampersand = url.count('&')

    special_chars = sum(c in ['@', '-', '_', '%', '=', '?', '&'] for c in url)
    special_ratio = special_chars / url_length if url_length else 0

    is_https = 1 if parsed.scheme == 'https' else 0

    # 🔥 New features
    suspicious_words = [
        "login", "verify", "secure", "account",
        "bank", "update", "confirm", "password",
        "paypal", "signin", "alert"
    ]

    has_suspicious = int(any(word in url for word in suspicious_words))
    hyphen_count = url.count('-')

    return [
        url_length,
        domain_length,
        is_ip,
        tld_length,
        subdomains,
        has_obfuscation,
        obfuscated_chars,
        obfuscation_ratio,
        letters,
        letter_ratio,
        digits,
        digit_ratio,
        equals,
        qmark,
        ampersand,
        special_chars,
        special_ratio,
        is_https,
        tld_risk,
        has_suspicious,
        hyphen_count
    ]