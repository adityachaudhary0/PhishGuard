from utils import tld_bucket
def extract_features(url):
    from urllib.parse import urlparse
    import re

    parsed = urlparse(url)
    domain = parsed.netloc

    url_length = len(url)
    domain_length = len(domain)

    is_ip = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0

    tld = domain.split('.')[-1]
    tld_length = len(tld)
    TLD_risk=tld_bucket(tld)

    subdomains = len(domain.split('.')) - 2

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)

    letter_ratio = letters / url_length
    digit_ratio = digits / url_length

    return [
        url_length,
        domain_length,
        is_ip,
        tld_length,
        subdomains,
        letters,
        letter_ratio,
        digits,
        digit_ratio,
        TLD_risk,
    ]